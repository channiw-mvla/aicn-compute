"""Node agent — runs on the owner's device (proposal sections 03, 04, 06).

Bundles the scheduler (owner availability) and the sandbox runner (isolated
execution). It dials out to the gateway and holds the connection open, so it
works from behind NAT with no port-forwarding — the same outbound model used in
the open phases, and perfectly fine on a LAN too.

Responsibilities:
  * REGISTER with hardware + current availability.
  * Poll the scheduler; when availability changes, tell the gateway.
  * Run a RUN_JOB in the sandbox (in a worker thread) and return JOB_RESULT.
  * Instant reclaim: the moment the owner becomes active (availability flips to
    unavailable) while a borrowed job is running, evict it and report
    JOB_EVICTED so the gateway re-dispatches elsewhere.
"""

import argparse
import asyncio
import hmac
import http.server
import json
import os
import socket
import sys
import threading
import uuid

import websockets

import identity as ID
import protocol as P
import tlsutil
from hardware import detect_hardware, sample_utilization
from policy import Policy
from sandbox import make_sandbox, docker_available
from scheduler import Scheduler

HERE = os.path.dirname(os.path.abspath(__file__))


def _find_panel_html():
    """Locate agent_panel.html. Next to the module when run from a source
    checkout; under <prefix>/share/aicn when pip/pipx-installed (a flat
    py-modules layout can't carry package data)."""
    candidates = [
        os.path.join(HERE, "agent_panel.html"),
        os.path.join(sys.prefix, "share", "aicn", "agent_panel.html"),
        os.path.join(os.path.dirname(os.path.dirname(sys.executable)),
                     "share", "aicn", "agent_panel.html"),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return candidates[0]      # keep the source path for the error message


PANEL_HTML = _find_panel_html()

DEFAULT_CONFIG = {
    "node_id": None,
    "gateway_url": "ws://100.65.180.16:8765",
    "token": None,
    "secure": False,
    "identity_key": None,
    "tls_ca": None,
    "insecure": False,
    "enabled": True,
    "schedule": [],
    "idle": {"require_idle": False, "idle_seconds": 300, "max_cpu_percent": 25},
    "max_job": {"ram_mb": 4096, "runtime_sec": 600},
    "stats_interval_sec": 5,
    # Local admin panel this node hosts itself (loopback by default, so only the
    # machine's owner can reach it). Set host to 0.0.0.0 for LAN + a token.
    "panel": {"enabled": True, "host": "127.0.0.1", "port": 8770, "token": None},
}


class Agent:
    def __init__(self, config, sandbox_kind, sandbox_runtime=None):
        self.config = config
        self.scheduler = Scheduler(config)
        self.sandbox_kind = sandbox_kind
        self.sandbox_runtime = sandbox_runtime
        if sandbox_kind in ("docker", "hardened"):
            if docker_available():
                rt = f" (runtime={sandbox_runtime})" if sandbox_runtime else ""
                log(f"hardened sandbox: docker OK{rt}")
            else:
                log("WARNING: sandbox is hardened/docker but Docker is not available/running "
                    "on this node — jobs will fail until Docker works.")
        elif sandbox_kind == "subprocess":
            log("NOTE: subprocess sandbox is for a TRUSTED LAN only — it is not a hard "
                "security boundary. Use --sandbox hardened to run untrusted (stranger) code.")
        self.node_id = config.get("node_id") or f"{socket.gethostname()}-{uuid.uuid4().hex[:6]}"
        self.hardware = detect_hardware()
        self.token = config.get("token") or os.environ.get("AICN_TOKEN") or None

        # Phase 3 secure mode: authenticate with an Ed25519 keypair.
        self.secure = bool(config.get("secure"))
        self.identity = None
        if self.secure:
            key_path = config.get("identity_key") or os.path.join(
                os.path.expanduser("~"), ".aicn", "identity.key")
            self.identity = ID.load_or_create(key_path)
            log(f"secure mode: identity {self.identity.fingerprint} ({key_path})")

        self.tls_ca = config.get("tls_ca")
        self.insecure = bool(config.get("insecure"))
        self.policy = Policy(config.get("policy") or {})
        if self.policy.active:
            log(f"owner allow-rules active: {list(self.policy.cfg.keys())}")

        self.config_path = config.get("config_path")   # for persisting remote schedule edits
        self.stats_interval = float(config.get("stats_interval_sec", 5) or 5)
        self.paused = False           # admin pause: stop taking new jobs (reversible)
        self.last_stats = {}          # latest local utilization sample (for the panel)
        self.panel_httpd = None

        self.loop = None
        self.ws = None
        self.fatal = False            # set on auth rejection to stop reconnecting
        self.available = self.scheduler.is_available()[0]
        # in-flight job state
        self.current_job_id = None
        self.current_sandbox = None
        self.current_evicted = False

    # -- connection ----------------------------------------------------------
    async def run(self):
        self.loop = asyncio.get_running_loop()
        self.start_panel()            # local admin panel, independent of the gateway link
        url = self.config["gateway_url"]
        ssl_param = (tlsutil.client_context(self.tls_ca, self.insecure)
                     if url.startswith("wss://") else None)
        backoff = 1
        while True:
            try:
                async with websockets.connect(url, ssl=ssl_param, ping_interval=20,
                                              max_size=P.MAX_MSG) as ws:
                    self.ws = ws
                    proceed = True
                    if self.secure:
                        ok, reason = await ID.client_handshake(ws, self.identity, P.ROLE_NODE)
                        if not ok:
                            log(f"authentication failed: {reason}")
                            if "revoke" in reason.lower():
                                self.fatal = True
                            proceed = False
                    if proceed:
                        backoff = 1
                        await self._serve(ws)
            except (OSError, websockets.WebSocketException) as e:
                log(f"connection lost ({e}); retrying in {backoff}s")
            self.ws = None
            if self.fatal:
                log("stopping: the gateway rejected this node.")
                return
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    async def _serve(self, ws):
        await self._register()
        monitor = asyncio.create_task(self._availability_monitor())
        stats = asyncio.create_task(self._stats_monitor())
        try:
            async for raw in ws:
                await self._on_message(P.decode(raw))
        finally:
            monitor.cancel()
            stats.cancel()

    async def _register(self):
        state = P.AVAIL if self.available else P.UNAVAIL
        reg = {
            "type": P.REGISTER,
            "role": P.ROLE_NODE,
            "node_id": self.node_id,
            "hardware": self.hardware,
            "availability": state,
            "max_job": self.config.get("max_job", {}),
            "schedule": self.config.get("schedule", []),
            "paused": self.paused,
        }
        # Report the sandbox AND whether it actually works right now. A node
        # started with --sandbox hardened but no working Docker must not be
        # advertised as isolated — it can't run anything, and claiming otherwise
        # would tell members it is safe for untrusted code.
        reg["sandbox"] = self.sandbox_kind
        reg["sandbox_ok"] = (docker_available()
                             if self.sandbox_kind in ("docker", "hardened") else True)
        if self.config.get("claim_token"):
            reg["claim_token"] = self.config["claim_token"]   # link this node to a portal account
        if self.token:
            reg["token"] = self.token
        await P.send(self.ws, reg)
        log(f"registered as {self.node_id}  hw={self.hardware}  available={self.available}")

    # -- availability + instant reclaim -------------------------------------
    async def _availability_monitor(self):
        while True:
            sched_ok, reason = self.scheduler.is_available()
            available = sched_ok and not self.paused
            if self.paused:
                reason = "paused"
            if available != self.available:
                self.available = available
                state = P.AVAIL if available else P.UNAVAIL
                log(f"availability -> {state} ({reason})")
                if self.ws is not None:
                    await P.send(self.ws,
                                 {"type": P.AVAILABILITY, "node_id": self.node_id,
                                  "state": state, "reason": reason})
                # Instant reclaim: the OWNER coming back (scheduler/idle) evicts a
                # running job. A manual admin pause does NOT — it lets it finish.
                if not available and not self.paused and self.current_job_id is not None:
                    await self._evict(reason)
            await asyncio.sleep(2)

    async def _push_availability(self):
        """Recompute and report availability immediately (after a control action)."""
        sched_ok, reason = self.scheduler.is_available()
        available = sched_ok and not self.paused
        if self.paused:
            reason = "paused"
        self.available = available
        state = P.AVAIL if available else P.UNAVAIL
        log(f"availability -> {state} ({reason})")
        if self.ws is not None:
            await P.send(self.ws, {"type": P.AVAILABILITY, "node_id": self.node_id,
                                   "state": state, "reason": reason})

    # -- live telemetry ------------------------------------------------------
    async def _stats_monitor(self):
        """Push CPU/RAM/GPU utilization to the gateway on a fixed interval."""
        while True:
            try:
                stats = await asyncio.to_thread(sample_utilization)
                self.last_stats = stats          # keep for the local panel
                if self.ws is not None:
                    await P.send(self.ws, {"type": P.NODE_STATS,
                                           "node_id": self.node_id, "stats": stats})
            except Exception:
                pass
            await asyncio.sleep(self.stats_interval)

    # -- admin control (relayed from the gateway; owner-only) ----------------
    async def _apply_control(self, msg):
        action = msg.get("action")
        if action == P.CTL_PAUSE:
            self.paused = True
            log("admin: paused — will not accept new jobs (running job, if any, continues)")
            await self._push_availability()
        elif action == P.CTL_RESUME:
            self.paused = False
            log("admin: resumed")
            await self._push_availability()
        elif action == P.CTL_SET_SCHEDULE:
            sched = msg.get("schedule") or []
            self.config["schedule"] = sched
            self.scheduler.config["schedule"] = sched
            self._persist_schedule(sched)
            log(f"admin: schedule updated ({len(sched)} window(s))")
            await self._push_availability()
        else:
            log(f"admin: ignoring unknown control action {action!r}")

    def _persist_schedule(self, schedule):
        """Write the new schedule back to the node's config file so it survives a
        restart. No-op when the node was started without --config."""
        path = self.config_path
        if not path:
            return
        try:
            data = {}
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
            data["schedule"] = schedule
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            log(f"persisted schedule to {path}")
        except Exception as e:
            log(f"could not persist schedule to {path}: {e}")

    # -- local admin panel (hosted by this node) -----------------------------
    def panel_snapshot(self) -> dict:
        """Everything the local panel needs to render this one node."""
        return {
            "node_id": self.node_id,
            "hardware": self.hardware,
            "available": self.available,
            "paused": self.paused,
            "schedule": self.config.get("schedule", []),
            "stats": self.last_stats,
            "current_job": self.current_job_id,
            "sandbox": self.sandbox_kind,
            "gateway": self.config.get("gateway_url"),
            "connected": self.ws is not None,
        }

    def start_panel(self):
        """Serve a small local admin panel + JSON API for THIS node. Bound to
        loopback by default, so only the machine's owner can reach it."""
        cfg = self.config.get("panel") or {}
        if cfg.get("enabled") is False:
            log("local admin panel: disabled")
            return
        host = cfg.get("host") or "127.0.0.1"
        port = int(cfg.get("port") or 8770)
        token = cfg.get("token") or ""
        handler = type("PanelHandler", (_PanelHTTP,), {"agent": self, "panel_token": token})
        try:
            httpd = http.server.ThreadingHTTPServer((host, port), handler)
        except OSError as e:
            log(f"local admin panel: could not bind {host}:{port} ({e}) — panel not started")
            return
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.panel_httpd = httpd
        loopback = host in ("127.0.0.1", "localhost", "::1")
        note = ""
        if not loopback and not token:
            note = "  WARNING: reachable beyond this machine with NO token — set panel.token"
        log(f"local admin panel: http://{host}:{port}{note}")

    async def _evict(self, reason):
        job_id = self.current_job_id
        if job_id is None:
            return
        log(f"instant reclaim: evicting job {job_id} ({reason})")
        self.current_evicted = True
        # Cancel now; JOB_EVICTED (with the job's checkpoint) is sent once the
        # sandbox returns, so partial progress can be resumed elsewhere.
        if self.current_sandbox is not None:
            self.current_sandbox.cancel()

    async def _stream_logs(self, job_id, queue):
        """Forward buffered stdout/stderr chunks to the gateway as they arrive."""
        while True:
            item = await queue.get()
            if item is None:
                return
            stream, text = item
            if self.ws is not None:
                try:
                    await P.send(self.ws, {"type": P.JOB_LOG, "job_id": job_id,
                                           "stream": stream, "data": text})
                except Exception:
                    pass

    # -- job handling --------------------------------------------------------
    async def _on_message(self, msg):
        mtype = msg.get("type")
        if mtype == P.UNAUTHORIZED:
            self.fatal = True
            log(f"gateway rejected registration: {msg.get('reason')}")
        elif mtype == P.REGISTERED:
            self.node_id = msg.get("node_id", self.node_id)
        elif mtype == P.RUN_JOB:
            await self._run_job(msg)
        elif mtype == P.CANCEL_JOB:
            if msg.get("job_id") == self.current_job_id and self.current_sandbox:
                self.current_sandbox.cancel()
        elif mtype == P.NODE_CONTROL:
            await self._apply_control(msg)

    async def _run_job(self, msg):
        job_id = msg.get("job_id")

        # Guard against a race: refuse work if the owner is no longer sharing.
        if self.current_job_id is not None or not self.available:
            await P.send(self.ws, {"type": P.JOB_EVICTED, "job_id": job_id,
                                   "reason": "not_available"})
            return

        job = {
            "workload": msg.get("workload", {}),
            "needs": msg.get("needs", {}),
            "max_runtime_sec": msg.get("max_runtime_sec", 60),
            "checkpoint": msg.get("checkpoint"),   # prior progress to resume from, if any
        }

        # Owner allow-rules: decline work the owner hasn't consented to.
        ok, reason = self.policy.check(job, self.sandbox_kind, msg.get("requester"))
        if not ok:
            log(f"refused job {job_id}: {reason}")
            await P.send(self.ws, {"type": P.JOB_REFUSED, "job_id": job_id, "reason": reason})
            return

        self.current_job_id = job_id
        self.current_evicted = False
        self.current_sandbox = make_sandbox(self.sandbox_kind, self.sandbox_runtime)
        log(f"running job {job_id} in {self.sandbox_kind} sandbox")

        # Stream stdout/stderr live: the sandbox (in a worker thread) hands lines
        # to on_output, which hops back onto the event loop for a JOB_LOG send.
        log_q = asyncio.Queue()

        def on_output(stream, text):
            try:
                self.loop.call_soon_threadsafe(log_q.put_nowait, (stream, text))
            except Exception:
                pass

        streamer = asyncio.create_task(self._stream_logs(job_id, log_q))
        try:
            result = await asyncio.to_thread(self.current_sandbox.run, job, None, on_output)
        finally:
            log_q.put_nowait(None)   # sentinel -> streamer drains and stops
            await streamer

        evicted = self.current_evicted
        self.current_job_id = None
        self.current_sandbox = None

        if evicted:
            # Return the job's latest checkpoint so it can resume elsewhere.
            checkpoint = (result or {}).get("checkpoint") or {}
            ev = {"type": P.JOB_EVICTED, "job_id": job_id, "reason": "owner_reclaim"}
            if checkpoint:
                ev["checkpoint"] = checkpoint
            if self.ws is not None:
                await P.send(self.ws, ev)
            log(f"job {job_id} evicted; checkpoint files: {len(checkpoint)}")
            return

        result.update({"type": P.JOB_RESULT, "job_id": job_id, "node_id": self.node_id})
        if self.ws is not None:
            await P.send(self.ws, result)
        log(f"job {job_id} done status={result['status']} "
            f"exit={result['exit_code']} {result['runtime_sec']}s")


class _PanelHTTP(http.server.BaseHTTPRequestHandler):
    """HTTP server for a node's own local admin panel.

    GET  /            -> the panel page
    GET  /api/state   -> this node's live snapshot (JSON)
    POST /api/control -> {action: pause|resume|set_schedule, schedule?} applied locally
    """
    agent = None
    panel_token = ""

    def _authed(self) -> bool:
        if not self.panel_token:
            return True
        got = self.headers.get("X-AICN-Token", "")
        return hmac.compare_digest(got, self.panel_token)

    def _json(self, obj, code=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            try:
                with open(PANEL_HTML, encoding="utf-8") as f:
                    html = f.read()
            except OSError:
                self.send_error(500, "agent_panel.html not found")
                return
            html = html.replace('"{{TOKEN_REQUIRED}}"', "true" if self.panel_token else "false")
            data = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/api/state":
            if not self._authed():
                self._json({"error": "unauthorized"}, 401)
                return
            self._json(self.agent.panel_snapshot())
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path.split("?")[0] != "/api/control":
            self.send_error(404)
            return
        if not self._authed():
            self._json({"ok": False, "error": "unauthorized"}, 401)
            return
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._json({"ok": False, "error": "bad request body"}, 400)
            return
        if body.get("action") not in (P.CTL_PAUSE, P.CTL_RESUME, P.CTL_SET_SCHEDULE):
            self._json({"ok": False, "error": "unknown action"}, 400)
            return
        try:
            # hop onto the agent's event loop to mutate state + notify the gateway
            fut = asyncio.run_coroutine_threadsafe(self.agent._apply_control(body), self.agent.loop)
            fut.result(timeout=5)
            self._json({"ok": True, "state": self.agent.panel_snapshot()})
        except Exception as e:
            self._json({"ok": False, "error": str(e)}, 500)

    def log_message(self, *args):
        pass  # keep the node console clean


def _parse_size_mb(s):
    """'24g' / '512m' / '8192' -> MB (int), or None if unparseable. Bare = MB."""
    if s is None:
        return None
    s = str(s).strip().lower()
    try:
        if s.endswith("g"):
            return int(float(s[:-1]) * 1024)
        if s.endswith("m"):
            return int(float(s[:-1]))
        if s.endswith("k"):
            return max(1, int(float(s[:-1]) / 1024))
        return int(float(s))
    except ValueError:
        return None


def _parse_time_sec(s):
    """'1h' / '30m' / '3600' -> seconds (int), or None. Bare = seconds."""
    if s is None:
        return None
    s = str(s).strip().lower()
    try:
        if s.endswith("h"):
            return int(float(s[:-1]) * 3600)
        if s.endswith("m"):
            return int(float(s[:-1]) * 60)
        if s.endswith("s"):
            return int(float(s[:-1]))
        return int(float(s))
    except ValueError:
        return None


def load_config(path):
    config = dict(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            config.update(json.load(f))
    return config


def log(msg):
    print(f"[node] {msg}", flush=True)


async def main():
    ap = argparse.ArgumentParser(description="AICN Phase 1 node agent")
    ap.add_argument("--config", help="path to node config JSON")
    ap.add_argument("--gateway", help="override gateway_url, e.g. ws://192.168.1.50:8765")
    ap.add_argument("--node-id", help="override node id")
    ap.add_argument("--token", help="shared-secret token (or set AICN_TOKEN env var)")
    ap.add_argument("--secure", action="store_true", help="use Phase 3 keypair auth (matches a secure gateway)")
    ap.add_argument("--identity-key", help="path to this node's private identity key (default ~/.aicn/identity.key)")
    ap.add_argument("--tls-ca", help="CA/self-signed cert (PEM) to verify a wss:// gateway")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (testing only)")
    ap.add_argument("--sandbox", choices=["subprocess", "docker", "hardened"], default="subprocess",
                    help="sandbox backend: 'subprocess' (trusted LAN only) or 'hardened'/'docker' "
                         "(locked-down container for untrusted code)")
    ap.add_argument("--sandbox-runtime", help="container runtime for the hardened sandbox, "
                    "e.g. 'runsc' for gVisor (kernel-level isolation)")
    ap.add_argument("--panel-port", type=int, help="local admin panel port (default 8770)")
    ap.add_argument("--panel-host", help="local admin panel bind host (default 127.0.0.1; "
                    "use 0.0.0.0 to reach it from the LAN — then also set --panel-token)")
    ap.add_argument("--panel-token", help="require this token to view/control the local panel")
    ap.add_argument("--no-panel", action="store_true", help="do not host the local admin panel")
    ap.add_argument("--claim-token", help="one-time token from the portal ('Add a server') that links "
                    "this node to your account so you can share it into organizations")
    ap.add_argument("--max-job-ram", help="biggest RAM a single job may request, e.g. 24g / 8192 "
                    "(default 4g). Jobs asking for more are refused by this node.")
    ap.add_argument("--max-job-runtime", help="longest runtime a single job may request, e.g. 1h / 3600 "
                    "(default 600s).")
    args = ap.parse_args()

    config = load_config(args.config)
    config["config_path"] = args.config   # remember where to persist remote schedule edits
    if args.claim_token:
        config["claim_token"] = args.claim_token
    if args.gateway:
        config["gateway_url"] = args.gateway
    if args.node_id:
        config["node_id"] = args.node_id
    if args.token:
        config["token"] = args.token
    if args.secure:
        config["secure"] = True
    if args.identity_key:
        config["identity_key"] = args.identity_key
    if args.tls_ca:
        config["tls_ca"] = args.tls_ca
    if args.insecure:
        config["insecure"] = True

    mj = dict(config.get("max_job") or {})
    if args.max_job_ram:
        v = _parse_size_mb(args.max_job_ram)
        if v:
            mj["ram_mb"] = v
    if args.max_job_runtime:
        v = _parse_time_sec(args.max_job_runtime)
        if v:
            mj["runtime_sec"] = v
    config["max_job"] = mj

    panel = dict(config.get("panel") or {})
    if args.no_panel:
        panel["enabled"] = False
    if args.panel_port:
        panel["port"] = args.panel_port
    if args.panel_host:
        panel["host"] = args.panel_host
    if args.panel_token:
        panel["token"] = args.panel_token
    config["panel"] = panel

    agent = Agent(config, args.sandbox, args.sandbox_runtime)
    await agent.run()


def cli():
    """Console-script entry point (`aicn-agent`) — see pyproject.toml."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    cli()
