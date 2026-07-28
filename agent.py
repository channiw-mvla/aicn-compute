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
import json
import os
import socket
import uuid

import websockets

import identity as ID
import protocol as P
import tlsutil
from hardware import detect_hardware
from policy import Policy
from sandbox import make_sandbox, docker_available
from scheduler import Scheduler

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
        try:
            async for raw in ws:
                await self._on_message(P.decode(raw))
        finally:
            monitor.cancel()

    async def _register(self):
        state = P.AVAIL if self.available else P.UNAVAIL
        reg = {
            "type": P.REGISTER,
            "role": P.ROLE_NODE,
            "node_id": self.node_id,
            "hardware": self.hardware,
            "availability": state,
            "max_job": self.config.get("max_job", {}),
        }
        if self.token:
            reg["token"] = self.token
        await P.send(self.ws, reg)
        log(f"registered as {self.node_id}  hw={self.hardware}  available={self.available}")

    # -- availability + instant reclaim -------------------------------------
    async def _availability_monitor(self):
        while True:
            available, reason = self.scheduler.is_available()
            if available != self.available:
                self.available = available
                state = P.AVAIL if available else P.UNAVAIL
                log(f"availability -> {state} ({reason})")
                if self.ws is not None:
                    await P.send(self.ws,
                                 {"type": P.AVAILABILITY, "node_id": self.node_id,
                                  "state": state, "reason": reason})
                # Instant reclaim: owner is back while a job runs -> evict it.
                if not available and self.current_job_id is not None:
                    await self._evict(reason)
            await asyncio.sleep(2)

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
    args = ap.parse_args()

    config = load_config(args.config)
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
