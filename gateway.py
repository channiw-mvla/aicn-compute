"""Gateway — the single shared service (proposal sections 02, 07).

Keeps a live view of every connected node, matches each submitted job to an
eligible device, routes the work out and streams the result back. If a node
drops or its owner reclaims it mid-job, the gateway re-dispatches to another
eligible node.

It also serves a small web **dashboard** (see dashboard.html): a static page
over HTTP plus a live WebSocket feed of pool state, so you can watch nodes and
submit jobs from a browser.

Phase 1 · LAN: nodes and requesters both dial in over WebSocket and identify
themselves with a first REGISTER message. There is deliberately NO auth or TLS
here — keep this on a trusted local network only.
"""

import argparse
import asyncio
import hmac
import http.server
import ipaddress
import json
import os
import secrets
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone

import websockets

import identity as ID
import portal_link as PL
import protocol as P
import tlsutil
from reputation import RateLimiter, ReputationStore

HERE = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_HTML = os.path.join(HERE, "dashboard.html")
NODE_HTML = os.path.join(HERE, "node.html")

# Networks trusted to CONTROL nodes (pause/resume/schedule). Local LAN + loopback
# only by default — deliberately EXCLUDES the Tailscale/CGNAT range (100.64.0.0/10)
# so remote/public users on the overlay can watch but never touch nodes.
_DEFAULT_CONTROL_NETS = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                         "192.168.0.0/16", "169.254.0.0/16",
                         "::1/128", "fc00::/7", "fe80::/10")


class Node:
    def __init__(self, node_id, ws, hardware, avail, max_job):
        self.id = node_id
        self.ws = ws
        self.hardware = hardware
        self.available = avail
        self.max_job = max_job or {}
        self.busy_job = None          # job_id currently running, or None
        self.ok = 0                   # reliability counters (seeded from persistent store)
        self.fail = 0
        self.identity = None
        self.rep_key = node_id        # reputation key (overridden to identity fp in secure mode)
        self.stats = {}               # latest live utilization (CPU/RAM/GPU) from the node
        self.paused = False           # admin pause (reversible); stops new job assignment
        self.schedule = []            # node's recurring availability windows (for the dashboard)
        self.org_ids = set()          # portal orgs this server is shared into (empty = flat pool)

    @property
    def reliability(self):
        total = self.ok + self.fail
        return 1.0 if total == 0 else self.ok / total


class Job:
    def __init__(self, job_id, requester_ws, needs, max_runtime, workload, target_node=None):
        self.id = job_id
        self.requester_ws = requester_ws   # live connection for push; None once it disconnects
        self.needs = needs or {}
        self.max_runtime = max_runtime
        self.workload = workload
        self.target_node = target_node   # pin to a specific node, or None = auto-match
        self.node_id = None
        self.tried = set()            # node ids already attempted
        self.requester_key = None     # reputation/abuse key of the submitter
        self.org_id = None            # portal org this job is scoped to (None = flat pool)
        self.batch_id = None          # groups tasks of a batch/array submission
        self.status = P.ST_QUEUED     # queued -> running -> done/failed/cancelled
        self.result = None            # stored JOB_RESULT payload (survives disconnect)
        self.created_at = time.time()
        self.log_tail = deque(maxlen=300)   # recent (stream, data) for live followers
        self.checkpoint = None              # latest resume state {relpath: base64}, if any


class Gateway:
    def __init__(self, token=None, authorized_keys_path=None, reputation_path=None,
                 max_jobs_per_min=0, max_concurrent=0, min_reliability=0.0,
                 admin_token=None, control_cidrs=None, auto_approve_nodes=False,
                 trust_proxy=False):
        self.nodes = {}               # node_id -> Node
        self.jobs = {}                # job_id -> Job
        self.observers = set()        # dashboard websockets
        self.events = deque(maxlen=60)  # recent activity for the dashboard
        self.token = token or None    # shared secret; None = open (LAN mode)
        # Owner-only node control (pause/resume/schedule). None = control disabled.
        self.admin_token = admin_token or None
        # Networks allowed to control nodes (LAN + loopback by default).
        nets = [ipaddress.ip_network(c) for c in _DEFAULT_CONTROL_NETS]
        for c in (control_cidrs or []):
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                self.log(f"ignoring invalid --control-cidr {c!r}")
        self.control_nets = nets
        # Phase 3 secure mode: when set, node/requester must pass keypair auth.
        self.authorized_keys_path = authorized_keys_path
        self.secure = bool(authorized_keys_path)
        # Open enrollment: a brand-new NODE key is approved on first contact (still
        # gets a unique identity, so it stays revocable + reputation-tracked).
        self.auto_approve_nodes = bool(auto_approve_nodes)
        # Behind a local reverse proxy / tunnel (e.g. cloudflared): trust the
        # forwarded client-IP header so the LAN-only control gate sees the REAL
        # client, not the proxy's 127.0.0.1. Only honored for loopback peers.
        self.trust_proxy = bool(trust_proxy)
        # Phase 3 reputation + abuse limits.
        self.reputation = ReputationStore(reputation_path)
        self.rate_limiter = RateLimiter(max_jobs_per_min, 60)
        self.max_concurrent = max_concurrent
        self.min_reliability = min_reliability
        self.active_jobs = {}         # requester key -> set(job_id) in flight
        # Async job queue + bounded result store.
        self.queue = deque()          # job_ids waiting for a free node
        self.done_order = deque()     # completion order, for bounding the store
        self.done_cap = 500           # keep at most this many finished jobs
        self.web_map = {}             # gateway job_id -> portal web_jobs.id (browser submissions)

    # -- logging + live state ------------------------------------------------
    def log(self, msg, record=True):
        print(f"[gateway] {msg}", flush=True)
        if record:
            self.events.append({"ts": time.strftime("%H:%M:%S"), "text": msg})

    def build_state(self):
        return {
            "type": P.STATE,
            "protocol": P.PROTOCOL,
            "control_enabled": bool(self.admin_token),
            "nodes": [{
                "id": n.id,
                "hardware": n.hardware,
                "available": n.available,
                "busy": n.busy_job is not None,
                "busy_job": n.busy_job,
                "ok": n.ok,
                "fail": n.fail,
                "reliability": round(n.reliability, 3),
                "stats": n.stats,
                "paused": n.paused,
                "schedule": n.schedule,
            } for n in self.nodes.values()],
            "jobs_active": sum(1 for j in self.jobs.values() if j.status == P.ST_RUNNING),
            "jobs_queued": len(self.queue),
            "events": list(self.events),
        }

    async def push(self):
        """Broadcast the current pool state to every connected dashboard."""
        if not self.observers:
            return
        state = self.build_state()
        for ws in list(self.observers):
            try:
                await P.send(ws, state)
            except Exception:
                self.observers.discard(ws)

    # -- matching (section 07) ----------------------------------------------
    def _fits(self, node: Node, job: Job) -> bool:
        # Org-scoped routing: a job bound to an org only runs on servers shared
        # into that org. Jobs with no org (job.org_id is None) use the flat pool.
        if job.org_id is not None and job.org_id not in node.org_ids:
            return False
        need = job.needs
        hw = node.hardware
        mj = node.max_job
        if need.get("cpu") and hw.get("cpu", 0) < need["cpu"]:
            return False
        if need.get("ram_mb") and hw.get("ram_mb", 0) < need["ram_mb"]:
            return False
        if need.get("gpu") and hw.get("gpu", 0) < need["gpu"]:
            return False
        if mj.get("ram_mb") and need.get("ram_mb", 0) > mj["ram_mb"]:
            return False
        if mj.get("runtime_sec") and (job.max_runtime or 0) > mj["runtime_sec"]:
            return False
        return True

    def _pick_node(self, job: Job):
        candidates = [
            n for n in self.nodes.values()
            if n.available and n.busy_job is None
            and n.id not in job.tried and self._fits(n, job)
        ]
        # Abuse guard: drop nodes with a proven-bad record (once they have some
        # history); unproven nodes still get a chance.
        if self.min_reliability:
            candidates = [n for n in candidates
                          if self.reputation.total(n.rep_key) < 5
                          or self.reputation.reliability(n.rep_key) >= self.min_reliability]
        if not candidates:
            return None

        def score(n: Node):
            # Prefer a good track record (persistent reputation) then headroom.
            headroom = n.hardware.get("ram_mb", 0) - job.needs.get("ram_mb", 0)
            return (self.reputation.reliability(n.rep_key) * 1_000_000) + headroom

        return max(candidates, key=score)

    def _select_node(self, job: Job):
        """Return (node, reason). node is None on failure with a reason string.

        A job may pin a specific device via target_node; otherwise the gateway
        auto-matches. A pinned target is never silently rerouted — if it can't
        take the job, the job fails with a clear reason.
        """
        if job.target_node:
            node = self.nodes.get(job.target_node)
            t = job.target_node
            if node is None:
                return None, f"target device '{t}' is not connected"
            if node.id in job.tried:
                return None, f"target device '{t}' was already attempted"
            if not node.available:
                return None, f"target device '{t}' is not available (owner offline or reclaimed)"
            if node.busy_job is not None:
                return None, f"target device '{t}' is busy with another job"
            if not self._fits(node, job):
                return None, f"target device '{t}' lacks the requested resources"
            return node, None

        node = self._pick_node(job)
        if node is None:
            return None, ("no eligible device available" if not job.tried
                          else "all eligible devices failed or were reclaimed")
        return node, None

    async def _notify(self, job, msg):
        """Best-effort push to the submitter's live connection (may be gone)."""
        ws = job.requester_ws
        if ws is None:
            return
        try:
            await P.send(ws, msg)
        except Exception:
            job.requester_ws = None

    def _release_job(self, job):
        """Drop a job from its submitter's RUNNING set (frees a concurrency slot)."""
        key = job.requester_key
        if key and key in self.active_jobs:
            self.active_jobs[key].discard(job.id)

    def _at_cap(self, job) -> bool:
        """True if the submitter already has max_concurrent jobs running — then
        the job waits in the queue instead of starting (so batches queue, not fail)."""
        if not self.max_concurrent:
            return False
        return len(self.active_jobs.get(job.requester_key, ())) >= self.max_concurrent

    def _finish(self, job):
        """Mark a job terminal: free its concurrency slot and bound the store."""
        self._release_job(job)
        self.done_order.append(job.id)
        while len(self.done_order) > self.done_cap:
            old = self.done_order.popleft()
            j = self.jobs.get(old)
            if j and j.status in (P.ST_DONE, P.ST_FAILED, P.ST_CANCELLED):
                self.jobs.pop(old, None)

    def _feasible(self, job: Job) -> bool:
        """Could this job ever run on the current fleet? Distinguishes 'wait in
        the queue' from 'impossible, fail now'."""
        if job.target_node:
            return True               # pinned — wait for that specific node
        if not self.nodes:
            return True               # empty pool — wait for nodes to join
        return any(self._fits(n, job) for n in self.nodes.values())

    # -- dispatch ------------------------------------------------------------
    async def _assign(self, job: Job, node: Node):
        node.busy_job = job.id
        job.node_id = node.id
        job.status = P.ST_RUNNING
        job.tried.add(node.id)
        self.active_jobs.setdefault(job.requester_key, set()).add(job.id)  # now running
        run_msg = {
            "type": P.RUN_JOB,
            "job_id": job.id,
            "needs": job.needs,
            "max_runtime_sec": job.max_runtime,
            "workload": job.workload,
            "requester": job.requester_key,   # so the node can apply owner allow-rules
        }
        if job.checkpoint:
            run_msg["checkpoint"] = job.checkpoint   # resume from prior progress
        await P.send(node.ws, run_msg)
        resumed = " (resuming from checkpoint)" if job.checkpoint else ""
        self.log(f"job {job.id} -> node {node.id}{resumed}")

    async def submit(self, job: Job):
        """Place a new job: run it now, queue it if the pool is busy, or fail it
        if no connected device could ever satisfy it."""
        if not self._feasible(job):
            job.status = P.ST_FAILED
            reason = "no connected device can satisfy these requirements"
            job.result = {"status": P.ST_FAILED, "reason": reason}
            self._finish(job)
            await self._notify(job, {"type": P.JOB_FAILED, "job_id": job.id, "reason": reason})
            self.log(f"job {job.id} FAILED: {reason}")
            await self.push()
            return

        node = None if self._at_cap(job) else self._select_node(job)[0]
        if node is not None:
            await self._assign(job, node)
            await self._notify(job, {"type": P.JOB_ACCEPTED, "job_id": job.id,
                                     "node_id": node.id, "status": P.ST_RUNNING})
        else:
            job.status = P.ST_QUEUED
            self.queue.append(job.id)
            await self._notify(job, {"type": P.JOB_ACCEPTED, "job_id": job.id,
                                     "status": P.ST_QUEUED, "queue_position": len(self.queue)})
            self.log(f"job {job.id} queued (position {len(self.queue)})")
        await self.push()

    async def _drain_queue(self):
        """Place as many queued jobs as free nodes allow (best-effort, FIFO-ish)."""
        if not self.queue:
            return
        remaining = deque()
        placed = False
        while self.queue:
            jid = self.queue.popleft()
            job = self.jobs.get(jid)
            if job is None or job.status != P.ST_QUEUED:
                continue
            if self._at_cap(job):
                remaining.append(jid)   # submitter at their running cap; keep waiting
                continue
            node, _ = self._select_node(job)
            if node is not None:
                await self._assign(job, node)
                await self._notify(job, {"type": P.JOB_ACCEPTED, "job_id": job.id,
                                         "node_id": node.id, "status": P.ST_RUNNING})
                placed = True
            else:
                remaining.append(jid)
        self.queue = remaining
        if placed:
            await self.push()

    async def _requeue(self, job_id, freed_node_id):
        """A running job's node dropped/reclaimed/refused it — put it back in the
        queue (skipping that node) and try to place it again."""
        job = self.jobs.get(job_id)
        if job is None:
            return
        node = self.nodes.get(freed_node_id)
        if node and node.busy_job == job_id:
            node.busy_job = None
        self._release_job(job)          # no longer running -> frees a concurrency slot
        job.tried.add(freed_node_id)
        job.status = P.ST_QUEUED
        job.node_id = None
        if job_id not in self.queue:
            self.queue.append(job_id)
        self.log(f"job {job_id} re-queued (node {freed_node_id} unavailable)")
        await self._drain_queue()

    def _authorized(self, register_msg) -> bool:
        """Constant-time check of the shared-secret token. Open when no token."""
        if not self.token:
            return True
        presented = str(register_msg.get("token") or "")
        return hmac.compare_digest(presented, self.token)

    @staticmethod
    def _is_loopback(ws) -> bool:
        try:
            host = ws.remote_address[0]
        except Exception:
            return False
        return host in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    @staticmethod
    def _strip_mapped(host):
        if host and host.startswith("::ffff:"):   # IPv4-mapped IPv6
            host = host[len("::ffff:"):]
        return host

    @staticmethod
    def _peer_host(ws):
        try:
            host = ws.remote_address[0]
        except Exception:
            return None
        return Gateway._strip_mapped(host)

    @staticmethod
    def _header(ws, name):
        """Case-insensitive lookup of a request header from the WS handshake,
        tolerating both old (request_headers) and new (request.headers) APIs."""
        try:
            h = getattr(ws, "request_headers", None)
            if h is None:
                req = getattr(ws, "request", None)
                h = getattr(req, "headers", None) if req is not None else None
            if h is None:
                return None
            return h.get(name)
        except Exception:
            return None

    @staticmethod
    def _is_loopback_host(host) -> bool:
        try:
            return ipaddress.ip_address(host).is_loopback
        except (ValueError, TypeError):
            return False

    def _client_host(self, ws):
        """The REAL client IP for policy decisions. Behind a trusted local proxy
        (cloudflared), the socket peer is 127.0.0.1, so use the forwarded header
        instead — but only when the peer really is loopback, so a direct client
        can't spoof it. cloudflared always sets the header, so a loopback peer
        with NO header is a genuine local process (the operator on the box)."""
        peer = self._peer_host(ws)
        if self.trust_proxy and self._is_loopback_host(peer):
            fwd = self._header(ws, "CF-Connecting-IP") or self._header(ws, "X-Forwarded-For")
            if fwd:
                return self._strip_mapped(fwd.split(",")[0].strip())
        return peer

    def _control_allowed(self, ws) -> bool:
        """True only if the client is on a trusted (local) network. This is the
        authoritative gate for pause/resume/schedule — the token alone is not
        enough; the request must also originate from the LAN."""
        host = self._client_host(ws)
        if not host:
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in self.control_nets)

    # -- connection handling -------------------------------------------------
    async def handle(self, ws):
        try:
            first = P.decode(await ws.recv())
        except Exception:
            return
        mtype = first.get("type")

        if self.secure:
            if mtype == P.HELLO:
                await self._secure_session(ws, first)
            elif mtype == P.REGISTER and first.get("role") == P.ROLE_DASHBOARD:
                # LAN dashboards get full access without keypair auth; public
                # (non-LAN) dashboards are allowed too but READ-ONLY — a public
                # status view that can watch the pool but not submit/cancel jobs.
                await self._requester_session(ws, first, observe=True,
                                              read_only=not self._control_allowed(ws))
            else:
                await P.send(ws, {"type": P.UNAUTHORIZED,
                                  "reason": "secure mode: send HELLO to authenticate with your key"})
            return

        # -- open mode (LAN / overlay), unchanged --------------------------
        if mtype != P.REGISTER:
            await P.send(ws, {"type": P.JOB_FAILED, "reason": "expected REGISTER"})
            return
        if not self._authorized(first):
            await P.send(ws, {"type": P.UNAUTHORIZED,
                              "reason": "invalid or missing shared-secret token"})
            self.log(f"rejected {first.get('role','?')} connection: bad token")
            return
        await self._dispatch_role(ws, first)

    async def _dispatch_role(self, ws, reg, identity=None):
        role = reg.get("role")
        if role == P.ROLE_NODE:
            await self._node_session(ws, reg, identity=identity)
        elif role in (P.ROLE_REQUESTER, P.ROLE_DASHBOARD):
            observe = (role == P.ROLE_DASHBOARD)
            # public (non-LAN) dashboards are read-only status views
            await self._requester_session(ws, reg, observe=observe, identity=identity,
                                          read_only=observe and not self._control_allowed(ws))
        else:
            await P.send(ws, {"type": P.JOB_FAILED, "reason": f"unknown role {role!r}"})

    async def _secure_session(self, ws, hello):
        """Challenge-response auth against the approved-keys store, then REGISTER."""
        role = hello.get("role")
        pubkey = hello.get("pubkey") or ""
        fp = ID.fingerprint_of(pubkey)
        keys = ID.load_keystore(self.authorized_keys_path)   # reload so approvals take effect live
        entry = keys.get(pubkey)

        if entry and entry.get("status") == "revoked":
            await P.send(ws, {"type": P.UNAUTHORIZED, "reason": f"key {fp} is revoked"})
            self.log(f"rejected {role}: revoked key {fp}")
            return

        # Prove key ownership: sign a fresh nonce.
        nonce = secrets.token_hex(32)
        await P.send(ws, {"type": P.CHALLENGE, "nonce": nonce})
        try:
            authmsg = P.decode(await asyncio.wait_for(ws.recv(), 20))
        except Exception:
            return
        signature = authmsg.get("signature") or ""
        if (authmsg.get("type") != P.AUTH or not pubkey
                or not ID.verify(pubkey, nonce.encode("utf-8"), _safe_unb64(signature))):
            await P.send(ws, {"type": P.UNAUTHORIZED, "reason": "bad signature"})
            self.log(f"rejected {role}: bad signature from {fp}")
            return

        # Ownership proven — now decide on approval status.
        auto = self.auto_approve_nodes and role == P.ROLE_NODE
        if entry is None:
            status = "approved" if auto else "pending"
            keys[pubkey] = {"role": role, "label": "", "status": status,
                            "first_seen": _now(), "fingerprint": fp}
            if auto:
                keys[pubkey]["approved_at"] = _now()
                keys[pubkey]["auto"] = True
            ID.save_keystore(self.authorized_keys_path, keys)
            if not auto:
                await P.send(ws, {"type": P.UNAUTHORIZED,
                                  "reason": f"key {fp} recorded, pending approval — ask the admin to approve it"})
                self.log(f"NEW {role} key {fp} recorded pending approval")
                return
            entry = keys[pubkey]
            self.log(f"AUTO-ENROLLED node {fp} (open enrollment)")
        if entry.get("status") != "approved":
            # A node that was pending gets auto-approved too when open enrollment is on.
            if auto and entry.get("status") == "pending":
                entry["status"] = "approved"
                entry["approved_at"] = _now()
                entry["auto"] = True
                ID.save_keystore(self.authorized_keys_path, keys)
                self.log(f"AUTO-ENROLLED node {fp} (was pending)")
            else:
                await P.send(ws, {"type": P.UNAUTHORIZED, "reason": f"key {fp} is pending approval"})
                return

        label = entry.get("label") or fp
        await P.send(ws, {"type": P.AUTH_OK, "fingerprint": fp, "label": label})
        self.log(f"authenticated {role} '{label}' ({fp})")

        try:
            reg = P.decode(await asyncio.wait_for(ws.recv(), 20))
        except Exception:
            return
        if reg.get("type") != P.REGISTER:
            await P.send(ws, {"type": P.JOB_FAILED, "reason": "expected REGISTER after AUTH_OK"})
            return
        await self._dispatch_role(ws, reg, identity={"pubkey": pubkey, "fp": fp, "label": label})

    async def _node_session(self, ws, reg, identity=None):
        node_id = reg.get("node_id") or ("node-" + uuid.uuid4().hex[:8])
        node = Node(
            node_id, ws,
            hardware=reg.get("hardware", {}),
            avail=(reg.get("availability") == P.AVAIL),
            max_job=reg.get("max_job", {}),
        )
        node.identity = identity
        node.schedule = reg.get("schedule", []) or []
        node.paused = bool(reg.get("paused"))
        if identity:
            node.rep_key = identity["fp"]
            fp = identity["fp"]
            # Portal link: claim the server to its owner (one-time), then learn
            # which orgs it's shared into so jobs can route to it.
            if PL.enabled():
                if reg.get("claim_token"):
                    if PL.claim_server(reg["claim_token"], fp):
                        self.log(f"node {node_id} claimed to a portal account ({fp})")
                node.org_ids = PL.org_ids_for_fingerprint(fp)
                PL.touch_server(fp)
        seed = self.reputation.get(node.rep_key)   # carry history across reconnects
        node.ok, node.fail = seed["ok"], seed["fail"] + seed["evict"]
        self.nodes[node_id] = node
        await P.send(ws, {"type": P.REGISTERED, "node_id": node_id})
        who = f"  id={identity['fp']}" if identity else ""
        self.log(f"node {node_id} connected  hw={node.hardware}  available={node.available}{who}")
        await self.push()
        await self._drain_queue()   # a new node may be able to take waiting jobs
        try:
            async for raw in ws:
                msg = P.decode(raw)
                await self._on_node_message(node, msg)
        except websockets.ConnectionClosed:
            pass
        finally:
            self.nodes.pop(node_id, None)
            self.log(f"node {node_id} disconnected")
            if node.busy_job:
                self.reputation.record(node.rep_key, "evict")  # dropped a job mid-run
                await self._requeue(node.busy_job, node_id)
            await self.push()

    async def _on_node_message(self, node: Node, msg: dict):
        mtype = msg.get("type")
        if mtype == P.AVAILABILITY:
            node.available = (msg.get("state") == P.AVAIL)
            node.paused = (msg.get("reason") == "paused")   # keep pause state in sync
            self.log(f"node {node.id} availability -> {msg.get('state')} ({msg.get('reason','')})")
            await self.push()
            if node.available:
                await self._drain_queue()   # newly-available node can take waiting jobs
        elif mtype == P.NODE_STATS:
            node.stats = msg.get("stats", {}) or {}
            if PL.enabled() and node.identity:
                PL.touch_server(node.rep_key)   # keep last_seen fresh for the portal
            await self.push()               # live utilization to the dashboards
        elif mtype == P.JOB_RESULT:
            job_id = msg.get("job_id")
            job = self.jobs.get(job_id)            # keep it in the store, don't pop
            if node.busy_job == job_id:
                node.busy_job = None
            if msg.get("status") == P.OK:
                node.ok += 1
                self.reputation.record(node.rep_key, "ok")
            else:
                node.fail += 1
                self.reputation.record(node.rep_key, "fail")
            if job is not None:
                job.result = msg
                job.status = P.ST_DONE          # ran to completion (result may be ok/error)
                self._finish(job)
                await self._notify(job, msg)
            self.log(f"job {job_id} result={msg.get('status')} from node {node.id}")
            await self.push()
            await self._drain_queue()           # this node is free now
        elif mtype == P.JOB_LOG:
            job = self.jobs.get(msg.get("job_id"))
            if job is not None:
                job.log_tail.append((msg.get("stream"), msg.get("data", "")))
                await self._notify(job, msg)   # relay live to the submitter if connected
        elif mtype == P.JOB_EVICTED:
            job_id = msg.get("job_id")
            node.available = False
            self.reputation.record(node.rep_key, "evict")
            job = self.jobs.get(job_id)
            cp = msg.get("checkpoint")
            if job is not None and cp:
                job.checkpoint = cp   # preserve progress for the resume elsewhere
                self.log(f"job {job_id} EVICTED by node {node.id}; kept checkpoint ({len(cp)} files)")
            else:
                self.log(f"job {job_id} EVICTED by owner of node {node.id}")
            await self._requeue(job_id, node.id)
            await self.push()
        elif mtype == P.JOB_REFUSED:
            # owner allow-rules declined this job — node stays available; try elsewhere
            job_id = msg.get("job_id")
            self.log(f"job {job_id} REFUSED by node {node.id}: {msg.get('reason')}")
            await self._requeue(job_id, node.id)
            await self.push()

    async def _requester_session(self, ws, reg, observe=False, identity=None, read_only=False):
        who = P.ROLE_DASHBOARD if observe else P.ROLE_REQUESTER
        req_id = (identity["label"] if identity else None) or \
            reg.get("requester_id") or (f"{who[:3]}-" + uuid.uuid4().hex[:8])
        await P.send(ws, {"type": P.REGISTERED, "requester_id": req_id})
        if observe:
            self.observers.add(ws)
            await P.send(ws, {"type": P.CONTROL_INFO,
                              "enabled": bool(self.admin_token),
                              "local": self._control_allowed(ws),
                              "read_only": read_only})
            await P.send(ws, self.build_state())
        ro = " (read-only)" if read_only else ""
        self.log(f"{who} {req_id} connected{ro}", record=not observe)
        rep_key = (identity["fp"] if identity else req_id)
        try:
            async for raw in ws:
                msg = P.decode(raw)
                mtype = msg.get("type")
                # A read-only (public) viewer may look but not act: no job submit,
                # no cancel. Enforced HERE server-side — hiding the form in the
                # browser is not a security boundary.
                if read_only and mtype in (P.SUBMIT_JOB, P.CANCEL_JOB):
                    await P.send(ws, {"type": P.JOB_FAILED, "job_id": msg.get("job_id"),
                                      "reason": "read-only status view — submit jobs with the aicn CLI"})
                    continue
                if mtype == P.SUBMIT_JOB:
                    await self._handle_submit(ws, msg, who, req_id, rep_key)
                elif mtype == P.GET_JOB:
                    await self._handle_get(ws, msg, rep_key)
                elif mtype == P.GET_BATCH:
                    await self._handle_get_batch(ws, msg, rep_key)
                elif mtype == P.LIST_JOBS:
                    await self._handle_list_jobs(ws, rep_key)
                elif mtype == P.GET_NODES:
                    await self._handle_nodes(ws)
                elif mtype == P.CANCEL_JOB:
                    await self._handle_cancel(ws, msg, rep_key)
                elif mtype == P.NODE_CONTROL:
                    await self._handle_control(ws, msg)
        except websockets.ConnectionClosed:
            pass
        finally:
            self.observers.discard(ws)
            self.log(f"{who} {req_id} disconnected", record=not observe)
            # Jobs SURVIVE the requester disconnecting — just drop the push target.
            for job in self.jobs.values():
                if job.requester_ws is ws:
                    job.requester_ws = None

    # -- web-job queue (browser submissions via the shared portal DB) --------
    async def _web_poll_loop(self):
        while True:
            try:
                await self._web_poll_tick()
            except Exception as e:
                self.log(f"web-poll error: {e}", record=False)
            await asyncio.sleep(2)

    async def _web_poll_tick(self):
        # 1. pick up new browser-submitted jobs
        for wj in PL.fetch_pending_web_jobs():
            job_id = "web-" + uuid.uuid4().hex[:8]
            workload = {"interpreter": wj["interpreter"], "script": wj["script"], "input": ""}
            if wj.get("pip"):
                workload["pip"] = [p.strip() for p in wj["pip"].split(",") if p.strip()]
            job = Job(job_id, None,
                      needs={"cpu": 1, "ram_mb": wj["ram_mb"]},
                      max_runtime=wj["max_runtime"], workload=workload)
            job.org_id = wj["org_id"]
            job.requester_key = f"web:{wj['user_id']}"
            self.jobs[job_id] = job
            self.web_map[job_id] = wj["id"]
            PL.mark_web_job(wj["id"], "queued", gateway_job_id=job_id)
            self.log(f"web job {wj['id']} accepted as {job_id} (org {wj['org_id']})")
            await self.submit(job)
        # 2. sync tracked jobs' progress/results back to the portal DB
        for gwid, web_id in list(self.web_map.items()):
            job = self.jobs.get(gwid)
            if job is None:
                PL.finish_web_job(web_id, "failed", None, {"status": "failed", "stderr": "job was dropped"})
                self.web_map.pop(gwid, None)
                continue
            if job.status in (P.ST_DONE, P.ST_FAILED, P.ST_CANCELLED):
                PL.finish_web_job(web_id, job.status, job.node_id, job.result or {})
                self.web_map.pop(gwid, None)
            else:
                PL.mark_web_job(web_id, job.status, node_id=job.node_id)

    async def _handle_submit(self, ws, msg, who, req_id, rep_key):
        job_id = msg.get("job_id") or ("job-" + uuid.uuid4().hex[:8])
        if not self.rate_limiter.allow(rep_key):
            await P.send(ws, {"type": P.JOB_FAILED, "job_id": job_id,
                              "reason": "rate limit exceeded — too many jobs; slow down"})
            self.log(f"{who} {req_id} rate-limited")
            return

        # Org-scoped submission: authenticate the submitter by API token and
        # confirm org membership, so the job routes only to that org's servers.
        org_slug = msg.get("org")
        org_id = None
        if org_slug:
            def refuse(reason):
                return P.send(ws, {"type": P.JOB_FAILED, "job_id": job_id, "reason": reason})
            if not PL.enabled():
                await refuse("this gateway isn't linked to the portal (org routing unavailable)")
                return
            who_user = PL.user_for_api_token(msg.get("api_token"))
            if who_user is None:
                await refuse("invalid or missing --api-token for an --org submission")
                return
            org_id = PL.org_id_for_slug(org_slug)
            if org_id is None or not PL.user_in_org(who_user[0], org_id):
                await refuse(f"you are not a member of organization '{org_slug}'")
                return

        job = Job(job_id, ws,
                  needs=msg.get("needs", {}),
                  max_runtime=msg.get("max_runtime_sec", 60),
                  workload=msg.get("workload", {}),
                  target_node=msg.get("target_node"))
        job.requester_key = rep_key
        job.org_id = org_id
        job.batch_id = msg.get("batch_id")
        self.jobs[job_id] = job
        self.reputation.record(rep_key, "submitted")
        tgt = f" target={job.target_node}" if job.target_node else ""
        bt = f" batch={job.batch_id}" if job.batch_id else ""
        self.log(f"{who} {req_id} submitted job {job_id} needs={job.needs}{tgt}{bt}")
        await self.submit(job)

    def _owns(self, job, rep_key) -> bool:
        # In secure mode a job can only be retrieved/cancelled by its submitter;
        # in open mode the (random) job id itself is the capability.
        return (not self.secure) or (job.requester_key == rep_key)

    async def _handle_get(self, ws, msg, rep_key):
        jid = msg.get("job_id")
        job = self.jobs.get(jid)
        if job is None or not self._owns(job, rep_key):
            await P.send(ws, {"type": P.JOB_STATUS, "job_id": jid, "status": "unknown"})
            return
        payload = {"type": P.JOB_STATUS, "job_id": jid, "status": job.status,
                   "node_id": job.node_id}
        if job.result is not None:
            payload["result"] = job.result
        if job.status == P.ST_QUEUED:
            try:
                payload["queue_position"] = list(self.queue).index(jid) + 1
            except ValueError:
                pass
        # Re-attach the push target so a reconnecting client can wait for the result.
        if job.status in (P.ST_QUEUED, P.ST_RUNNING):
            job.requester_ws = ws
        await P.send(ws, payload)
        # Replay recent output for a following client, then live logs continue.
        if msg.get("follow") and job.status == P.ST_RUNNING:
            for stream, data in list(job.log_tail):
                await P.send(ws, {"type": P.JOB_LOG, "job_id": jid, "stream": stream, "data": data})

    async def _handle_get_batch(self, ws, msg, rep_key):
        batch_id = msg.get("batch_id")
        jobs = [j for j in self.jobs.values()
                if j.batch_id == batch_id and self._owns(j, rep_key)]
        tasks = []
        for j in sorted(jobs, key=lambda x: x.id):
            entry = {"job_id": j.id, "status": j.status, "node_id": j.node_id}
            if j.result is not None:
                entry["result"] = j.result
            tasks.append(entry)
        await P.send(ws, {"type": P.BATCH_STATUS, "batch_id": batch_id, "tasks": tasks})

    async def _handle_list_jobs(self, ws, rep_key):
        # open mode: show all jobs (trusted LAN); secure mode: only the caller's.
        jobs = [j for j in self.jobs.values() if not self.secure or self._owns(j, rep_key)]
        items = [{"job_id": j.id, "status": j.status, "node_id": j.node_id,
                  "batch_id": j.batch_id, "created_at": j.created_at}
                 for j in sorted(jobs, key=lambda x: x.created_at, reverse=True)]
        await P.send(ws, {"type": P.JOBS_LIST, "jobs": items})

    async def _handle_nodes(self, ws):
        nodes = [{"id": n.id, "available": n.available, "busy": n.busy_job is not None,
                  "hardware": n.hardware, "max_job": n.max_job,
                  "reliability": round(self.reputation.reliability(n.rep_key), 3)}
                 for n in self.nodes.values()]
        await P.send(ws, {"type": P.NODES_LIST, "nodes": nodes})

    async def _handle_control(self, ws, msg):
        """Owner-only node control: pause / resume / set schedule. Gated by the
        gateway admin token so a public viewer can watch but never touch nodes."""
        def deny(reason):
            return P.send(ws, {"type": P.CONTROL_RESULT, "ok": False, "reason": reason})

        # Network boundary first (don't even reveal whether control is enabled to
        # a remote client): pause/resume/schedule are local-network only.
        if not self._control_allowed(ws):
            self.log(f"rejected node-control from non-local client {self._client_host(ws)}")
            await deny("node control is restricted to the local network")
            return
        if not self.admin_token:
            await deny("node control is disabled — start the gateway with "
                       "--admin-token / AICN_ADMIN_TOKEN to enable it")
            return
        presented = str(msg.get("admin_token") or "")
        if not hmac.compare_digest(presented, self.admin_token):
            self.log("rejected node-control: bad admin token")
            await deny("invalid admin token")
            return
        node_id = msg.get("node_id")
        node = self.nodes.get(node_id)
        if node is None:
            await deny(f"node '{node_id}' is not connected")
            return
        action = msg.get("action")
        if action not in (P.CTL_PAUSE, P.CTL_RESUME, P.CTL_SET_SCHEDULE):
            await deny(f"unknown action {action!r}")
            return

        relay = {"type": P.NODE_CONTROL, "action": action}
        if action == P.CTL_SET_SCHEDULE:
            relay["schedule"] = msg.get("schedule") or []
        try:
            await P.send(node.ws, relay)
        except Exception:
            await deny("failed to reach the node")
            return

        # Optimistic local update; the node's AVAILABILITY reply confirms/corrects it.
        if action == P.CTL_PAUSE:
            node.paused = True
        elif action == P.CTL_RESUME:
            node.paused = False
        elif action == P.CTL_SET_SCHEDULE:
            node.schedule = relay["schedule"]
        self.log(f"admin control '{action}' -> node {node_id}")
        await P.send(ws, {"type": P.CONTROL_RESULT, "ok": True,
                          "node_id": node_id, "action": action})
        await self.push()

    async def _handle_cancel(self, ws, msg, rep_key):
        jid = msg.get("job_id")
        job = self.jobs.get(jid)
        if job is None or not self._owns(job, rep_key):
            await P.send(ws, {"type": P.JOB_STATUS, "job_id": jid, "status": "unknown"})
            return
        if job.status == P.ST_QUEUED:
            try:
                self.queue.remove(jid)
            except ValueError:
                pass
            job.status = P.ST_CANCELLED
            job.result = {"status": P.CANCELLED, "reason": "cancelled by requester"}
            self._finish(job)
            await P.send(ws, {"type": P.JOB_STATUS, "job_id": jid, "status": P.ST_CANCELLED})
            self.log(f"job {jid} cancelled (was queued)")
        elif job.status == P.ST_RUNNING:
            node = self.nodes.get(job.node_id)
            if node:
                await P.send(node.ws, {"type": P.CANCEL_JOB, "job_id": jid})
            await P.send(ws, {"type": P.JOB_STATUS, "job_id": jid, "status": "cancelling"})
            self.log(f"job {jid} cancel requested (running on {job.node_id})")
        else:
            await P.send(ws, {"type": P.JOB_STATUS, "job_id": jid, "status": job.status})


# -- dashboard HTTP server (stdlib, background thread) -----------------------
class _DashboardHTTP(http.server.BaseHTTPRequestHandler):
    ws_port = 8765
    token = ""
    ws_scheme = "ws"

    def do_GET(self):
        path = self.path.split("?")[0]
        node_id = None
        if path in ("/", "/index.html", "/dashboard"):
            src = DASHBOARD_HTML
        elif path.startswith("/node/") and len(path) > len("/node/"):
            from urllib.parse import unquote
            node_id = unquote(path[len("/node/"):]).strip("/")
            src = NODE_HTML
        else:
            self.send_error(404)
            return
        try:
            with open(src, encoding="utf-8") as f:
                html = f.read()
        except OSError:
            self.send_error(500, f"{os.path.basename(src)} not found")
            return
        html = html.replace("{{WS_PORT}}", str(self.ws_port))
        html = html.replace("{{WS_SCHEME}}", self.ws_scheme)
        html = html.replace('"{{TOKEN}}"', json.dumps(self.token or ""))
        if node_id is not None:
            html = html.replace('"{{NODE_ID}}"', json.dumps(node_id))
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass  # keep the console clean


def start_dashboard_http(host, http_port, ws_port, token="", ssl_ctx=None):
    scheme = "wss" if ssl_ctx else "ws"
    handler = type("Handler", (_DashboardHTTP,),
                   {"ws_port": ws_port, "token": token, "ws_scheme": scheme})
    httpd = http.server.ThreadingHTTPServer((host, http_port), handler)
    if ssl_ctx is not None:
        httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_unb64(text):
    try:
        return ID.unb64(text)
    except Exception:
        return b""


def log(msg):
    print(f"[gateway] {msg}", flush=True)


async def main():
    ap = argparse.ArgumentParser(description="AICN Phase 1 gateway (LAN, no auth/TLS)")
    ap.add_argument("--host", default="0.0.0.0",
                    help="bind address (default 0.0.0.0 for LAN; use 127.0.0.1 for local-only)")
    ap.add_argument("--port", type=int, default=8765, help="WebSocket port")
    ap.add_argument("--http-port", type=int, default=8766, help="dashboard HTTP port")
    ap.add_argument("--no-dashboard", action="store_true", help="disable the web dashboard")
    ap.add_argument("--token", help="shared-secret token required from every client "
                    "(safer to set via the AICN_TOKEN env var so it isn't in the process list)")
    ap.add_argument("--admin-token", help="enable owner-only node control (pause/resume/schedule) "
                    "from the dashboard; holders of this token can control nodes (env: AICN_ADMIN_TOKEN)")
    ap.add_argument("--control-cidr", help="extra network(s) allowed to control nodes, comma-separated "
                    "CIDR (e.g. 100.64.0.0/10 to also allow your Tailscale range). Default: local LAN + "
                    "loopback only — control is refused from anywhere else, even with a valid admin token.")
    ap.add_argument("--trusted-proxy", action="store_true",
                    help="the gateway sits behind a LOCAL reverse proxy / tunnel (e.g. cloudflared): read "
                         "the real client IP from CF-Connecting-IP / X-Forwarded-For so the LAN-only "
                         "control gate isn't fooled into treating every proxied client as local. Only "
                         "enable when a trusted proxy on this host is the sole way in. (env: AICN_TRUSTED_PROXY=1)")
    ap.add_argument("--authorized-keys", help="path to the approved-keys JSON store; enables "
                    "Phase 3 secure mode (keypair challenge-response auth). Manage it with authctl.py")
    ap.add_argument("--auto-approve-nodes", action="store_true",
                    help="open enrollment: auto-approve a new NODE's key on first connect (it still gets "
                         "a unique identity, so it stays revocable + reputation-tracked). Requesters still "
                         "need manual approval. Requires --authorized-keys. (env: AICN_AUTO_APPROVE_NODES=1)")
    ap.add_argument("--tls-cert", help="TLS certificate (PEM) to serve wss:// and https dashboard")
    ap.add_argument("--tls-key", help="TLS private key (PEM) matching --tls-cert")
    ap.add_argument("--reputation", help="path to the persistent reputation JSON store "
                    "(per-identity job history feeding matching)")
    ap.add_argument("--max-jobs-per-min", type=int, default=0,
                    help="per-submitter rate limit (0 = unlimited)")
    ap.add_argument("--max-concurrent", type=int, default=0,
                    help="max concurrent in-flight jobs per submitter (0 = unlimited)")
    ap.add_argument("--min-reliability", type=float, default=0.0,
                    help="skip nodes below this reliability once they have a track record (0 = off)")
    args = ap.parse_args()

    token = args.token or os.environ.get("AICN_TOKEN") or None
    admin_token = args.admin_token or os.environ.get("AICN_ADMIN_TOKEN") or None
    control_cidr = args.control_cidr or os.environ.get("AICN_CONTROL_CIDR") or ""
    control_cidrs = [c.strip() for c in control_cidr.split(",") if c.strip()]
    keys_path = args.authorized_keys or os.environ.get("AICN_AUTHORIZED_KEYS") or None
    rep_path = args.reputation or os.environ.get("AICN_REPUTATION") or None
    auto_approve = args.auto_approve_nodes or os.environ.get("AICN_AUTO_APPROVE_NODES") in ("1", "true", "yes")
    trust_proxy = args.trusted_proxy or os.environ.get("AICN_TRUSTED_PROXY") in ("1", "true", "yes")
    gw = Gateway(token=token, authorized_keys_path=keys_path, reputation_path=rep_path,
                 max_jobs_per_min=args.max_jobs_per_min, max_concurrent=args.max_concurrent,
                 min_reliability=args.min_reliability, admin_token=admin_token,
                 control_cidrs=control_cidrs, auto_approve_nodes=auto_approve, trust_proxy=trust_proxy)
    if rep_path:
        log(f"reputation store: {rep_path}")
    if args.max_jobs_per_min or args.max_concurrent:
        log(f"abuse limits: {args.max_jobs_per_min or 'unlimited'}/min, "
            f"{args.max_concurrent or 'unlimited'} concurrent per submitter")

    ssl_ctx = None
    if args.tls_cert and args.tls_key:
        ssl_ctx = tlsutil.server_context(args.tls_cert, args.tls_key)
    elif args.tls_cert or args.tls_key:
        ap.error("--tls-cert and --tls-key must be given together")
    ws_scheme = "wss" if ssl_ctx else "ws"

    public = args.host not in ("127.0.0.1", "localhost", "::1")
    if ssl_ctx:
        log("TLS ENABLED — serving wss:// (and https dashboard).")
    elif public:
        log("NOTE: no TLS — traffic is cleartext. Fine over a Tailscale/WireGuard "
            "overlay (already encrypted); for a public gateway add --tls-cert/--tls-key.")
    if gw.secure:
        log(f"SECURE MODE — keypair auth required (approved-keys: {keys_path}). "
            "Nodes/requesters must be approved via authctl.py; local dashboard allowed from the LAN.")
        if auto_approve:
            log("OPEN ENROLLMENT — new nodes auto-join on first connect (unique identity, still "
                "revocable via authctl.py). Requesters still require manual approval.")
    elif auto_approve:
        log("WARNING: --auto-approve-nodes has no effect without --authorized-keys (secure mode). "
            "Ignoring — the gateway is in open mode where any node can already connect.")
    if token:
        log("shared-secret token ENABLED — clients must present a matching token.")
    if admin_token:
        extra = f" plus {', '.join(control_cidrs)}" if control_cidrs else ""
        log(f"node control ENABLED — pause/resume/schedule require the admin token AND a client "
            f"on the local network (LAN + loopback{extra}). Remote/overlay viewers are monitor-only.")
    else:
        log("node control DISABLED — dashboard is monitor-only (set --admin-token / AICN_ADMIN_TOKEN to enable).")
    if public and not token and not gw.secure:
        log("WARNING: binding to a non-loopback address with NO auth. The gateway "
            "runs arbitrary submitted code in sandboxes on your nodes — do NOT expose "
            "it beyond a trusted LAN. Set --authorized-keys (keypair auth) or "
            "--token / AICN_TOKEN before widening reach.")
    elif public and token:
        log("WARNING: token is sent in cleartext over ws:// (no TLS until Phase 3). "
            "It blocks casual/unauthenticated access but not a network sniffer — for "
            "real exposure use a private overlay (Tailscale/WireGuard) or wss.")

    if trust_proxy:
        log("TRUSTED PROXY mode — real client IP read from CF-Connecting-IP/X-Forwarded-For for "
            "loopback peers (for a cloudflared tunnel or similar local reverse proxy).")

    if not args.no_dashboard:
        http_scheme = "https" if ssl_ctx else "http"
        start_dashboard_http(args.host, args.http_port, args.port, token or "", ssl_ctx)
        log(f"dashboard: {http_scheme}://127.0.0.1:{args.http_port}  "
            f"(from another device: {http_scheme}://<this-host>:{args.http_port})")
        if token:
            log("note: the dashboard page embeds the token, so keep the dashboard "
                "HTTP port private (localhost/LAN), not public.")

    if PL.enabled():
        log(f"PORTAL LINK ENABLED — org sharing + browser-submitted jobs via {PL.PORTAL_DB}")
    log(f"listening on {ws_scheme}://{args.host}:{args.port}  ({P.PROTOCOL})")
    async with websockets.serve(gw.handle, args.host, args.port, ssl=ssl_ctx,
                                ping_interval=20, max_size=P.MAX_MSG):
        if PL.enabled():
            asyncio.create_task(gw._web_poll_loop())   # run browser-submitted jobs
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
