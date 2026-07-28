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
import protocol as P
import tlsutil
from reputation import RateLimiter, ReputationStore

HERE = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_HTML = os.path.join(HERE, "dashboard.html")


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
        self.batch_id = None          # groups tasks of a batch/array submission
        self.status = P.ST_QUEUED     # queued -> running -> done/failed/cancelled
        self.result = None            # stored JOB_RESULT payload (survives disconnect)
        self.created_at = time.time()
        self.log_tail = deque(maxlen=300)   # recent (stream, data) for live followers
        self.checkpoint = None              # latest resume state {relpath: base64}, if any


class Gateway:
    def __init__(self, token=None, authorized_keys_path=None, reputation_path=None,
                 max_jobs_per_min=0, max_concurrent=0, min_reliability=0.0):
        self.nodes = {}               # node_id -> Node
        self.jobs = {}                # job_id -> Job
        self.observers = set()        # dashboard websockets
        self.events = deque(maxlen=60)  # recent activity for the dashboard
        self.token = token or None    # shared secret; None = open (LAN mode)
        # Phase 3 secure mode: when set, node/requester must pass keypair auth.
        self.authorized_keys_path = authorized_keys_path
        self.secure = bool(authorized_keys_path)
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

    # -- logging + live state ------------------------------------------------
    def log(self, msg, record=True):
        print(f"[gateway] {msg}", flush=True)
        if record:
            self.events.append({"ts": time.strftime("%H:%M:%S"), "text": msg})

    def build_state(self):
        return {
            "type": P.STATE,
            "protocol": P.PROTOCOL,
            "nodes": [{
                "id": n.id,
                "hardware": n.hardware,
                "available": n.available,
                "busy": n.busy_job is not None,
                "busy_job": n.busy_job,
                "ok": n.ok,
                "fail": n.fail,
                "reliability": round(n.reliability, 3),
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
            elif (mtype == P.REGISTER and first.get("role") == P.ROLE_DASHBOARD
                  and self._is_loopback(ws)):
                # the operator's local dashboard is allowed without keypair auth
                await self._requester_session(ws, first, observe=True)
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
            await self._requester_session(ws, reg, observe=(role == P.ROLE_DASHBOARD),
                                          identity=identity)
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
        if entry is None:
            keys[pubkey] = {"role": role, "label": "", "status": "pending",
                            "first_seen": _now(), "fingerprint": fp}
            ID.save_keystore(self.authorized_keys_path, keys)
            await P.send(ws, {"type": P.UNAUTHORIZED,
                              "reason": f"key {fp} recorded, pending approval — ask the admin to approve it"})
            self.log(f"NEW {role} key {fp} recorded pending approval")
            return
        if entry.get("status") != "approved":
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
        if identity:
            node.rep_key = identity["fp"]
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
            self.log(f"node {node.id} availability -> {msg.get('state')} ({msg.get('reason','')})")
            await self.push()
            if node.available:
                await self._drain_queue()   # newly-available node can take waiting jobs
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

    async def _requester_session(self, ws, reg, observe=False, identity=None):
        who = P.ROLE_DASHBOARD if observe else P.ROLE_REQUESTER
        req_id = (identity["label"] if identity else None) or \
            reg.get("requester_id") or (f"{who[:3]}-" + uuid.uuid4().hex[:8])
        await P.send(ws, {"type": P.REGISTERED, "requester_id": req_id})
        if observe:
            self.observers.add(ws)
            await P.send(ws, self.build_state())
        self.log(f"{who} {req_id} connected", record=not observe)
        rep_key = (identity["fp"] if identity else req_id)
        try:
            async for raw in ws:
                msg = P.decode(raw)
                mtype = msg.get("type")
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
        except websockets.ConnectionClosed:
            pass
        finally:
            self.observers.discard(ws)
            self.log(f"{who} {req_id} disconnected", record=not observe)
            # Jobs SURVIVE the requester disconnecting — just drop the push target.
            for job in self.jobs.values():
                if job.requester_ws is ws:
                    job.requester_ws = None

    async def _handle_submit(self, ws, msg, who, req_id, rep_key):
        job_id = msg.get("job_id") or ("job-" + uuid.uuid4().hex[:8])
        if not self.rate_limiter.allow(rep_key):
            await P.send(ws, {"type": P.JOB_FAILED, "job_id": job_id,
                              "reason": "rate limit exceeded — too many jobs; slow down"})
            self.log(f"{who} {req_id} rate-limited")
            return
        job = Job(job_id, ws,
                  needs=msg.get("needs", {}),
                  max_runtime=msg.get("max_runtime_sec", 60),
                  workload=msg.get("workload", {}),
                  target_node=msg.get("target_node"))
        job.requester_key = rep_key
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
        if self.path.split("?")[0] not in ("/", "/index.html", "/dashboard"):
            self.send_error(404)
            return
        try:
            with open(DASHBOARD_HTML, encoding="utf-8") as f:
                html = f.read()
        except OSError:
            self.send_error(500, "dashboard.html not found")
            return
        html = html.replace("{{WS_PORT}}", str(self.ws_port))
        html = html.replace("{{WS_SCHEME}}", self.ws_scheme)
        html = html.replace('"{{TOKEN}}"', json.dumps(self.token or ""))
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
    ap.add_argument("--authorized-keys", help="path to the approved-keys JSON store; enables "
                    "Phase 3 secure mode (keypair challenge-response auth). Manage it with authctl.py")
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
    keys_path = args.authorized_keys or os.environ.get("AICN_AUTHORIZED_KEYS") or None
    rep_path = args.reputation or os.environ.get("AICN_REPUTATION") or None
    gw = Gateway(token=token, authorized_keys_path=keys_path, reputation_path=rep_path,
                 max_jobs_per_min=args.max_jobs_per_min, max_concurrent=args.max_concurrent,
                 min_reliability=args.min_reliability)
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
            "Nodes/requesters must be approved via authctl.py; local dashboard allowed from loopback.")
    if token:
        log("shared-secret token ENABLED — clients must present a matching token.")
    if public and not token:
        log("WARNING: binding to a non-loopback address with NO token. The gateway "
            "runs arbitrary submitted code in sandboxes on your nodes — do NOT expose "
            "it beyond a trusted LAN. Set --token / AICN_TOKEN before widening reach.")
    elif public and token:
        log("WARNING: token is sent in cleartext over ws:// (no TLS until Phase 3). "
            "It blocks casual/unauthenticated access but not a network sniffer — for "
            "real exposure use a private overlay (Tailscale/WireGuard) or wss.")

    if not args.no_dashboard:
        http_scheme = "https" if ssl_ctx else "http"
        start_dashboard_http(args.host, args.http_port, args.port, token or "", ssl_ctx)
        log(f"dashboard: {http_scheme}://127.0.0.1:{args.http_port}  "
            f"(from another device: {http_scheme}://<this-host>:{args.http_port})")
        if token:
            log("note: the dashboard page embeds the token, so keep the dashboard "
                "HTTP port private (localhost/LAN), not public.")

    log(f"listening on {ws_scheme}://{args.host}:{args.port}  ({P.PROTOCOL})")
    async with websockets.serve(gw.handle, args.host, args.port, ssl=ssl_ctx,
                                ping_interval=20, max_size=P.MAX_MSG):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
