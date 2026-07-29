"""Requester client / API (proposal section 03).

Submits a workload to the gateway. Jobs are async: submit returns a job id, the
job is queued if the pool is busy, and results are stored so you can retrieve
them later even if you disconnected.

    # submit and wait for the result:
    python client.py --gateway ws://GW:8765 --job examples/hello_job.json

    # submit and return immediately with a job id:
    python client.py --gateway ws://GW:8765 --job examples/hello_job.json --detach

    # retrieve a job later (add --wait to block until it finishes):
    python client.py --gateway ws://GW:8765 --get job-abc123 [--wait]

    # cancel a queued or running job:
    python client.py --gateway ws://GW:8765 --cancel job-abc123
"""

import argparse
import asyncio
import base64
import json
import os
import sys
import uuid
from contextlib import asynccontextmanager

import websockets

import identity as ID
import protocol as P
import tlsutil


class _AuthError(Exception):
    pass


@asynccontextmanager
async def _session(gateway_url, token, identity, tls_ca, insecure):
    """Open a connection, authenticate, register as a requester, yield the ws."""
    ssl_param = (tlsutil.client_context(tls_ca, insecure)
                 if gateway_url.startswith("wss://") else None)
    async with websockets.connect(gateway_url, ssl=ssl_param, ping_interval=20,
                                  max_size=P.MAX_MSG) as ws:
        if identity is not None:
            ok, reason = await ID.client_handshake(ws, identity, P.ROLE_REQUESTER)
            if not ok:
                raise _AuthError(reason)
        reg = {"type": P.REGISTER, "role": P.ROLE_REQUESTER}
        if token:
            reg["token"] = token
        await P.send(ws, reg)
        first = P.decode(await ws.recv())
        if first.get("type") == P.UNAUTHORIZED:
            raise _AuthError(first.get("reason"))
        yield ws


async def submit(gateway_url, job_spec, token=None, identity=None, tls_ca=None,
                 insecure=False, detach=False, out_dir=None):
    job_id = job_spec.get("job_id") or ("job-" + uuid.uuid4().hex[:8])
    try:
        async with _session(gateway_url, token, identity, tls_ca, insecure) as ws:
            msg = {"type": P.SUBMIT_JOB, "job_id": job_id,
                   "needs": job_spec.get("needs", {}),
                   "max_runtime_sec": job_spec.get("max_runtime_sec", 60),
                   "workload": job_spec["workload"]}
            if job_spec.get("target_node"):
                msg["target_node"] = job_spec["target_node"]
            await P.send(ws, msg)

            streamed = False
            async for raw in ws:
                m = P.decode(raw)
                mtype = m.get("type")
                if mtype == P.JOB_ACCEPTED:
                    if m.get("status") == P.ST_QUEUED:
                        print(f"job {job_id} QUEUED (position {m.get('queue_position','?')}) — "
                              "pool busy; it will run when a device frees up", flush=True)
                    else:
                        print(f"job {job_id} running on {m.get('node_id')}", flush=True)
                    if detach:
                        print(f"detached — retrieve with:  --get {job_id}", flush=True)
                        return 0
                elif mtype == P.JOB_LOG:
                    _emit_log(m); streamed = True
                elif mtype == P.JOB_FAILED:
                    print(f"JOB FAILED: {m.get('reason')}", flush=True)
                    return 2
                elif mtype == P.JOB_RESULT:
                    _print_result(m, streamed, out_dir)
                    return 0 if m.get("status") == P.OK else 1
    except _AuthError as e:
        print(f"UNAUTHORIZED: {e}", flush=True)
        return 4
    return 3


async def get(gateway_url, job_id, token=None, identity=None, tls_ca=None,
              insecure=False, wait=False, out_dir=None):
    try:
        async with _session(gateway_url, token, identity, tls_ca, insecure) as ws:
            await P.send(ws, {"type": P.GET_JOB, "job_id": job_id, "follow": bool(wait)})
            streamed = False
            async for raw in ws:
                m = P.decode(raw)
                mtype = m.get("type")
                if mtype == P.JOB_STATUS:
                    status = m.get("status")
                    if m.get("result") is not None:
                        print(f"job {job_id}: {status}")
                        _print_result(m["result"], streamed, out_dir)
                        return 0 if m["result"].get("status") == P.OK else 1
                    pos = f" (position {m.get('queue_position')})" if m.get("queue_position") else ""
                    print(f"job {job_id}: {status}{pos}", flush=True)
                    if status in (P.ST_QUEUED, P.ST_RUNNING) and wait:
                        continue          # gateway re-attached us; wait for logs + result
                    return 0 if status in (P.ST_QUEUED, P.ST_RUNNING, P.ST_DONE) else 1
                elif mtype == P.JOB_LOG:
                    _emit_log(m); streamed = True
                elif mtype == P.JOB_RESULT:
                    _print_result(m, streamed, out_dir)
                    return 0 if m.get("status") == P.OK else 1
    except _AuthError as e:
        print(f"UNAUTHORIZED: {e}", flush=True)
        return 4
    return 3


async def cancel(gateway_url, job_id, token=None, identity=None, tls_ca=None, insecure=False):
    try:
        async with _session(gateway_url, token, identity, tls_ca, insecure) as ws:
            await P.send(ws, {"type": P.CANCEL_JOB, "job_id": job_id})
            m = P.decode(await asyncio.wait_for(ws.recv(), 10))
            print(f"job {job_id}: {m.get('status')}", flush=True)
            return 0
    except _AuthError as e:
        print(f"UNAUTHORIZED: {e}", flush=True)
        return 4
    except Exception as e:
        print(f"error: {e}", flush=True)
        return 3


async def submit_batch(gateway_url, base_spec, tasks, token=None, identity=None,
                       tls_ca=None, insecure=False, detach=False, out_dir=None):
    batch_id = "batch-" + uuid.uuid4().hex[:8]
    try:
        async with _session(gateway_url, token, identity, tls_ca, insecure) as ws:
            for i, params in enumerate(tasks):
                wl = dict(base_spec["workload"])
                env = dict(wl.get("env") or {})
                env["AICN_TASK_INDEX"] = str(i)
                if params is not None:
                    env["AICN_TASK"] = json.dumps(params)
                wl["env"] = env
                m = {"type": P.SUBMIT_JOB, "job_id": f"{batch_id}.{i}", "batch_id": batch_id,
                     "needs": base_spec.get("needs", {}),
                     "max_runtime_sec": base_spec.get("max_runtime_sec", 60), "workload": wl}
                if base_spec.get("target_node"):
                    m["target_node"] = base_spec["target_node"]
                await P.send(ws, m)
            n = len(tasks)
            print(f"submitted batch {batch_id}: {n} task(s), fanning out across the pool", flush=True)
            if detach:
                print(f"detached — retrieve with:  --get-batch {batch_id}", flush=True)
                return 0
            pending = {f"{batch_id}.{i}" for i in range(n)}
            results = {}
            async for raw in ws:
                m = P.decode(raw)
                t = m.get("type")
                if t == P.JOB_RESULT:
                    results[m["job_id"]] = m
                    pending.discard(m["job_id"])
                elif t == P.JOB_FAILED:
                    results[m["job_id"]] = {"status": "failed", "reason": m.get("reason")}
                    pending.discard(m["job_id"])
                if not pending:
                    break
            return _print_batch(batch_id, results, out_dir)
    except _AuthError as e:
        print(f"UNAUTHORIZED: {e}", flush=True)
        return 4
    return 3


async def get_batch(gateway_url, batch_id, token=None, identity=None, tls_ca=None,
                    insecure=False, out_dir=None):
    try:
        async with _session(gateway_url, token, identity, tls_ca, insecure) as ws:
            await P.send(ws, {"type": P.GET_BATCH, "batch_id": batch_id})
            m = P.decode(await asyncio.wait_for(ws.recv(), 15))
            if m.get("type") != P.BATCH_STATUS:
                print("unexpected reply", flush=True)
                return 3
            tasks = m.get("tasks", [])
            if not tasks:
                print(f"batch {batch_id}: no tasks found", flush=True)
                return 2
            results = {t["job_id"]: (t.get("result") or {"status": t.get("status")}) for t in tasks}
            return _print_batch(batch_id, results, out_dir)
    except _AuthError as e:
        print(f"UNAUTHORIZED: {e}", flush=True)
        return 4
    return 3


def _emit_log(msg):
    """Print a live JOB_LOG chunk to the matching stream."""
    data = msg.get("data", "")
    if msg.get("stream") == "stderr":
        sys.stderr.write(data); sys.stderr.flush()
    else:
        sys.stdout.write(data); sys.stdout.flush()


async def list_jobs(gateway_url, token=None, identity=None, tls_ca=None, insecure=False):
    async with _session(gateway_url, token, identity, tls_ca, insecure) as ws:
        await P.send(ws, {"type": P.LIST_JOBS})
        m = P.decode(await asyncio.wait_for(ws.recv(), 15))
        return m.get("jobs", [])


async def list_nodes(gateway_url, token=None, identity=None, tls_ca=None, insecure=False):
    async with _session(gateway_url, token, identity, tls_ca, insecure) as ws:
        await P.send(ws, {"type": P.GET_NODES})
        m = P.decode(await asyncio.wait_for(ws.recv(), 15))
        return m.get("nodes", [])


def _save_artifacts(artifacts, out_dir):
    n = 0
    base = os.path.abspath(out_dir)
    for name, b64 in artifacts.items():
        try:
            data = base64.b64decode(b64)
        except Exception:
            continue
        dest = os.path.normpath(os.path.join(base, name))
        if not (dest == base or dest.startswith(base + os.sep)):
            continue
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data)
        n += 1
    return n


def _task_index(job_id):
    try:
        return int(job_id.rsplit(".", 1)[1])
    except (ValueError, IndexError):
        return job_id


def _print_batch(batch_id, results, out_dir):
    ok = 0
    for jid in sorted(results, key=lambda j: (isinstance(_task_index(j), str), _task_index(j))):
        res = results[jid] or {}
        st = res.get("status")
        arts = res.get("artifacts") or {}
        extra = ""
        if arts and out_dir:
            sub = os.path.join(out_dir, str(_task_index(jid)))
            _save_artifacts(arts, sub)
            extra = f"  -> {len(arts)} artifact(s)"
        elif arts:
            extra = f"  ({len(arts)} artifact(s))"
        reason = f" — {res.get('reason')}" if res.get("reason") else ""
        print(f"  task {_task_index(jid)}: {st}{reason}{extra}")
        if st == P.OK:
            ok += 1
    tail = f"  (artifacts under {out_dir}/<index>/)" if out_dir else ""
    print(f"batch {batch_id}: {ok}/{len(results)} ok{tail}")
    return 0 if ok == len(results) else 1


def _print_result(msg, streamed=False, out_dir=None):
    print("\n=== result ===")
    print(f"status    : {msg.get('status')}")
    print(f"exit code : {msg.get('exit_code')}")
    print(f"runtime   : {msg.get('runtime_sec')}s")
    if streamed:
        print("(output streamed above)")
    else:
        if msg.get("stdout"):
            print("--- stdout ---")
            print(msg["stdout"].rstrip())
        if msg.get("stderr"):
            print("--- stderr ---")
            print(msg["stderr"].rstrip())
    _handle_artifacts(msg.get("artifacts") or {}, out_dir)


def _handle_artifacts(artifacts, out_dir):
    if not artifacts:
        return
    print(f"--- artifacts ({len(artifacts)}) ---")
    for name, b64 in artifacts.items():
        try:
            data = base64.b64decode(b64)
        except Exception:
            continue
        print(f"  {name}  ({len(data)} bytes)")
        if out_dir:
            base = os.path.abspath(out_dir)
            dest = os.path.normpath(os.path.join(base, name))
            if not (dest == base or dest.startswith(base + os.sep)):
                continue
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            with open(dest, "wb") as f:
                f.write(data)
    if out_dir:
        print(f"  -> saved to {out_dir}")


def load_job(args):
    if args.job:
        with open(args.job, encoding="utf-8") as f:
            return json.load(f)
    script = args.script
    if args.script_file:
        with open(args.script_file, encoding="utf-8") as f:
            script = f.read()
    if script is not None:
        workload = {"interpreter": args.interpreter, "script": script, "input": ""}
        if args.pip:
            workload["pip"] = [p.strip() for p in args.pip.split(",") if p.strip()]
        if args.pip_timeout:
            workload["pip_timeout_sec"] = args.pip_timeout
        return {
            "needs": {"cpu": 1, "ram_mb": args.ram_mb},
            "max_runtime_sec": args.max_runtime,
            "workload": workload,
        }
    print("error: pass --job <file.json>, --script <code>, or --script-file <file>", file=sys.stderr)
    sys.exit(64)


def main():
    ap = argparse.ArgumentParser(description="AICN requester client")
    ap.add_argument("--gateway", default="ws://100.65.180.16:8765")
    ap.add_argument("--token", help="shared-secret token (or set AICN_TOKEN env var)")
    ap.add_argument("--secure", action="store_true", help="use Phase 3 keypair auth (matches a secure gateway)")
    ap.add_argument("--identity-key", help="path to your private identity key (default ~/.aicn/identity.key)")
    ap.add_argument("--tls-ca", help="CA/self-signed cert (PEM) to verify a wss:// gateway")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (testing only)")
    ap.add_argument("--target", help="pin the job to a specific node id (default: auto-match)")
    ap.add_argument("--job", help="path to a job spec JSON")
    ap.add_argument("--script", help="inline script to run (with --interpreter)")
    ap.add_argument("--script-file", help="path to a script file to run (avoids shell quoting)")
    ap.add_argument("--interpreter", default="python", choices=["python", "bash", "sh", "node"])
    ap.add_argument("--pip", help="comma-separated packages to install for this job, e.g. numpy,pandas")
    ap.add_argument("--pip-timeout", type=int, help="seconds allowed for the per-job pip install (default 600)")
    ap.add_argument("--ram-mb", type=int, default=128, dest="ram_mb")
    ap.add_argument("--max-runtime", type=int, default=60)
    ap.add_argument("--detach", action="store_true", help="submit and return a job id immediately")
    ap.add_argument("--get", metavar="JOB_ID", help="retrieve a previously submitted job")
    ap.add_argument("--wait", action="store_true", help="with --get: block until the job finishes")
    ap.add_argument("--cancel", metavar="JOB_ID", help="cancel a queued or running job")
    ap.add_argument("--in", dest="in_files", action="append", metavar="FILE",
                    help="input file to place in the job's working dir (repeatable)")
    ap.add_argument("--out", dest="out_dir", metavar="DIR",
                    help="save the job's output artifacts (from $AICN_OUTPUT_DIR) into this dir")
    ap.add_argument("--array", type=int, metavar="N",
                    help="run the job as a batch of N tasks (each gets $AICN_TASK_INDEX 0..N-1)")
    ap.add_argument("--array-file", metavar="FILE",
                    help="JSON list of param objects; one task per item ($AICN_TASK = its JSON)")
    ap.add_argument("--get-batch", metavar="BATCH_ID", help="retrieve all tasks of a batch")
    args = ap.parse_args()

    token = args.token or os.environ.get("AICN_TOKEN")
    identity = None
    if args.secure:
        key_path = args.identity_key or os.path.join(
            os.path.expanduser("~"), ".aicn", "identity.key")
        identity = ID.load_or_create(key_path)
        print(f"secure mode: identity {identity.fingerprint} ({key_path})")

    common = dict(token=token, identity=identity, tls_ca=args.tls_ca, insecure=args.insecure)

    if args.get_batch:
        rc = asyncio.run(get_batch(args.gateway, args.get_batch, out_dir=args.out_dir, **common))
        sys.exit(rc)
    if args.get:
        rc = asyncio.run(get(args.gateway, args.get, wait=args.wait, out_dir=args.out_dir, **common))
        sys.exit(rc)
    if args.cancel:
        rc = asyncio.run(cancel(args.gateway, args.cancel, **common))
        sys.exit(rc)

    job_spec = load_job(args)
    if args.target:
        job_spec["target_node"] = args.target
    if args.in_files:
        files = job_spec.setdefault("workload", {}).setdefault("files", {})
        for path in args.in_files:
            with open(path, "rb") as f:
                files[os.path.basename(path)] = base64.b64encode(f.read()).decode("ascii")

    if args.array or args.array_file:
        if args.array_file:
            tasks = json.load(open(args.array_file, encoding="utf-8"))
            if not isinstance(tasks, list):
                print("--array-file must contain a JSON list", file=sys.stderr); sys.exit(64)
        else:
            tasks = [None] * args.array
        rc = asyncio.run(submit_batch(args.gateway, job_spec, tasks, detach=args.detach,
                                      out_dir=args.out_dir, **common))
    else:
        rc = asyncio.run(submit(args.gateway, job_spec, detach=args.detach,
                                out_dir=args.out_dir, **common))
    sys.exit(rc)


if __name__ == "__main__":
    main()
