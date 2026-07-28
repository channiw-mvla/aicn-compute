#!/usr/bin/env python3
"""aicn — friendly CLI for the AI Compute Network.

Set your gateway once, then use short commands:

    aicn config set gateway ws://192.168.1.136:8765
    aicn run script.py --pip numpy --ram 4g --out ./results
    aicn ls                 # your jobs and their status
    aicn nodes              # the compute pool
    aicn get  <job-id> --wait --out ./results
    aicn cancel <job-id>

Config lives in ~/.aicn/config.json. Flags override config per-command.
"""

import argparse
import asyncio
import base64
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import client as C           # reuse the async job functions
import identity as ID

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".aicn", "config.json")
DEFAULTS = {
    "gateway": "ws://100.65.180.16:8765",   # tailnet gateway; override: aicn config set gateway ...
    "token": None, "secure": False, "identity_key": None,
    "tls_ca": None, "insecure": False,
    "ram": "1g", "timeout": "5m",
}


# -- config -----------------------------------------------------------------
def load_config():
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        try:
            cfg.update(json.load(open(CONFIG_PATH, encoding="utf-8")))
        except (OSError, ValueError):
            pass
    return cfg


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    json.dump(cfg, open(CONFIG_PATH, "w", encoding="utf-8"), indent=2)


def _coerce(key, value):
    if key in ("secure", "insecure"):
        return str(value).lower() in ("1", "true", "yes", "on")
    if str(value).lower() in ("none", "null", ""):
        return None
    return value


# -- human units ------------------------------------------------------------
def parse_size(s):
    """'4g' / '512m' / '2048' -> megabytes."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(g|gb|m|mb|k|kb)?\s*", str(s).lower())
    if not m:
        return int(float(s))
    val = float(m.group(1))
    mult = {"g": 1024, "gb": 1024, "m": 1, "mb": 1, "k": 1 / 1024, "kb": 1 / 1024, None: 1}
    return max(1, int(val * mult[m.group(2)]))


def parse_time(s):
    """'15m' / '30s' / '2h' -> seconds."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(h|m|s)?\s*", str(s).lower())
    if not m:
        return int(float(s))
    return int(float(m.group(1)) * {"h": 3600, "m": 60, "s": 1, None: 1}[m.group(2)])


def _age(ts):
    if not ts:
        return "-"
    d = int(time.time() - ts)
    if d < 60:
        return f"{d}s"
    if d < 3600:
        return f"{d // 60}m"
    return f"{d // 3600}h"


# -- credentials/session helpers --------------------------------------------
def creds(cfg):
    identity = None
    if cfg.get("secure"):
        key = cfg.get("identity_key") or os.path.join(os.path.expanduser("~"), ".aicn", "identity.key")
        identity = ID.load_or_create(key)
    return dict(token=cfg.get("token"), identity=identity,
                tls_ca=cfg.get("tls_ca"), insecure=bool(cfg.get("insecure")))


def call(coro, gateway):
    """Run a coroutine, turning connection failures into a friendly message."""
    try:
        return asyncio.run(coro)
    except (ConnectionRefusedError, ConnectionError, asyncio.TimeoutError, OSError) as e:
        print(f"error: couldn't reach the gateway at {gateway}", file=sys.stderr)
        print("  is it running, and is the address right?  set it with:", file=sys.stderr)
        print("    aicn config set gateway ws://<host>:8765", file=sys.stderr)
        print(f"  ({type(e).__name__}: {e})", file=sys.stderr)
        return None
    except Exception as e:  # noqa: BLE001 - surface anything else cleanly
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return None


# -- commands ---------------------------------------------------------------
def cmd_config(args, cfg):
    if args.action == "show" or args.action is None:
        print(json.dumps(cfg, indent=2))
    elif args.action == "get":
        print(cfg.get(args.key))
    elif args.action == "set":
        cfg[args.key] = _coerce(args.key, args.value)
        save_config(cfg)
        print(f"{args.key} = {cfg[args.key]}")
    return 0


def _build_spec(args, cfg):
    with open(args.file, encoding="utf-8") as f:
        script = f.read()
    workload = {"interpreter": args.interpreter, "script": script, "input": ""}
    if args.pip:
        workload["pip"] = [p.strip() for p in args.pip.split(",") if p.strip()]
    if args.pip_index:
        workload["pip_index_url"] = args.pip_index
    if args.pip_timeout:
        workload["pip_timeout_sec"] = parse_time(args.pip_timeout)
    if args.in_files:
        files = workload.setdefault("files", {})
        for path in args.in_files:
            with open(path, "rb") as fh:
                files[os.path.basename(path)] = base64.b64encode(fh.read()).decode("ascii")
    needs = {"cpu": 1, "ram_mb": parse_size(args.ram or cfg["ram"])}
    if args.gpu:
        needs["gpu"] = 1
    spec = {"needs": needs, "max_runtime_sec": parse_time(args.timeout or cfg["timeout"]),
            "workload": workload}
    if args.target:
        spec["target_node"] = args.target
    return spec


def cmd_run(args, cfg):
    spec = _build_spec(args, cfg)
    gw, cr = cfg["gateway"], creds(cfg)
    if args.array or args.array_file:
        if args.array_file:
            tasks = json.load(open(args.array_file, encoding="utf-8"))
            if not isinstance(tasks, list):
                print("--array-file must be a JSON list", file=sys.stderr); return 64
        else:
            tasks = [None] * args.array
        return call(C.submit_batch(gw, spec, tasks, detach=args.detach, out_dir=args.out, **cr), gw) or 0
    return call(C.submit(gw, spec, detach=args.detach, out_dir=args.out, **cr), gw) or 0


def cmd_get(args, cfg):
    gw, cr = cfg["gateway"], creds(cfg)
    return call(C.get(gw, args.job_id, wait=args.wait, out_dir=args.out, **cr), gw) or 0


def cmd_cancel(args, cfg):
    gw, cr = cfg["gateway"], creds(cfg)
    return call(C.cancel(gw, args.job_id, **cr), gw) or 0


def cmd_ls(args, cfg):
    gw = cfg["gateway"]
    jobs = call(C.list_jobs(gw, **creds(cfg)), gw)
    if jobs is None:
        return 3
    if not jobs:
        print("no jobs")
        return 0
    print(f"{'JOB ID':24} {'STATUS':9} {'NODE':16} {'BATCH':12} AGE")
    for j in jobs:
        print(f"{j['job_id']:24} {j['status']:9} {(j.get('node_id') or '-'):16} "
              f"{(j.get('batch_id') or '-'):12} {_age(j.get('created_at'))}")
    return 0


def cmd_nodes(args, cfg):
    gw = cfg["gateway"]
    nodes = call(C.list_nodes(gw, **creds(cfg)), gw)
    if nodes is None:
        return 3
    if not nodes:
        print("no nodes connected")
        return 0
    print(f"{'NODE':18} {'STATE':10} {'CPU':>4} {'RAM':>8} {'GPU':<22} REL")
    for n in nodes:
        state = "busy" if n["busy"] else ("available" if n["available"] else "offline")
        hw = n.get("hardware", {})
        gpus = hw.get("gpus") or []
        gpu = gpus[0]["name"] if gpus else "-"
        ram = f"{hw.get('ram_mb', 0) // 1024}G" if hw.get("ram_mb") else "?"
        print(f"{n['id']:18} {state:10} {hw.get('cpu', '?'):>4} {ram:>8} {gpu:<22} "
              f"{int(n.get('reliability', 1) * 100)}%")
    return 0


def cmd_install(args, cfg):
    """Prewarm packages into nodes' pip cache so later jobs start instantly."""
    packages = [p.strip() for p in args.packages.split(",") if p.strip()]
    if not packages:
        print("nothing to install", file=sys.stderr)
        return 64
    gw, cr = cfg["gateway"], creds(cfg)
    if args.node:
        targets = [args.node]
    else:
        nodes = call(C.list_nodes(gw, **cr), gw)
        if nodes is None:
            return 3
        targets = [n["id"] for n in nodes]
        if not targets:
            print("no nodes connected")
            return 2
    timeout = parse_time(args.pip_timeout) if args.pip_timeout else 3600
    verify = f"print('prewarmed:', {packages!r})\n"
    rc = 0
    for node in targets:
        workload = {"interpreter": "python", "script": verify,
                    "pip": packages, "pip_timeout_sec": timeout}
        if args.pip_index:
            workload["pip_index_url"] = args.pip_index
        spec = {"needs": {"cpu": 1, "ram_mb": 1024}, "max_runtime_sec": 120,
                "workload": workload, "target_node": node}
        print(f"-> installing {','.join(packages)} on {node} "
              f"(up to {timeout}s; cached on that node afterwards)...", flush=True)
        r = call(C.submit(gw, spec, **cr), gw)
        if r not in (0, None):
            rc = r
    print("\nnote: `aicn run` jobs must use the SAME --pip (and --pip-index) list "
          "to hit this cache.")
    return rc


def main():
    cfg = load_config()
    ap = argparse.ArgumentParser(prog="aicn", description="AI Compute Network CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("config", help="view/set config (~/.aicn/config.json)")
    p.add_argument("action", nargs="?", choices=["show", "get", "set"], default="show")
    p.add_argument("key", nargs="?"); p.add_argument("value", nargs="?")

    def add_run(pr):
        pr.add_argument("file", help="script file to run")
        pr.add_argument("--interpreter", default="python", choices=["python", "bash", "sh", "node"])
        pr.add_argument("--pip", help="comma-separated packages, e.g. numpy,torch")
        pr.add_argument("--pip-index", dest="pip_index", help="custom pip index URL (ROCm/CUDA wheels)")
        pr.add_argument("--pip-timeout", dest="pip_timeout", help="install time budget, e.g. 30m")
        pr.add_argument("--ram", help="RAM budget, e.g. 4g / 512m (default from config)")
        pr.add_argument("--timeout", help="max runtime, e.g. 15m / 2h (default from config)")
        pr.add_argument("--gpu", action="store_true", help="require a GPU node")
        pr.add_argument("--target", help="pin to a specific node id")
        pr.add_argument("--in", dest="in_files", action="append", metavar="FILE", help="input file (repeatable)")
        pr.add_argument("--out", metavar="DIR", help="save output artifacts here")
        pr.add_argument("--detach", action="store_true", help="return a job id immediately")
        pr.add_argument("--array", type=int, metavar="N", help="run as N parallel tasks")
        pr.add_argument("--array-file", dest="array_file", metavar="FILE", help="JSON list of per-task params")

    add_run(sub.add_parser("run", help="submit a script file as a job"))

    p = sub.add_parser("get", help="retrieve a job")
    p.add_argument("job_id"); p.add_argument("--wait", action="store_true")
    p.add_argument("--out", metavar="DIR")

    p = sub.add_parser("cancel", help="cancel a job")
    p.add_argument("job_id")

    sub.add_parser("ls", help="list jobs")
    sub.add_parser("nodes", help="list the compute pool")

    p = sub.add_parser("install", help="prewarm packages on nodes so jobs start fast")
    p.add_argument("packages", help="comma-separated packages, e.g. numpy,tensorflow")
    p.add_argument("--node", help="install on one node id (default: all connected nodes)")
    p.add_argument("--pip-index", dest="pip_index", help="custom pip index URL (ROCm/CUDA wheels)")
    p.add_argument("--pip-timeout", dest="pip_timeout", help="install budget, e.g. 60m (default 60m)")

    args = ap.parse_args()
    handler = {"config": cmd_config, "run": cmd_run, "get": cmd_get, "cancel": cmd_cancel,
               "ls": cmd_ls, "nodes": cmd_nodes, "install": cmd_install}[args.cmd]
    sys.exit(handler(args, cfg) or 0)


if __name__ == "__main__":
    main()
