# AICN — AI Compute Network · Phase 1 (LAN)

A network for sharing idle compute. A **device owner** lends idle time from a
computer or server; a **requester** submits a workload; a central **gateway**
matches the two and runs the job in an isolated **sandbox** on the borrowed
machine — on the owner's schedule, and only until the owner wants the machine
back.

This repository implements **Phase 1 of the rollout: LAN, no trust machinery.**
The goal of this stage (per the proposal roadmap) is to prove the hard
mechanics — owner scheduling, matching, the sandbox, and result return — in the
simplest possible setting: devices on one local network, no NAT or trust
machinery, no auth/TLS/encryption. Those are deliberately Phase 3 concerns.

> A device lends **raw compute**, not a hosted model. The requester brings the
> workload; the device brings the horsepower.

## Components → files

The five components from the proposal map to these files:

| Component (proposal §3) | File | Role |
|---|---|---|
| **Node agent** | `agent.py` | Runs on the owner's device; dials the gateway, reports hardware + availability, runs jobs. Bundles the scheduler and sandbox. |
| ↳ Scheduler | `scheduler.py` | Enforces owner availability: on/off, scheduled hours, idle auto-detect. |
| ↳ Sandbox runner | `sandbox.py` | Executes the borrowed workload in isolation with hard CPU/memory/time caps. |
| **Gateway** | `gateway.py` | The single shared service: tracks nodes, matches jobs, routes work + results, re-dispatches on drop. |
| **Requester client / API** | `client.py` | Submits jobs with resource needs; receives results. |
| Shared protocol | `protocol.py` | `AICN-C/0.1` — JSON over WebSocket. |
| Hardware detection | `hardware.py` | CPU / RAM / GPU advertised by a node. |

## Owner controls (proposal §4)

Configured in a node config file (see `node.config.example.json`):

- **On / off toggle** — `"enabled"`. Instantly join or leave the pool.
- **Scheduled hours** — `"schedule"`: recurring weekday windows, e.g. weeknights
  midnight–7am, all weekend.
- **Idle auto-detect** — `"idle"`: only share when the machine has been untouched
  for `idle_seconds` (desktop input idle, Windows) **or** CPU usage is below
  `max_cpu_percent` (cross-platform).
- **Instant reclaim** — automatic. The moment availability flips to unavailable
  while a borrowed job is running, the agent evicts the job and reports it; the
  gateway re-dispatches it to another eligible device. Sharing only fills the gaps.

## Install (node agent + CLI)

Contributors (running a node) and requesters (submitting work) install with pip —
no scp, no manual venv. This ships the **agent** and the **`aicn` CLI**; the
gateway is run from source on the hub machine.

```bash
# straight from your repo (recommended — isolated, gives the commands globally):
pipx install git+https://github.com/<you>/aicn-compute
# or from a local checkout:
pip install .
```

Gives two commands:
```bash
aicn-agent --gateway ws://<gateway>:8765           # contribute this machine as a node
aicn config set gateway ws://<gateway>:8765        # point the CLI at the gateway (saved to ~/.aicn)
aicn run script.py --pip numpy --out ./results     # submit work
aicn ls ;  aicn nodes                              # see jobs / the pool
```

The **gateway** stays source-run on the hub: `python gateway.py --host 0.0.0.0`.

> On an SSL-intercepting corporate network, pip's build isolation can't reach
> PyPI. Install with:
> `pip install --no-build-isolation --trusted-host pypi.org --trusted-host files.pythonhosted.org .`
> (after `pip install -U setuptools wheel` with the same `--trusted-host` flags).

## Quick start

```bash
pip install -r requirements.txt      # websockets + psutil + cryptography

# One-command end-to-end demo on localhost (gateway + node + a job):
python run_local_demo.py
```

### The `aicn` CLI (recommended)

`aicn` is the friendly front-end: set your gateway once, then use short commands
(instead of `python client.py --gateway … --long-flags`).

```bash
# one-time: point it at your gateway (saved to ~/.aicn/config.json)
python aicn.py config set gateway ws://192.168.1.136:8765
#   Linux: put ~/aicn on PATH (or symlink the ./aicn launcher) and just type `aicn`

aicn run script.py --pip numpy --ram 4g --out ./results   # submit a script file
aicn run train.py --gpu --target gpuserver-139 --pip torch # on the GPU node
aicn run job.py --array 8 --out ./results                  # 8-task batch
aicn ls                                                     # your jobs + status
aicn nodes                                                  # the pool (cpu/ram/gpu/reliability)
aicn get <job-id> --wait --out ./results                   # retrieve / follow
aicn cancel <job-id>
aicn config show
```

Nice touches: human units (`--ram 4g`, `--timeout 15m`), sensible defaults from
config, and clean errors — a wrong/unreachable gateway prints a one-line hint,
not a stack trace. For secure/token/TLS gateways, set them once in config
(`aicn config set secure true`, `... token <t>`, `... tls_ca cert.pem`).

### Web dashboard

The gateway serves a browser dashboard (no extra dependencies): the live device
pool (availability, hardware, busy/idle, reliability), a submit form (with node
pinning), **live streaming logs**, **downloadable output artifacts**, a running
/queued count, and a **Jobs panel** listing every job with **view** and **cancel**
buttons — everything the CLI does, in the browser.

```bash
python gateway.py                    # dashboard on http://127.0.0.1:8766
```

Open **http://127.0.0.1:8766** on the gateway machine. To view it from another
LAN device, browse to `http://<gateway-ip>:8766` and open that port too (see
below). Disable with `--no-dashboard`; change the port with `--http-port`.

### Running across a LAN

On the machine that will host the gateway:

```bash
python gateway.py --host 0.0.0.0 --port 8765
```

On each device that will lend compute (copy `node.config.example.json` →
`node.config.json`, set `gateway_url` to the gateway's LAN IP):

```bash
python agent.py --config node.config.json
# or quickly:
python agent.py --gateway ws://192.168.1.50:8765 --node-id my-laptop
```

Submit a job from any device:

```bash
python client.py --gateway ws://192.168.1.50:8765 --job examples/hello_job.json
# or an inline one-liner:
python client.py --gateway ws://192.168.1.50:8765 --script "print(2+2)"
```

## Job format

```json
{
  "needs": {"cpu": 1, "ram_mb": 128},
  "max_runtime_sec": 30,
  "workload": {"interpreter": "python", "script": "print('hi')", "input": ""}
}
```

`interpreter` is one of `python`, `bash`, `sh`, `node`. The result returned to
the requester carries `status` (`ok` / `error` / `timeout` / `oom` /
`cancelled`), `exit_code`, `stdout`, `stderr` and `runtime_sec`.

### Batch / job arrays

Submit many related tasks at once — a parameter sweep, N repetitions, frames to
render — and they **fan out across the pool in parallel**, queueing as capacity
allows.

```bash
# N identical tasks; each gets $AICN_TASK_INDEX = 0..N-1
python client.py --gateway ws://GW:8765 --job examples/array_job.json --array 8 --out ./results

# one task per item of a JSON list; each gets $AICN_TASK = that item's JSON
python client.py --gateway ws://GW:8765 --job sweep.json --array-file params.json --out ./results

# submit detached, collect later:
python client.py --gateway ws://GW:8765 --job job.json --array 100 --detach
python client.py --gateway ws://GW:8765 --get-batch batch-abc123 --out ./results
```

Each task reads its parameters from the environment:
```python
import os, json
idx = os.environ["AICN_TASK_INDEX"]                 # "0", "1", ...
params = json.loads(os.environ.get("AICN_TASK", "{}"))   # from --array-file
```
Output artifacts are saved per task under `--out/<index>/`. A batch reports a
summary (`5/8 ok`), and `--get-batch <id>` retrieves the whole group's statuses
and results — even after you disconnect.

Note: `--max-concurrent` (if the gateway sets it) now **queues** a batch's excess
tasks rather than rejecting them, so large batches drain gracefully within the cap.

### Async jobs, queue & retrieval

Jobs are asynchronous and durable. Submitting returns a **job id**; the job is
**queued** if the pool is busy (rather than failing) and runs when a device frees
up; results are **stored on the gateway**, so you can disconnect and retrieve
them later.

```bash
# submit and wait for the result (queues automatically if all nodes are busy):
python client.py --gateway ws://GW:8765 --job examples/hello_job.json

# submit and return immediately with a job id:
python client.py --gateway ws://GW:8765 --job examples/hello_job.json --detach
#   -> job job-abc123 running on gpuserver-139
#      detached — retrieve with:  --get job-abc123

# retrieve later (‑‑wait blocks until it finishes):
python client.py --gateway ws://GW:8765 --get job-abc123 --wait

# cancel a queued or running job:
python client.py --gateway ws://GW:8765 --cancel job-abc123
```

**Live output:** while you wait (a plain submit, or `--get <id> --wait`), a job's
stdout/stderr **stream to you line by line as it runs** — not just a blob at the
end. The gateway also buffers the recent tail, so `--get <id> --wait` on an
already-running job replays what it missed and then follows live. (Python jobs
run unbuffered so prints appear immediately.)

Behavior:
- A job only fails immediately (`JOB_FAILED`) if **no connected device could ever
  satisfy it** (e.g. more RAM than any node has). Otherwise it waits in the queue.
- If a running job's node drops or its owner reclaims it, the job is **re-queued**
  and placed on another device automatically.
- The gateway keeps the last few hundred finished jobs; `--get` returns the stored
  result even after the submitting client is long gone.
- In secure mode a job can only be retrieved/cancelled by the identity that
  submitted it; in open mode the (random) job id is the capability.

### Checkpoint / resume on eviction

Long jobs can survive an owner reclaiming their machine mid-run. If a job saves
its progress to the **`AICN_CHECKPOINT_DIR`** directory, then when it's evicted
the node ships that checkpoint back, the gateway keeps it, and **re-stages it
when re-dispatching** — so the job resumes on the next device instead of
restarting from zero. (This needs the workload to cooperate; a hard node *crash*
can't ship a checkpoint, so only graceful reclaim resumes.)

The job just reads/writes one directory:
```python
import os, json
ck = os.environ["AICN_CHECKPOINT_DIR"]
state = os.path.join(ck, "state.json")
start = json.load(open(state))["next"] if os.path.exists(state) else 0   # resume point
for i in range(start, N):
    ...work...
    json.dump({"next": i + 1}, open(state, "w"))                          # checkpoint
```
See [examples/checkpoint_job.json](examples/checkpoint_job.json). The checkpoint
is internal to resumption; final outputs still go to `$AICN_OUTPUT_DIR`.

### Input files & output artifacts

Jobs can take data in and return files out — not just stdout.

```bash
python client.py --gateway ws://GW:8765 --script "$(cat process.py)" \
  --in data.csv --in config.json \
  --out ./results
```

- **`--in FILE`** (repeatable) uploads a file into the job's working directory,
  readable by the script by its basename (`open("data.csv")`).
- The job writes outputs to the directory named by the **`AICN_OUTPUT_DIR`**
  environment variable (set for every job). Everything it writes there — including
  subdirectories — is collected and returned as **artifacts**.
- **`--out DIR`** saves those artifacts to a local directory; without it they're
  just listed in the result.

Example job body:
```python
import os
data = open("data.csv").read()                     # an --in file
out = os.environ["AICN_OUTPUT_DIR"]                 # where to write results
open(os.path.join(out, "summary.txt"), "w").write(...)
```

Notes: total input and output are base64-encoded in the job messages, so there's
a size cap (output is capped at 32 MB per job); path-traversal in input names is
rejected. Artifacts are stored with the job result, so `--get <id>` retrieves them
later too.

### Per-job dependencies (`pip`)

A Python job can bring its own packages — the node stays clean and any node can
run any workload:

```json
{
  "needs": {"cpu": 1, "ram_mb": 512},
  "max_runtime_sec": 120,
  "workload": {"interpreter": "python", "pip": ["numpy", "pandas"],
               "script": "import numpy as np; print(np.__version__)"}
}
```

```bash
python client.py --script "import numpy as np; print(np.__version__)" --pip numpy
python client.py --job examples/numpy_job.json
```

- The packages install into an **isolated per-job directory** injected via a
  bootstrap, so they never touch the node's own venv.
- Installs are **cached per node** (keyed by the requirement set + Python
  version), so the first job with a given set of packages pays the install cost
  and later ones reuse it instantly. Cache dir: `~/.aicn/pipcache` (override with
  the `AICN_PIP_CACHE` env var).
- The node owner can steer pip without changing the protocol via
  `AICN_PIP_ARGS`, e.g. for an SSL-intercepting network:
  `export AICN_PIP_ARGS="--trusted-host pypi.org --trusted-host files.pythonhosted.org"`
  (or point at a private index with `--index-url`).
- `pip_timeout_sec` (default 300) caps the install.
- Only the **subprocess** backend supports `pip`; the Docker backend runs with
  `--network none`, so bake dependencies into the image there instead.

## GPU jobs

Nodes advertise their GPUs (via `nvidia-smi`, or `rocm-smi` for AMD). A job asks
for one by setting `needs.gpu`, and the gateway routes it only to a node that has
one:

```json
{
  "needs": {"cpu": 1, "ram_mb": 2048, "gpu": 1},
  "max_runtime_sec": 600,
  "workload": {"interpreter": "python", "pip": ["torch"],
               "script": "import torch; print(torch.cuda.is_available())"}
}
```

```bash
python client.py --gateway ws://<gw>:8765 --job examples/gpu_check.json
```

To actually run *on* the GPU and be optimized for it:

- **Bring a GPU framework** with per-job `pip` — e.g. `torch` (Linux PyPI wheels
  include CUDA), or `cupy-cuda12x` (match your driver's CUDA version). numpy alone
  is CPU-only. The framework then does the acceleration (`tensor.to("cuda")`, etc.).
  The first `torch` install is a large download (~GBs) but is cached per node
  afterwards.
- **Driver compatibility:** the wheel's CUDA version must be supported by the
  node's driver. Check with `torch.cuda.is_available()` / `nvidia-smi`.
- **Subprocess sandbox:** GPU jobs run as a normal host process and inherit the
  node's GPU and `CUDA_VISIBLE_DEVICES`. The sandbox does **not** cap GPU memory
  (only host RAM/time), so a GPU job shares the card with the owner's work.
- **Docker sandbox:** the runner passes the GPU through when `needs.gpu` is set —
  `--gpus all` for NVIDIA (needs the NVIDIA Container Toolkit) or `/dev/kfd` +
  `/dev/dri` for AMD (detected by `/dev/kfd`). Install GPU packages into the image
  (per-job `pip` isn't available under `--network none`).

### AMD GPUs (ROCm)

AMD cards use **ROCm**, not CUDA. For a node to advertise and run GPU work:

1. **Install ROCm** on the node (driver + runtime), and confirm `rocm-smi` lists
   the card — that's what the agent detects. The agent's user must be in the
   `render`/`video` groups to access `/dev/kfd` and `/dev/dri`.
2. **Bring a ROCm PyTorch build** via per-job pip using a custom index:

   ```json
   "workload": {
     "interpreter": "python",
     "pip": ["torch"],
     "pip_index_url": "https://download.pytorch.org/whl/rocm6.2",
     "script": "import torch; print(torch.cuda.is_available())"
   }
   ```

   `torch.cuda.is_available()` returns `True` on ROCm too. Match the `rocmX.Y` in
   the index URL to the ROCm version installed on the node. See
   [examples/gpu_check_amd.json](examples/gpu_check_amd.json).
3. Very new cards (e.g. RDNA4 / Radeon AI PRO) need a recent ROCm and may require
   `HSA_OVERRIDE_GFX_VERSION` — set it in the node's environment before starting
   the agent if the runtime doesn't recognize the GPU.

## The sandbox

Every borrowed job runs with hard caps on CPU, memory and wall-clock time in a
throwaway working directory. Two backends share one interface:

- **`subprocess`** (default) — a resource-limited child process. On POSIX it
  applies rlimits (CPU, address space, process count); everywhere it enforces a
  wall-clock timeout and, with psutil, an RSS watchdog. Fine for a **trusted
  LAN**, but *not a hard security boundary*.
- **`hardened`** (`--sandbox hardened`, alias `docker`) — the real isolation
  boundary for **untrusted / stranger code** (Phase 3). Runs `docker run` locked
  down: `--network none`, `--read-only` root with only a size-capped `--tmpfs`
  writable, the job mounted **read-only**, `--cap-drop ALL`, `--security-opt
  no-new-privileges`, a **non-root** user (`65534:65534`), and hard
  memory/CPU/PID/open-file caps. For kernel-level syscall isolation, add
  `--sandbox-runtime runsc` (gVisor) if it's installed on the node. Per-job
  `pip` isn't available here (no network) — bake deps into the image.

Which to use: **`subprocess`** for a trusted LAN; **`hardened`** whenever the
gateway is in secure mode / accepting jobs from people you don't fully trust.
The interface stays pluggable so a micro-VM / confidential-compute backend can
drop in later without touching the agent.

## Shared-secret token (optional gate)

For reaching beyond a fully trusted LAN, the gateway can require a **shared
secret** from every client (node, requester, dashboard). Set it via env var
(preferred — keeps it out of the process list) or `--token`:

```bash
# generate one:
python -c "import secrets; print(secrets.token_urlsafe(32))"

# gateway:
AICN_TOKEN=<secret> python gateway.py --host 0.0.0.0

# node / requester (env var or flag or the node config "token" field):
AICN_TOKEN=<secret> python agent.py --gateway ws://<gw>:8765
python client.py --gateway ws://<gw>:8765 --token <secret> --job examples/hello_job.json
```

When no token is set, the gateway runs open (LAN mode) as before. The comparison
is constant-time, and a client that presents the wrong/no token is rejected with
`UNAUTHORIZED` (the agent stops retrying, the dashboard shows "unauthorized").

**Limits — this is a gate, not real security.** The token is sent in cleartext
over `ws://` (TLS is a Phase 3 concern), so it blocks casual/unauthenticated
access but not a network sniffer. The dashboard page embeds the token, so keep
the dashboard HTTP port private (localhost/LAN). For genuine internet exposure,
put everything on a private overlay (Tailscale/WireGuard) or terminate TLS.

## Phase 3 — identity & approved-key auth (secure mode)

For stranger-to-stranger use, the shared token is replaced by per-participant
**Ed25519 identities** with challenge-response auth and an admin **allowlist**.
Each node/requester has a keypair; the gateway keeps an approved-keys store and
only lets in keys an admin has approved. Ownership is proven by signing a random
nonce, so knowing someone's public key is not enough to impersonate them.

**Each node/requester** — generate an identity and read off its public key:
```bash
python identity.py            # writes ~/.aicn/identity.key, prints pubkey + fingerprint
```
Send the **fingerprint** (and public key) to the gateway admin.

**Gateway admin** — run the gateway in secure mode and manage the allowlist:
```bash
python gateway.py --host 0.0.0.0 --authorized-keys authorized_keys.json
python authctl.py --keys authorized_keys.json pending      # see who has asked to join
python authctl.py --keys authorized_keys.json approve <fingerprint> --label gpu139
python authctl.py --keys authorized_keys.json revoke  <fingerprint>
```
A key is recorded as `pending` automatically the first time its owner tries to
connect; approving it lets them in on their **next reconnect — no gateway restart**.

**Node / requester** — connect in secure mode:
```bash
python agent.py --config node.config.json --secure
python client.py --gateway ws://<gw>:8765 --secure --job examples/hello_job.json
```

Handshake: `HELLO(pubkey)` → `CHALLENGE(nonce)` → `AUTH(signature)` →
`AUTH_OK` → `REGISTER`. Rejections are explicit: `pending approval`, `revoked`,
or `bad signature`. The browser **dashboard** isn't part of keypair auth yet — in
secure mode it's accepted only from **loopback** on the gateway host (tunnel in
over SSH/tailnet for remote viewing).

Secure mode is opt-in (gateway `--authorized-keys`, clients `--secure`); without
it the gateway runs in open LAN/overlay mode as before.

### Encrypted transport (wss / TLS)

The gateway serves `wss://` (and an https dashboard) when given a cert + key;
clients connect over `wss://` and verify it. Generate a self-signed cert (no
openssl needed):

```bash
python gencert.py --host <gateway-ip-or-hostname>    # writes cert.pem + key.pem
python gateway.py --host 0.0.0.0 --tls-cert cert.pem --tls-key key.pem
```

Clients:
```bash
python agent.py  --gateway wss://<gw>:8765 --tls-ca cert.pem --config node.config.json
python client.py --gateway wss://<gw>:8765 --tls-ca cert.pem --job examples/hello_job.json
# testing / over an already-encrypted overlay: --insecure  (encrypts, skips verification)
```

Guidance by deployment:
- **Over Tailscale/WireGuard:** the overlay already encrypts and authenticates,
  so `wss` is redundant — use plain `ws`, or `wss --insecure` if you want a second
  layer. This is the simplest and is fully working.
- **Public gateway:** use a **real CA-signed cert** (Let's Encrypt, e.g. behind a
  Caddy/nginx reverse proxy). Clients then verify against the system trust store
  with no `--tls-ca` needed — the most robust path.

> Note: `--tls-ca` self-signed **verification** requires a modern OpenSSL (3.x).
> The bundled OpenSSL in some older Pythons (e.g. Python 3.10.0 / OpenSSL 1.1.1)
> fails to verify a locally-trusted cert — the *encryption* still works, but on
> such a host use `--insecure` (over an encrypted overlay) or a real CA cert.
> This affects the verifying side only; a gateway just *serving* wss is fine.

### Reputation & abuse limits

The gateway can keep a **persistent, per-identity reputation** and enforce
**abuse limits** — the self-policing layer for an open network:

```bash
python gateway.py --authorized-keys authorized_keys.json \
  --reputation reputation.json \
  --max-jobs-per-min 30 --max-concurrent 5 --min-reliability 0.4
```

- **Reputation** (`--reputation <file>`) — every job outcome is recorded against
  the participant's identity (keypair fingerprint in secure mode, else node id).
  A node's track record **survives reconnects and gateway restarts** and feeds
  the matcher: reliability is a Laplace-smoothed success rate (unknown = 0.5,
  rises with successes, falls with failures/evictions/mid-job drops), and the
  matcher prefers higher-reputation nodes.
- **`--min-reliability`** — once a node has a track record (≥5 outcomes), skip it
  if its reliability is below this floor. Unproven nodes still get a chance.
- **`--max-jobs-per-min`** — sliding-window rate limit per submitter.
- **`--max-concurrent`** — cap on in-flight jobs per submitter.

Rate/concurrency limits are in-memory (reset on restart); reputation is
persisted. All are off by default (0 / no file), so open mode is unchanged.

### Owner allow-rules

A device owner controls exactly what borrowed work their machine will run, via a
`"policy"` block in the node config. It's enforced **on the node** (owner's
consent, owner's machine) before a job executes; a violating job is **refused**
and the gateway re-dispatches it to another node (the refusing node stays
available). Every field is optional; an empty policy allows everything.

```json
"policy": {
  "interpreters": ["python"],       // allowed interpreters (empty = any)
  "allow_pip": false,               // allow per-job pip installs
  "allow_gpu": true,                // allow jobs that request a GPU
  "require_sandbox": "hardened",    // only run if the node uses this sandbox
  "max_ram_mb": 4096,               // ceiling on requested RAM
  "max_runtime_sec": 600,           // ceiling on requested runtime
  "images": ["python:3-slim"],      // allowed container images (hardened; empty = any)
  "allow_requesters": ["<fp>"],     // only these requester fingerprints (empty = any)
  "deny_requesters": ["<fp>"]       // never these requester fingerprints
}
```

Requester rules use the identity fingerprint the gateway forwards with each job
(secure mode). `require_sandbox: "hardened"` is the big one for lending to
strangers — it guarantees untrusted code never runs in the weaker subprocess
sandbox.

Still to come this phase: workload privacy (confidential compute).

## Reaching beyond the LAN — private overlay (recommended)

To let nodes/requesters join from other networks **without exposing anything to
the public internet**, put every machine on a private overlay
(**Tailscale** or WireGuard) instead of port-forwarding.

1. Install Tailscale on the gateway, each node, and any requester machine, and
   authenticate each to your tailnet:
   - Linux node: `curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up`
   - Windows gateway: `winget install tailscale.tailscale` then `tailscale up`
2. Find the gateway's tailnet IP: `tailscale ip -4` (looks like `100.x.y.z`).
3. Point clients at it — no code change, just the address:
   - node config: `"gateway_url": "ws://100.x.y.z:8765"`
   - `python client.py --gateway ws://100.x.y.z:8765 ...`
4. Optionally bind the gateway to the tailnet only: `python gateway.py --host 100.x.y.z`
   (plus `127.0.0.1` for the local dashboard). Use `--host 0.0.0.0` to keep LAN
   access too.

Now any node behind any NAT reaches the gateway over an encrypted tunnel, and
only devices on your tailnet can connect. The shared-secret token becomes
redundant (the tailnet is the access control) — run open, or keep the token as a
second layer if you share the tailnet with other people. Tighten further with
Tailscale ACLs to control which devices may reach the gateway ports.

Note: an overlay secures *transport* and *access*. It does not replace Phase 3's
in-app protections — a node's owner can still observe a workload running on their
own machine. That only matters once strangers join; for your own servers it's a
non-issue.

## Security posture (read this)

Phase 1 is **LAN-only and has no trust machinery by design**:

- **No auth, no TLS, no encryption.** Anyone who can reach the gateway can submit
  jobs and any device can join. Keep it on a trusted local network. **Do not
  port-forward or expose the gateway to the internet** — the gateway prints a
  warning when bound to a non-loopback address.
- **The requester's workload is visible to the device owner.** Shielding the
  requester from a malicious owner is a Phase 3 concern. Run only non-sensitive
  workloads for now.
- The subprocess sandbox protects the *owner* from a malicious/buggy workload on
  a trusted LAN; use the Docker backend for a stronger boundary.

## What's next (roadmap)

- **Phase 2 · Open** — devices dial out to a public gateway so anyone can join
  from behind NAT; prove matching + scale on non-sensitive workloads. (The agent
  already uses the outbound dial-out model, so this is mostly gateway hosting.)
- **Phase 3 · Secured** — end-to-end encryption, hardened sandbox, workload
  privacy, device identity + reputation, abuse limits, owner protections.
