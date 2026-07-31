"""AICN-C/0.1 — wire protocol for the AI Compute Network (Phase 1 · LAN).

A tiny JSON-over-WebSocket protocol. Every message is a JSON object with a
"type" field. This module holds the version string, message-type constants and
a couple of send/recv helpers so the gateway, node agent and requester client
all speak the same dialect.

Phase 1 is LAN-only and has NO trust machinery: no auth, no TLS, no identity.
That is by design (see the proposal roadmap) and is why this must never be
exposed to the public internet.
"""

import json

PROTOCOL = "AICN-C/0.2"

# Max WebSocket message size (bytes). Raised well above the library default so
# jobs can carry base64-encoded input files and return output artifacts.
MAX_MSG = 64 * 1024 * 1024

# --- roles (sent in the first REGISTER message) -----------------------------
ROLE_NODE = "node"
ROLE_REQUESTER = "requester"
ROLE_DASHBOARD = "dashboard"   # like a requester, plus receives live STATE snapshots

# --- Phase 3 identity handshake (secure mode) -------------------------------
# Flow: client HELLO(pubkey, role) -> gateway CHALLENGE(nonce)
#       -> client AUTH(signature)  -> gateway AUTH_OK  (or UNAUTHORIZED)
#       -> client REGISTER(...)    -> gateway REGISTERED
HELLO = "HELLO"            # client -> gateway (public key + role)
CHALLENGE = "CHALLENGE"    # gateway -> client (random nonce to sign)
AUTH = "AUTH"              # client -> gateway (signature over the nonce)
AUTH_OK = "AUTH_OK"        # gateway -> client (identity accepted)

# --- dashboard <-> gateway --------------------------------------------------
STATE = "STATE"                # gateway -> dashboard (live snapshot of the pool)
CONTROL_INFO = "CONTROL_INFO"  # gateway -> dashboard (per-viewer: is control enabled + are you local)

# --- node <-> gateway -------------------------------------------------------
REGISTER = "REGISTER"          # both roles -> gateway (first message)
REGISTERED = "REGISTERED"      # gateway -> either
UNAUTHORIZED = "UNAUTHORIZED"  # gateway -> either (bad/missing shared-secret token)
AVAILABILITY = "AVAILABILITY"  # node -> gateway (owner-availability changed)
NODE_STATS = "NODE_STATS"      # node -> gateway (periodic CPU/RAM/GPU utilization)
NODE_CONTROL = "NODE_CONTROL"  # dashboard -> gateway -> node (admin: pause/resume/schedule)
CONTROL_RESULT = "CONTROL_RESULT"  # gateway -> dashboard (admin action accepted/denied)
RUN_JOB = "RUN_JOB"            # gateway -> node
CANCEL_JOB = "CANCEL_JOB"      # gateway -> node
JOB_RESULT = "JOB_RESULT"      # node -> gateway -> requester
JOB_LOG = "JOB_LOG"            # node -> gateway -> requester (live stdout/stderr chunk)
JOB_EVICTED = "JOB_EVICTED"    # node -> gateway (owner reclaimed / not available)
JOB_REFUSED = "JOB_REFUSED"    # node -> gateway (owner allow-rules declined this job)

# --- requester <-> gateway --------------------------------------------------
SUBMIT_JOB = "SUBMIT_JOB"      # requester -> gateway
JOB_ACCEPTED = "JOB_ACCEPTED"  # gateway -> requester (queued or matched to a node)
JOB_FAILED = "JOB_FAILED"      # gateway -> requester (no capable node / rejected)
GET_JOB = "GET_JOB"            # requester -> gateway (query/retrieve a job by id)
JOB_STATUS = "JOB_STATUS"      # gateway -> requester (lifecycle status + stored result)
GET_BATCH = "GET_BATCH"        # requester -> gateway (retrieve all tasks of a batch)
BATCH_STATUS = "BATCH_STATUS"  # gateway -> requester (per-task status + results)
LIST_JOBS = "LIST_JOBS"        # requester -> gateway (list jobs)
JOBS_LIST = "JOBS_LIST"        # gateway -> requester (job summaries)
GET_NODES = "GET_NODES"        # requester -> gateway (list the pool)
NODES_LIST = "NODES_LIST"      # gateway -> requester (node summaries)

# --- job lifecycle states (Job.status) --------------------------------------
ST_QUEUED = "queued"
ST_RUNNING = "running"
ST_DONE = "done"          # ran to completion (result may itself be ok/error/timeout)
ST_FAILED = "failed"      # gateway-level failure (no capable device)
ST_CANCELLED = "cancelled"

# --- availability states ----------------------------------------------------
AVAIL = "AVAILABLE"
UNAVAIL = "UNAVAILABLE"

# --- admin node-control actions (owner-only, gated by the gateway admin token)
CTL_PAUSE = "pause"            # stop taking new jobs (reversible; running job finishes)
CTL_RESUME = "resume"          # undo a pause
CTL_SET_SCHEDULE = "set_schedule"  # replace the node's recurring availability windows

# --- job result statuses ----------------------------------------------------
OK = "ok"
ERROR = "error"
TIMEOUT = "timeout"
OOM = "oom"
CANCELLED = "cancelled"


async def send(ws, message: dict) -> None:
    """Serialize and send one protocol message over a websocket."""
    await ws.send(json.dumps(message))


def decode(raw) -> dict:
    """Parse an incoming frame into a dict, tolerating bytes or str."""
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", "replace")
    return json.loads(raw)
