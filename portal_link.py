"""Bridge from a gateway to the portal — in one of two modes:

* API mode (federated): set AICN_PORTAL_URL + AICN_GATEWAY_TOKEN. The gateway is
  remote, run by an org, and talks to the central portal over HTTPS. Each gateway
  serves exactly ONE org (the org its token belongs to).

* DB mode (co-located): set AICN_PORTAL_DB to the portal's SQLite file (portal and
  gateway on the same box).

If neither is set every call is a no-op and the gateway is a plain flat pool.
All calls fail soft (return "no info") so a portal hiccup can't crash the gateway.
"""

import json
import os
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timezone

PORTAL_DB = os.environ.get("AICN_PORTAL_DB")
PORTAL_URL = (os.environ.get("AICN_PORTAL_URL") or "").rstrip("/")
GATEWAY_TOKEN = os.environ.get("AICN_GATEWAY_TOKEN")

_API = bool(PORTAL_URL and GATEWAY_TOKEN)
_org_id = None            # this gateway's org (API mode) — set by heartbeat()
_org_slug = None


def api_mode() -> bool:
    return _API


def enabled() -> bool:
    return _API or (bool(PORTAL_DB) and os.path.exists(PORTAL_DB))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============================ API mode (HTTP) ==============================
last_error = None          # why the most recent API call failed (for logging)


def _api(method, path, body=None, params=None):
    global last_error
    url = PORTAL_URL + path
    if params:
        from urllib.parse import urlencode
        url += "?" + urlencode(params)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + GATEWAY_TOKEN)
    # Identify ourselves properly: the default "Python-urllib/x.y" user agent is
    # blocked as a bot by Cloudflare (403) when the portal sits behind a tunnel.
    req.add_header("User-Agent", "AICN-Gateway/0.2")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            last_error = None
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        # 401 means the portal answered and rejected us — a very different
        # problem from "unreachable", so say so.
        last_error = ("this gateway's token was rejected (401) — it may have been "
                      "removed or re-registered in the portal; update AICN_GATEWAY_TOKEN"
                      if e.code == 401 else f"portal returned HTTP {e.code}")
        return None
    except Exception as e:
        last_error = f"cannot reach the portal: {e}"
        return None


def heartbeat():
    """API mode: mark this gateway online + learn its org. No-op in DB mode."""
    global _org_id, _org_slug
    if not _API:
        return None
    r = _api("POST", "/api/gw/heartbeat", body={})
    if r and r.get("org_id") is not None:
        _org_id, _org_slug = r["org_id"], r.get("org_slug")
    return r


def my_org_id():
    return _org_id


# ============================ DB mode (SQLite) =============================
def _conn():
    conn = sqlite3.connect(PORTAL_DB, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


# ============================ shared operations ============================
def claim_server(token, fingerprint):
    if not (enabled() and token and fingerprint):
        return None
    if _API:
        r = _api("POST", "/api/gw/claim", body={"claim_token": token, "fingerprint": fingerprint})
        return (r or {}).get("server_id")
    try:
        conn = _conn()
        try:
            row = conn.execute("SELECT id FROM servers WHERE claim_token = ?", (token,)).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE servers SET fingerprint=?, claimed_at=?, claim_token=NULL, last_seen=? WHERE id=?",
                (fingerprint, _now(), _now(), row["id"]))
            conn.commit()
            return row["id"]
        finally:
            conn.close()
    except Exception:
        return None


def touch_server(fingerprint):
    if not (enabled() and fingerprint):
        return
    if _API:
        _api("POST", "/api/gw/touch", body={"fingerprint": fingerprint})
        return
    try:
        conn = _conn()
        try:
            conn.execute("UPDATE servers SET last_seen=? WHERE fingerprint=?", (_now(), fingerprint))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def org_ids_for_fingerprint(fingerprint):
    """The org ids a node's server belongs to — the routing key. In API mode a
    gateway serves one org, so this is {my_org} if the node belongs, else empty."""
    if not (enabled() and fingerprint):
        return set()
    if _API:
        if _org_id is None:
            return set()
        r = _api("GET", "/api/gw/node", params={"fingerprint": fingerprint})
        return {_org_id} if (r or {}).get("belongs") else set()
    try:
        conn = _conn()
        try:
            rows = conn.execute(
                "SELECT ss.org_id FROM servers s JOIN server_shares ss ON ss.server_id=s.id "
                "WHERE s.fingerprint=?", (fingerprint,)).fetchall()
            org = conn.execute("SELECT org_id FROM servers WHERE fingerprint=?", (fingerprint,)).fetchone()
            out = {r["org_id"] for r in rows}
            if org and org["org_id"] is not None:      # Option A: servers.org_id
                out.add(org["org_id"])
            return out
        finally:
            conn.close()
    except Exception:
        return set()


def authorize_org_submit(api_token, org_slug):
    """Resolve a CLI --org submission: returns the org id if the api_token's user
    may submit to org_slug, else None. Works in both modes."""
    if not (enabled() and org_slug):
        return None
    if _API:
        if _org_slug is None or org_slug != _org_slug:
            return None                                 # a gateway only serves its own org
        r = _api("GET", "/api/gw/authz", params={"api_token": api_token or ""})
        return _org_id if (r or {}).get("member") else None
    try:
        conn = _conn()
        try:
            u = conn.execute(
                "SELECT user_id FROM api_tokens WHERE token=? AND revoked=0", (api_token,)).fetchone()
            if u is None:
                return None
            org = conn.execute("SELECT id FROM orgs WHERE slug=?", (org_slug,)).fetchone()
            if org is None:
                return None
            m = conn.execute("SELECT 1 FROM memberships WHERE user_id=? AND org_id=?",
                             (u["user_id"], org["id"])).fetchone()
            return org["id"] if m else None
        finally:
            conn.close()
    except Exception:
        return None


# ============================ web-job queue ===============================
def fetch_pending_web_jobs():
    if not enabled():
        return []
    if _API:
        r = _api("GET", "/api/gw/jobs/pending")
        return (r or {}).get("jobs", []) or []
    try:
        conn = _conn()
        try:
            rows = conn.execute(
                "SELECT id, org_id, user_id, interpreter, script, pip, ram_mb, max_runtime "
                "FROM web_jobs WHERE status='pending' ORDER BY id ASC LIMIT 20").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
    except Exception:
        return []


def mark_web_job(web_id, status, gateway_job_id=None, node_id=None):
    if not enabled():
        return
    if _API:
        body = {"status": status}
        if gateway_job_id is not None:
            body["gateway_job_id"] = gateway_job_id
        if node_id is not None:
            body["node_id"] = node_id
        _api("POST", f"/api/gw/jobs/{web_id}", body=body)
        return
    try:
        conn = _conn()
        try:
            conn.execute(
                "UPDATE web_jobs SET status=?, gateway_job_id=COALESCE(?,gateway_job_id), "
                "node_id=COALESCE(?,node_id) WHERE id=?",
                (status, gateway_job_id, node_id, web_id))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def finish_web_job(web_id, status, node_id, result):
    if not enabled():
        return
    result = result or {}

    def clip(s):
        s = s or ""
        return s[:20000] if isinstance(s, str) else str(s)[:20000]

    fields = {"status": status, "result_status": result.get("status"),
              "exit_code": result.get("exit_code"), "stdout": clip(result.get("stdout")),
              "stderr": clip(result.get("stderr")), "finished_at": _now()}
    if node_id is not None:
        fields["node_id"] = node_id
    if _API:
        _api("POST", f"/api/gw/jobs/{web_id}", body=fields)
        return
    try:
        conn = _conn()
        try:
            conn.execute(
                "UPDATE web_jobs SET status=?, node_id=COALESCE(?,node_id), result_status=?, "
                "exit_code=?, stdout=?, stderr=?, finished_at=? WHERE id=?",
                (fields["status"], node_id, fields["result_status"], fields["exit_code"],
                 fields["stdout"], fields["stderr"], fields["finished_at"], web_id))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass
