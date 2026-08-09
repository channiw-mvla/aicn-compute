"""Bridge from the gateway to the portal database (a shared SQLite file).

Lets the gateway resolve node ownership + org sharing and authenticate job
submitters by API token, so a job routes only to servers shared into the
submitter's organization.

Enabled only when AICN_PORTAL_DB points at the portal's database. When it isn't
set (or the file is missing), every call is a safe no-op and the gateway behaves
exactly as before — a single flat pool. Read/write failures never raise; they
degrade to "no info", so a portal hiccup can't take the gateway down.
"""

import os
import sqlite3
from datetime import datetime, timezone

PORTAL_DB = os.environ.get("AICN_PORTAL_DB")


def enabled() -> bool:
    return bool(PORTAL_DB) and os.path.exists(PORTAL_DB)


def _conn():
    conn = sqlite3.connect(PORTAL_DB, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def claim_server(token, fingerprint):
    """Bind an agent's fingerprint to a server via its one-time claim token.
    Returns the server id, or None."""
    if not (enabled() and token and fingerprint):
        return None
    try:
        conn = _conn()
        try:
            row = conn.execute("SELECT id FROM servers WHERE claim_token = ?", (token,)).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE servers SET fingerprint = ?, claimed_at = ?, claim_token = NULL, "
                "last_seen = ? WHERE id = ?",
                (fingerprint, _now(), _now(), row["id"]),
            )
            conn.commit()
            return row["id"]
        finally:
            conn.close()
    except Exception:
        return None


def touch_server(fingerprint) -> None:
    if not (enabled() and fingerprint):
        return
    try:
        conn = _conn()
        try:
            conn.execute("UPDATE servers SET last_seen = ? WHERE fingerprint = ?",
                         (_now(), fingerprint))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def org_ids_for_fingerprint(fingerprint) -> set:
    """The org ids a claimed server is shared into — the routing key."""
    if not (enabled() and fingerprint):
        return set()
    try:
        conn = _conn()
        try:
            rows = conn.execute(
                "SELECT ss.org_id FROM servers s JOIN server_shares ss ON ss.server_id = s.id "
                "WHERE s.fingerprint = ?",
                (fingerprint,),
            ).fetchall()
            return {r["org_id"] for r in rows}
        finally:
            conn.close()
    except Exception:
        return set()


def user_for_api_token(token):
    """(user_id, email) for a live API token, or None."""
    if not (enabled() and token):
        return None
    try:
        conn = _conn()
        try:
            r = conn.execute(
                "SELECT u.id AS id, u.email AS email FROM api_tokens t JOIN users u ON u.id = t.user_id "
                "WHERE t.token = ? AND t.revoked = 0",
                (token,),
            ).fetchone()
            return (r["id"], r["email"]) if r else None
        finally:
            conn.close()
    except Exception:
        return None


def org_id_for_slug(slug):
    if not (enabled() and slug):
        return None
    try:
        conn = _conn()
        try:
            r = conn.execute("SELECT id FROM orgs WHERE slug = ?", (slug,)).fetchone()
            return r["id"] if r else None
        finally:
            conn.close()
    except Exception:
        return None


def user_in_org(user_id, org_id) -> bool:
    if not enabled():
        return False
    try:
        conn = _conn()
        try:
            r = conn.execute("SELECT 1 FROM memberships WHERE user_id = ? AND org_id = ?",
                             (user_id, org_id)).fetchone()
            return r is not None
        finally:
            conn.close()
    except Exception:
        return False


# -- web-job queue (browser-submitted jobs the gateway runs) -----------------
def fetch_pending_web_jobs():
    """Pending web jobs to pick up; each returned as a plain dict."""
    if not enabled():
        return []
    try:
        conn = _conn()
        try:
            rows = conn.execute(
                "SELECT id, org_id, user_id, interpreter, script, pip, ram_mb, max_runtime "
                "FROM web_jobs WHERE status = 'pending' ORDER BY id ASC LIMIT 20"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
    except Exception:
        return []


def mark_web_job(web_id, status, gateway_job_id=None, node_id=None):
    if not enabled():
        return
    try:
        conn = _conn()
        try:
            conn.execute(
                "UPDATE web_jobs SET status = ?, "
                "gateway_job_id = COALESCE(?, gateway_job_id), "
                "node_id = COALESCE(?, node_id) WHERE id = ?",
                (status, gateway_job_id, node_id, web_id),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def finish_web_job(web_id, status, node_id, result):
    """Write a terminal web job's outcome back to the portal DB."""
    if not enabled():
        return
    result = result or {}

    def clip(s):
        s = s or ""
        return s[:20000] if isinstance(s, str) else str(s)[:20000]

    try:
        conn = _conn()
        try:
            conn.execute(
                "UPDATE web_jobs SET status = ?, node_id = COALESCE(?, node_id), "
                "result_status = ?, exit_code = ?, stdout = ?, stderr = ?, finished_at = ? "
                "WHERE id = ?",
                (status, node_id, result.get("status"), result.get("exit_code"),
                 clip(result.get("stdout")), clip(result.get("stderr")), _now(), web_id),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass
