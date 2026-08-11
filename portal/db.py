"""SQLite storage for the AICN portal (the multi-tenant org platform).

Phase 1 covers users + sessions. Later phases add orgs, memberships, servers,
server_shares, and jobs — the schema is written to grow into those.

Deliberately no ORM: stdlib sqlite3 with a thin helper layer keeps the whole
thing dependency-light and easy to read.
"""

import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = os.environ.get(
    "AICN_PORTAL_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "portal.db"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    verified      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL,
    expires_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS orgs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    slug       TEXT    UNIQUE NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT    NOT NULL DEFAULT 'member',
    created_at TEXT    NOT NULL,
    UNIQUE(org_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id);

CREATE TABLE IF NOT EXISTS invites (
    token      TEXT    PRIMARY KEY,
    org_id     INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    role       TEXT    NOT NULL DEFAULT 'member',
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT    NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS servers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id        INTEGER REFERENCES orgs(id) ON DELETE CASCADE,  -- the org this server belongs to (Option A)
    name          TEXT    NOT NULL,
    claim_token   TEXT    UNIQUE,          -- one-time token shown to the owner
    fingerprint   TEXT    UNIQUE,          -- set when the agent claims it (its keypair id)
    claimed_at    TEXT,
    last_seen     TEXT,
    created_at    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_servers_owner ON servers(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_servers_org ON servers(org_id);

CREATE TABLE IF NOT EXISTS gateways (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    token      TEXT    UNIQUE NOT NULL,     -- bearer token the gateway uses on the API
    url        TEXT,                        -- public address nodes dial (e.g. wss://gateway.org.com)
    created_at TEXT    NOT NULL,
    last_seen  TEXT
);
CREATE INDEX IF NOT EXISTS idx_gateways_org ON gateways(org_id);

CREATE TABLE IF NOT EXISTS server_shares (
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    org_id     INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL,
    PRIMARY KEY (server_id, org_id)
);

CREATE TABLE IF NOT EXISTS api_tokens (
    token      TEXT    PRIMARY KEY,        -- used by the CLI to submit jobs as this user
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS web_jobs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id         INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    gateway_job_id TEXT,                          -- set when the gateway picks it up
    interpreter    TEXT    NOT NULL DEFAULT 'python',
    script         TEXT    NOT NULL,
    pip            TEXT,                           -- comma-separated packages (subprocess nodes only)
    image          TEXT,                           -- Docker image (hardened nodes: deps baked in)
    ram_mb         INTEGER NOT NULL DEFAULT 512,
    max_runtime    INTEGER NOT NULL DEFAULT 60,
    status         TEXT    NOT NULL DEFAULT 'pending',  -- pending/queued/running/done/failed
    node_id        TEXT,
    result_status  TEXT,                           -- ok/error/timeout/oom from the run
    exit_code      INTEGER,
    stdout         TEXT,
    stderr         TEXT,
    created_at     TEXT    NOT NULL,
    finished_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_web_jobs_org ON web_jobs(org_id);
CREATE INDEX IF NOT EXISTS idx_web_jobs_status ON web_jobs(status);
"""

ROLES = ("admin", "member")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        # migrate older DBs: add servers.org_id if it predates Option A
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(servers)").fetchall()}
        if "org_id" not in cols:
            conn.execute("ALTER TABLE servers ADD COLUMN org_id INTEGER REFERENCES orgs(id)")
        jcols = {r["name"] for r in conn.execute("PRAGMA table_info(web_jobs)").fetchall()}
        if jcols and "image" not in jcols:
            conn.execute("ALTER TABLE web_jobs ADD COLUMN image TEXT")
        conn.commit()
    finally:
        conn.close()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return _now().isoformat()


# -- users -------------------------------------------------------------------
def create_user(email: str, password_hash: str):
    """Insert a user; returns the new id, or None if the email is taken."""
    conn = connect()
    try:
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, password_hash, now_iso()),
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None          # UNIQUE(email) violated
    finally:
        conn.close()


def get_user_by_email(email: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    finally:
        conn.close()


def get_user_by_id(user_id: int):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()


# -- sessions ----------------------------------------------------------------
def create_session(user_id: int, days: int = 30) -> str:
    token = secrets.token_urlsafe(32)
    expires = (_now() + timedelta(days=days)).isoformat()
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now_iso(), expires),
        )
        conn.commit()
        return token
    finally:
        conn.close()


def get_session_user(token: str):
    """Return the user row for a live session token, or None (expired/invalid).
    Prunes the row if it has expired."""
    if not token:
        return None
    conn = connect()
    try:
        row = conn.execute(
            "SELECT u.* , s.expires_at AS _expires "
            "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
            (token,),
        ).fetchone()
        if row is None:
            return None
        if row["_expires"] <= now_iso():
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return None
        return row
    finally:
        conn.close()


def delete_session(token: str) -> None:
    if not token:
        return
    conn = connect()
    try:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()


# -- orgs + memberships ------------------------------------------------------
import re as _re


def slugify(name: str) -> str:
    s = _re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s or "org"


def create_org(name: str, user_id: int):
    """Create an org with a unique slug and make the creator its admin.
    Returns the org row."""
    base = slugify(name)
    conn = connect()
    try:
        slug, n = base, 1
        while conn.execute("SELECT 1 FROM orgs WHERE slug = ?", (slug,)).fetchone():
            n += 1
            slug = f"{base}-{n}"
        cur = conn.execute(
            "INSERT INTO orgs (name, slug, created_by, created_at) VALUES (?, ?, ?, ?)",
            (name.strip(), slug, user_id, now_iso()),
        )
        org_id = cur.lastrowid
        conn.execute(
            "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'admin', ?)",
            (org_id, user_id, now_iso()),
        )
        conn.commit()
        return conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    finally:
        conn.close()


def get_org_by_slug(slug: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM orgs WHERE slug = ?", (slug,)).fetchone()
    finally:
        conn.close()


def get_org(org_id: int):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    finally:
        conn.close()


def list_user_orgs(user_id: int):
    """Orgs the user belongs to, with their role and the member count."""
    conn = connect()
    try:
        return conn.execute(
            "SELECT o.*, m.role AS role, "
            "  (SELECT COUNT(*) FROM memberships mm WHERE mm.org_id = o.id) AS members "
            "FROM orgs o JOIN memberships m ON m.org_id = o.id "
            "WHERE m.user_id = ? ORDER BY o.name COLLATE NOCASE",
            (user_id,),
        ).fetchall()
    finally:
        conn.close()


def get_membership(org_id: int, user_id: int):
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?", (org_id, user_id)
        ).fetchone()
    finally:
        conn.close()


def list_members(org_id: int):
    conn = connect()
    try:
        return conn.execute(
            "SELECT m.user_id, m.role, m.created_at, u.email "
            "FROM memberships m JOIN users u ON u.id = m.user_id "
            "WHERE m.org_id = ? ORDER BY (m.role='admin') DESC, u.email COLLATE NOCASE",
            (org_id,),
        ).fetchall()
    finally:
        conn.close()


def add_member(org_id: int, user_id: int, role: str = "member") -> bool:
    """Add a member; returns False if they're already in the org."""
    if role not in ROLES:
        role = "member"
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)",
            (org_id, user_id, role, now_iso()),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False           # UNIQUE(org_id, user_id)
    finally:
        conn.close()


def count_admins(org_id: int) -> int:
    conn = connect()
    try:
        return conn.execute(
            "SELECT COUNT(*) AS c FROM memberships WHERE org_id = ? AND role = 'admin'", (org_id,)
        ).fetchone()["c"]
    finally:
        conn.close()


def set_member_role(org_id: int, user_id: int, role: str) -> None:
    if role not in ROLES:
        return
    conn = connect()
    try:
        conn.execute(
            "UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?",
            (role, org_id, user_id),
        )
        conn.commit()
    finally:
        conn.close()


def remove_member(org_id: int, user_id: int) -> None:
    conn = connect()
    try:
        conn.execute(
            "DELETE FROM memberships WHERE org_id = ? AND user_id = ?", (org_id, user_id)
        )
        conn.commit()
    finally:
        conn.close()


# -- invites -----------------------------------------------------------------
def create_invite(org_id: int, role: str, user_id: int) -> str:
    if role not in ROLES:
        role = "member"
    token = secrets.token_urlsafe(18)
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO invites (token, org_id, role, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
            (token, org_id, role, user_id, now_iso()),
        )
        conn.commit()
        return token
    finally:
        conn.close()


def get_invite(token: str):
    conn = connect()
    try:
        return conn.execute(
            "SELECT i.*, o.name AS org_name, o.slug AS org_slug "
            "FROM invites i JOIN orgs o ON o.id = i.org_id "
            "WHERE i.token = ? AND i.revoked = 0",
            (token,),
        ).fetchone()
    finally:
        conn.close()


def list_invites(org_id: int):
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM invites WHERE org_id = ? AND revoked = 0 ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    finally:
        conn.close()


def revoke_invite(token: str, org_id: int) -> None:
    conn = connect()
    try:
        conn.execute("UPDATE invites SET revoked = 1 WHERE token = ? AND org_id = ?",
                     (token, org_id))
        conn.commit()
    finally:
        conn.close()


# -- servers -----------------------------------------------------------------
def _cli_token(n: int = 24) -> str:
    """A URL-safe token that never starts with '-' — it's passed as a command-line
    argument (--claim-token …), and argparse would read a leading dash as a flag."""
    while True:
        t = secrets.token_urlsafe(n)
        if not t.startswith("-"):
            return t


def create_server(owner_user_id: int, name: str, org_id: int):
    """Register a server to a user, belonging to one org (Option A). Returns the
    row (incl. its one-time claim_token)."""
    token = _cli_token(24)
    conn = connect()
    try:
        cur = conn.execute(
            "INSERT INTO servers (owner_user_id, org_id, name, claim_token, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (owner_user_id, org_id, name.strip(), token, now_iso()),
        )
        conn.commit()
        return conn.execute("SELECT * FROM servers WHERE id = ?", (cur.lastrowid,)).fetchone()
    finally:
        conn.close()


def get_server(server_id: int, owner_user_id: int = None):
    """Fetch a server; if owner_user_id is given, only when they own it."""
    conn = connect()
    try:
        if owner_user_id is None:
            return conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        return conn.execute("SELECT * FROM servers WHERE id = ? AND owner_user_id = ?",
                            (server_id, owner_user_id)).fetchone()
    finally:
        conn.close()


def list_user_servers(owner_user_id: int):
    conn = connect()
    try:
        return conn.execute(
            "SELECT s.*, o.name AS org_name, o.slug AS org_slug "
            "FROM servers s LEFT JOIN orgs o ON o.id = s.org_id "
            "WHERE s.owner_user_id = ? ORDER BY s.name COLLATE NOCASE",
            (owner_user_id,),
        ).fetchall()
    finally:
        conn.close()


def rename_server(server_id: int, owner_user_id: int, name: str) -> None:
    conn = connect()
    try:
        conn.execute("UPDATE servers SET name = ? WHERE id = ? AND owner_user_id = ?",
                     (name.strip(), server_id, owner_user_id))
        conn.commit()
    finally:
        conn.close()


def delete_server(server_id: int, owner_user_id: int) -> None:
    conn = connect()
    try:
        conn.execute("DELETE FROM servers WHERE id = ? AND owner_user_id = ?",
                     (server_id, owner_user_id))
        conn.commit()
    finally:
        conn.close()


def claim_server(claim_token: str, fingerprint: str):
    """Bind an agent's keypair fingerprint to a server via its one-time claim
    token. Called by the GATEWAY when an agent connects with --claim-token.
    The token is single-use (cleared on success). Returns the server row or None."""
    if not claim_token or not fingerprint:
        return None
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM servers WHERE claim_token = ?", (claim_token,)).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE servers SET fingerprint = ?, claimed_at = ?, claim_token = NULL, last_seen = ? "
            "WHERE id = ?",
            (fingerprint, now_iso(), now_iso(), row["id"]),
        )
        conn.commit()
        return conn.execute("SELECT * FROM servers WHERE id = ?", (row["id"],)).fetchone()
    except sqlite3.IntegrityError:
        return None          # fingerprint already bound to another server
    finally:
        conn.close()


def server_by_fingerprint(fingerprint: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM servers WHERE fingerprint = ?", (fingerprint,)).fetchone()
    finally:
        conn.close()


def touch_server(fingerprint: str) -> None:
    """Update last_seen for a connected node (gateway calls this)."""
    conn = connect()
    try:
        conn.execute("UPDATE servers SET last_seen = ? WHERE fingerprint = ?",
                     (now_iso(), fingerprint))
        conn.commit()
    finally:
        conn.close()


# -- server <-> org sharing --------------------------------------------------
def share_server(server_id: int, org_id: int) -> None:
    conn = connect()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO server_shares (server_id, org_id, created_at) VALUES (?, ?, ?)",
            (server_id, org_id, now_iso()),
        )
        conn.commit()
    finally:
        conn.close()


def unshare_server(server_id: int, org_id: int) -> None:
    conn = connect()
    try:
        conn.execute("DELETE FROM server_shares WHERE server_id = ? AND org_id = ?",
                     (server_id, org_id))
        conn.commit()
    finally:
        conn.close()


def server_org_ids(server_id: int):
    conn = connect()
    try:
        rows = conn.execute("SELECT org_id FROM server_shares WHERE server_id = ?",
                            (server_id,)).fetchall()
        return {r["org_id"] for r in rows}
    finally:
        conn.close()


def list_org_servers(org_id: int):
    """Servers that belong to an org (Option A), with owner email + claim/online info."""
    conn = connect()
    try:
        return conn.execute(
            "SELECT s.*, u.email AS owner_email FROM servers s JOIN users u ON u.id = s.owner_user_id "
            "WHERE s.org_id = ? ORDER BY s.name COLLATE NOCASE",
            (org_id,),
        ).fetchall()
    finally:
        conn.close()


# -- gateways (one per org; a remote gateway authenticates with its token) ----
def create_gateway(org_id: int, name: str, url: str = None) -> str:
    token = "aicngw_" + secrets.token_urlsafe(24)
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO gateways (org_id, name, token, url, created_at) VALUES (?, ?, ?, ?, ?)",
            (org_id, name.strip() or "gateway", token, (url or "").strip() or None, now_iso()),
        )
        conn.commit()
        return token
    finally:
        conn.close()


def gateway_for_org(org_id: int):
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM gateways WHERE org_id = ? ORDER BY id DESC LIMIT 1", (org_id,)
        ).fetchone()
    finally:
        conn.close()


def get_gateway_by_token(token: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM gateways WHERE token = ?", (token,)).fetchone()
    finally:
        conn.close()


def touch_gateway(gateway_id: int) -> None:
    conn = connect()
    try:
        conn.execute("UPDATE gateways SET last_seen = ? WHERE id = ?", (now_iso(), gateway_id))
        conn.commit()
    finally:
        conn.close()


def delete_gateway(gateway_id: int, org_id: int) -> None:
    conn = connect()
    try:
        conn.execute("DELETE FROM gateways WHERE id = ? AND org_id = ?", (gateway_id, org_id))
        conn.commit()
    finally:
        conn.close()


# -- federation helpers (called via the gateway API, scoped to one org) -------
def claim_server_in_org(claim_token: str, fingerprint: str, org_id: int):
    """Claim a server that belongs to org_id. Returns server id or None."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT id FROM servers WHERE claim_token = ? AND org_id = ?", (claim_token, org_id)
        ).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE servers SET fingerprint = ?, claimed_at = ?, claim_token = NULL, last_seen = ? "
            "WHERE id = ?",
            (fingerprint, now_iso(), now_iso(), row["id"]),
        )
        conn.commit()
        return row["id"]
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def server_belongs_to_org(fingerprint: str, org_id: int) -> bool:
    conn = connect()
    try:
        return conn.execute(
            "SELECT 1 FROM servers WHERE fingerprint = ? AND org_id = ?", (fingerprint, org_id)
        ).fetchone() is not None
    finally:
        conn.close()


def pending_web_jobs_for_org(org_id: int):
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT id, org_id, user_id, interpreter, script, pip, image, ram_mb, max_runtime "
            "FROM web_jobs WHERE org_id = ? AND status = 'pending' ORDER BY id ASC LIMIT 20",
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_web_job_fields(job_id: int, org_id: int, **fields):
    """Update a web job that belongs to org_id (the gateway's org). Only known columns."""
    allowed = {"status", "node_id", "result_status", "exit_code", "stdout", "stderr",
               "gateway_job_id", "finished_at"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    cols = ", ".join(f"{k} = ?" for k in sets)
    conn = connect()
    try:
        conn.execute(f"UPDATE web_jobs SET {cols} WHERE id = ? AND org_id = ?",
                     (*sets.values(), job_id, org_id))
        conn.commit()
    finally:
        conn.close()


def org_ids_for_fingerprint(fingerprint: str):
    """The set of org ids a claimed server is shared into (gateway routing)."""
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT ss.org_id FROM servers s JOIN server_shares ss ON ss.server_id = s.id "
            "WHERE s.fingerprint = ?",
            (fingerprint,),
        ).fetchall()
        return {r["org_id"] for r in rows}
    finally:
        conn.close()


# -- API tokens (CLI job submission as a user) -------------------------------
def create_api_token(user_id: int, name: str) -> str:
    token = "aicn_" + secrets.token_urlsafe(24)
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO api_tokens (token, user_id, name, created_at) VALUES (?, ?, ?, ?)",
            (token, user_id, name.strip() or "token", now_iso()),
        )
        conn.commit()
        return token
    finally:
        conn.close()


def list_api_tokens(user_id: int):
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM api_tokens WHERE user_id = ? AND revoked = 0 ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
    finally:
        conn.close()


def revoke_api_token(token: str, user_id: int) -> None:
    conn = connect()
    try:
        conn.execute("UPDATE api_tokens SET revoked = 1 WHERE token = ? AND user_id = ?",
                     (token, user_id))
        conn.commit()
    finally:
        conn.close()


# -- web jobs (submitted from the browser; the gateway runs them) -------------
def create_web_job(org_id, user_id, interpreter, script, pip, ram_mb, max_runtime, image=None):
    conn = connect()
    try:
        cur = conn.execute(
            "INSERT INTO web_jobs (org_id, user_id, interpreter, script, pip, image, ram_mb, "
            "max_runtime, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (org_id, user_id, interpreter, script, pip or None, (image or "").strip() or None,
             int(ram_mb), int(max_runtime), now_iso()),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_org_jobs(org_id, limit=25):
    conn = connect()
    try:
        return conn.execute(
            "SELECT j.*, u.email AS user_email FROM web_jobs j JOIN users u ON u.id = j.user_id "
            "WHERE j.org_id = ? ORDER BY j.id DESC LIMIT ?",
            (org_id, limit),
        ).fetchall()
    finally:
        conn.close()


def get_web_job(job_id):
    conn = connect()
    try:
        return conn.execute(
            "SELECT j.*, u.email AS user_email, o.slug AS org_slug, o.name AS org_name "
            "FROM web_jobs j JOIN users u ON u.id = j.user_id JOIN orgs o ON o.id = j.org_id "
            "WHERE j.id = ?", (job_id,),
        ).fetchone()
    finally:
        conn.close()
