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
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
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
