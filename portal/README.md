# AICN Portal

The multi-tenant web app for AICN: accounts, organizations, and sharing servers.
A **separate** service from the gateway (FastAPI + SQLite), so it can be run and
reasoned about on its own; later phases share its database for job routing.

## Phase status
- **Phase 1 — accounts (this):** register / login / logout, secure password
  hashing (scrypt), server-side sessions. ✅
- Phase 2 — organizations (create, invite, roles).
- Phase 3 — servers (claim to your account, share into orgs) + gateway routing.
- Phase 4 — org dashboards + submit jobs from the web.

## Run it

```bash
cd portal
python -m venv venv && . venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```
Then open http://localhost:8000 — sign up, and you land on your dashboard.

## Configuration (env vars)
- `AICN_PORTAL_DB` — path to the SQLite file (default `portal.db` next to the code).
- `AICN_PORTAL_SECURE_COOKIES=1` — set in production (behind HTTPS / the tunnel)
  so the session cookie is only sent over TLS.

## Notes
- Passwords are hashed with `hashlib.scrypt` (stdlib) — never stored in plaintext.
- Sessions are server-side (a row in the `sessions` table); logging out deletes
  the row, so sessions are revocable.
- SameSite=Lax cookies give basic CSRF protection for form posts. Explicit CSRF
  tokens and email verification/reset are planned hardening (see the roadmap).

## Serving it publicly
Add a hostname to your cloudflared tunnel, e.g. `app.aicn.dev -> http://localhost:8000`,
and set `AICN_PORTAL_SECURE_COOKIES=1`. Keep it on the same box as the gateway so
later phases can share the database.
