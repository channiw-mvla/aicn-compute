# AICN Portal

The multi-tenant web app for AICN: accounts, organizations, and sharing servers.
A **separate** service from the gateway (FastAPI + SQLite), so it can be run and
reasoned about on its own; later phases share its database for job routing.

## Phase status
- **Phase 1 — accounts:** register / login / logout, scrypt hashing, sessions. ✅
- **Phase 2 — organizations:** create, invite links, roles (admin/member), member
  management, last-admin protection. ✅
- **Phase 3 — servers + gateway routing:** claim a server to your account (one-time
  token), share into orgs, API tokens; the gateway reads this DB to route an org
  member's jobs only to servers shared into that org. ✅
- **Phase 4 — org dashboards + submit from the web:** per-org page shows online
  servers, a "Run a job" form, and recent jobs with live status/output. Jobs flow
  through a shared-DB queue: the browser writes a pending job, the gateway picks it
  up, runs it org-scoped, and writes the result back — no extra network coupling. ✅

## Connecting the gateway (Phase 3)
The gateway reads this app's SQLite DB to resolve node ownership + org sharing and
to authenticate job submitters. Run the gateway on the **same box** with
`AICN_PORTAL_DB` pointing at `portal.db`:

```bash
AICN_PORTAL_DB=/path/to/portal/portal.db  python gateway.py --host 0.0.0.0 \
    --authorized-keys ~/aicn/authorized_keys.json --auto-approve-nodes --trusted-proxy
```
Then: add a server in the portal → run the shown `aicn-agent ... --claim-token` on
the machine → share it into an org → members submit with
`aicn run job.py --org <slug> --api-token <token>`.
When `AICN_PORTAL_DB` is unset, the gateway ignores all of this and runs as a
single flat pool (unchanged behavior).

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
