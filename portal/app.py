"""AICN portal — Phase 1: accounts (register / login / logout).

A separate FastAPI app from the gateway. Serves server-rendered pages and holds
server-side sessions in SQLite. Later phases add organizations, servers, and
job routing on top of the same database.

Run it:
    pip install -r requirements.txt
    uvicorn app:app --host 0.0.0.0 --port 8000
"""

import os
from datetime import datetime, timezone

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import auth
import db

HERE = os.path.dirname(os.path.abspath(__file__))
app = FastAPI(title="AICN Portal")
templates = Jinja2Templates(directory=os.path.join(HERE, "templates"))

COOKIE = "aicn_session"
SESSION_DAYS = 30
# The gateway address shown in the "add a server" command. Set to your real one.
GATEWAY_URL = os.environ.get("AICN_GATEWAY_URL", "wss://gateway.aicn.dev")
# Set AICN_PORTAL_SECURE_COOKIES=1 in production (behind HTTPS/the tunnel) so the
# session cookie is only sent over TLS. Off by default for local http testing.
SECURE_COOKIES = os.environ.get("AICN_PORTAL_SECURE_COOKIES", "").lower() in ("1", "true", "yes")

db.init_db()


def render(request: Request, template: str, status_code: int = 200, **ctx):
    """Render a template with the current Starlette signature (request first).
    The param is `template` (not `name`) so a context var named `name` can't clash."""
    return templates.TemplateResponse(request, template, ctx, status_code=status_code)


def current_user(request: Request):
    """The logged-in user row, or None."""
    return db.get_session_user(request.cookies.get(COOKIE))


def safe_next(nxt: str) -> str:
    """Only allow same-site relative redirects (avoid open-redirects)."""
    if nxt and nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return "/dashboard"


def _set_session_cookie(resp: RedirectResponse, token: str) -> None:
    resp.set_cookie(COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True,
                    samesite="lax", secure=SECURE_COOKIES, path="/")


# -- landing -----------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "home.html")


# -- register ----------------------------------------------------------------
@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard", status_code=303)
    nxt = request.query_params.get("next", "")
    return render(request, "register.html", error=None, email="", next=nxt)


@app.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...),
             confirm: str = Form(...), next: str = Form("")):
    email = email.strip().lower()

    def fail(msg: str):
        return render(request, "register.html", status_code=400, error=msg, email=email, next=next)

    if not auth.valid_email(email):
        return fail("Please enter a valid email address.")
    pw_problem = auth.password_problem(password)
    if pw_problem:
        return fail(pw_problem)
    if password != confirm:
        return fail("Passwords do not match.")

    user_id = db.create_user(email, auth.hash_password(password))
    if user_id is None:
        return fail("That email is already registered. Try logging in.")

    token = db.create_session(user_id, days=SESSION_DAYS)
    resp = RedirectResponse(safe_next(next), status_code=303)
    _set_session_cookie(resp, token)
    return resp


# -- login -------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard", status_code=303)
    nxt = request.query_params.get("next", "")
    return render(request, "login.html", error=None, email="", next=nxt)


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...),
          next: str = Form("")):
    email = email.strip().lower()
    user = db.get_user_by_email(email)
    # One generic error for both cases — don't reveal whether the email exists.
    if user is None or not auth.verify_password(password, user["password_hash"]):
        return render(request, "login.html", status_code=401,
                      error="Incorrect email or password.", email=email, next=next)

    token = db.create_session(user["id"], days=SESSION_DAYS)
    resp = RedirectResponse(safe_next(next), status_code=303)
    _set_session_cookie(resp, token)
    return resp


# -- logout ------------------------------------------------------------------
@app.post("/logout")
def logout(request: Request):
    db.delete_session(request.cookies.get(COOKIE))
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie(COOKIE, path="/")
    return resp


# -- dashboard ---------------------------------------------------------------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return render(request, "dashboard.html", user=user, orgs=db.list_user_orgs(user["id"]))


# -- organizations -----------------------------------------------------------
def _member_ctx(request: Request, slug: str):
    """(user, org, membership). Any may be None."""
    user = current_user(request)
    if user is None:
        return None, None, None
    org = db.get_org_by_slug(slug)
    if org is None:
        return user, None, None
    return user, org, db.get_membership(org["id"], user["id"])


def _deny(request: Request, code: int = 404):
    return render(request, "message.html", status_code=code,
                  heading="Not found" if code == 404 else "Not allowed",
                  text="That page doesn't exist or you don't have access to it.")


@app.get("/orgs/new", response_class=HTMLResponse)
def org_new_form(request: Request):
    if current_user(request) is None:
        return RedirectResponse("/login?next=/orgs/new", status_code=303)
    return render(request, "org_new.html", error=None, name="")


@app.post("/orgs")
def org_create(request: Request, name: str = Form(...)):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    name = name.strip()
    if not name or len(name) > 80:
        return render(request, "org_new.html", status_code=400,
                      error="Enter an organization name (1–80 characters).", name=name)
    org = db.create_org(name, user["id"])
    return RedirectResponse(f"/orgs/{org['slug']}", status_code=303)


@app.get("/orgs/{slug}", response_class=HTMLResponse)
def org_detail(request: Request, slug: str):
    user, org, m = _member_ctx(request, slug)
    if user is None:
        return RedirectResponse(f"/login?next=/orgs/{slug}", status_code=303)
    if org is None or m is None:
        return _deny(request, 404)          # don't reveal orgs you're not in
    is_admin = m["role"] == "admin"
    servers = db.list_org_servers(org["id"])
    online = {s["id"] for s in servers if _is_online(s["last_seen"])}
    gw = db.gateway_for_org(org["id"])
    return render(request, "org_detail.html", user=user, org=org, role=m["role"],
                  is_admin=is_admin, members=db.list_members(org["id"]),
                  invites=db.list_invites(org["id"]) if is_admin else [],
                  invite_base=str(request.base_url).rstrip("/") + "/invite/",
                  admin_count=db.count_admins(org["id"]),
                  servers=servers, online=online, any_online=bool(online),
                  jobs=db.list_org_jobs(org["id"]),
                  gateway=gw, gateway_online=_is_online(gw["last_seen"]) if gw else False,
                  gw_token=request.query_params.get("gw_token"),
                  portal_base=str(request.base_url).rstrip("/"))


def _is_online(last_seen, secs: int = 90) -> bool:
    if not last_seen:
        return False
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(last_seen)).total_seconds() < secs
    except Exception:
        return False


@app.post("/orgs/{slug}/submit")
def org_submit(request: Request, slug: str, script: str = Form(...),
               interpreter: str = Form("python"), pip: str = Form(""),
               image: str = Form(""), ram_mb: int = Form(512), max_runtime: int = Form(60)):
    user, org, m = _member_ctx(request, slug)
    if not (org and m):                     # must be a member of the org
        return _deny(request, 403)
    if not script.strip():
        return RedirectResponse(f"/orgs/{slug}", status_code=303)
    jid = db.create_web_job(org["id"], user["id"], interpreter, script.strip(),
                            pip.strip(), ram_mb, max_runtime, image)
    return RedirectResponse(f"/jobs/{jid}", status_code=303)


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail(request: Request, job_id: int):
    user = current_user(request)
    if user is None:
        return RedirectResponse(f"/login?next=/jobs/{job_id}", status_code=303)
    job = db.get_web_job(job_id)
    if job is None or db.get_membership(job["org_id"], user["id"]) is None:
        return _deny(request, 404)
    running = job["status"] in ("pending", "queued", "running")
    return render(request, "job_detail.html", user=user, job=job, running=running)


@app.post("/jobs/{job_id}/rerun")
def job_rerun(request: Request, job_id: int, script: str = Form(...), pip: str = Form(""),
              image: str = Form(""), interpreter: str = Form("python"),
              ram_mb: int = Form(512), max_runtime: int = Form(60)):
    """Submit a new job based on this one — dependencies and script editable."""
    user = current_user(request)
    if user is None:
        return RedirectResponse(f"/login?next=/jobs/{job_id}", status_code=303)
    job = db.get_web_job(job_id)
    if job is None or db.get_membership(job["org_id"], user["id"]) is None:
        return _deny(request, 404)
    if not script.strip():
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)
    new_id = db.create_web_job(job["org_id"], user["id"], interpreter, script.strip(),
                               pip.strip(), ram_mb, max_runtime, image)
    return RedirectResponse(f"/jobs/{new_id}", status_code=303)


@app.get("/jobs/{job_id}/output")
def job_output(request: Request, job_id: int):
    user = current_user(request)
    if user is None:
        return RedirectResponse(f"/login?next=/jobs/{job_id}", status_code=303)
    job = db.get_web_job(job_id)
    if job is None or db.get_membership(job["org_id"], user["id"]) is None:
        return _deny(request, 404)
    parts = []
    if job["stdout"]:
        parts.append(job["stdout"])
    if job["stderr"]:
        parts.append(("\n" if parts else "") + "--- stderr ---\n" + job["stderr"])
    body = "".join(parts) or "(no output)"
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": f'attachment; filename="job-{job_id}-output.txt"'},
    )


@app.post("/orgs/{slug}/invite")
def org_invite(request: Request, slug: str, role: str = Form("member")):
    user, org, m = _member_ctx(request, slug)
    if not (org and m and m["role"] == "admin"):
        return _deny(request, 403)
    db.create_invite(org["id"], role if role in db.ROLES else "member", user["id"])
    return RedirectResponse(f"/orgs/{slug}", status_code=303)


@app.post("/orgs/{slug}/invite/{token}/revoke")
def org_invite_revoke(request: Request, slug: str, token: str):
    user, org, m = _member_ctx(request, slug)
    if not (org and m and m["role"] == "admin"):
        return _deny(request, 403)
    db.revoke_invite(token, org["id"])
    return RedirectResponse(f"/orgs/{slug}", status_code=303)


@app.get("/invite/{token}")
def invite_accept(request: Request, token: str):
    user = current_user(request)
    if user is None:
        return RedirectResponse(f"/login?next=/invite/{token}", status_code=303)
    inv = db.get_invite(token)
    if inv is None:
        return render(request, "message.html", status_code=404, heading="Invite not valid",
                      text="This invite link is invalid or has been revoked.")
    if db.get_membership(inv["org_id"], user["id"]) is None:
        db.add_member(inv["org_id"], user["id"], inv["role"])
    return RedirectResponse(f"/orgs/{inv['org_slug']}", status_code=303)


@app.post("/orgs/{slug}/members/{user_id}/role")
def member_set_role(request: Request, slug: str, user_id: int, role: str = Form(...)):
    user, org, m = _member_ctx(request, slug)
    if not (org and m and m["role"] == "admin"):
        return _deny(request, 403)
    target = db.get_membership(org["id"], user_id)
    if target is None or role not in db.ROLES:
        return RedirectResponse(f"/orgs/{slug}", status_code=303)
    # never demote the last admin (would leave the org with no admin)
    if target["role"] == "admin" and role != "admin" and db.count_admins(org["id"]) <= 1:
        return RedirectResponse(f"/orgs/{slug}", status_code=303)
    db.set_member_role(org["id"], user_id, role)
    return RedirectResponse(f"/orgs/{slug}", status_code=303)


@app.post("/orgs/{slug}/members/{user_id}/remove")
def member_remove(request: Request, slug: str, user_id: int):
    user, org, m = _member_ctx(request, slug)
    if not (org and m and m["role"] == "admin"):
        return _deny(request, 403)
    target = db.get_membership(org["id"], user_id)
    if target is None:
        return RedirectResponse(f"/orgs/{slug}", status_code=303)
    if target["role"] == "admin" and db.count_admins(org["id"]) <= 1:
        return RedirectResponse(f"/orgs/{slug}", status_code=303)   # can't remove last admin
    db.remove_member(org["id"], user_id)
    return RedirectResponse(f"/orgs/{slug}", status_code=303)


@app.post("/orgs/{slug}/leave")
def org_leave(request: Request, slug: str):
    user, org, m = _member_ctx(request, slug)
    if not (org and m):
        return RedirectResponse("/dashboard", status_code=303)
    if m["role"] == "admin" and db.count_admins(org["id"]) <= 1:
        return RedirectResponse(f"/orgs/{slug}", status_code=303)   # last admin must stay/hand off
    db.remove_member(org["id"], user["id"])
    return RedirectResponse("/dashboard", status_code=303)


# -- servers -----------------------------------------------------------------
@app.get("/servers", response_class=HTMLResponse)
def servers_list(request: Request):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login?next=/servers", status_code=303)
    return render(request, "servers.html", user=user, servers=db.list_user_servers(user["id"]),
                  orgs=db.list_user_orgs(user["id"]))


@app.post("/servers")
def server_create(request: Request, name: str = Form(...), org_id: int = Form(...)):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    name = name.strip()
    if not name or len(name) > 80 or db.get_membership(org_id, user["id"]) is None:
        return render(request, "servers.html", status_code=400, user=user,
                      servers=db.list_user_servers(user["id"]), orgs=db.list_user_orgs(user["id"]),
                      error="Enter a server name and pick an org you belong to.")
    srv = db.create_server(user["id"], name, org_id)
    return RedirectResponse(f"/servers/{srv['id']}", status_code=303)


@app.get("/servers/{server_id}", response_class=HTMLResponse)
def server_detail(request: Request, server_id: int):
    user = current_user(request)
    if user is None:
        return RedirectResponse(f"/login?next=/servers/{server_id}", status_code=303)
    srv = db.get_server(server_id, owner_user_id=user["id"])
    if srv is None:
        return _deny(request, 404)
    org = db.get_org(srv["org_id"]) if srv["org_id"] else None
    gw = db.gateway_for_org(srv["org_id"]) if srv["org_id"] else None
    gw_url = (gw["url"] if gw and gw["url"] else GATEWAY_URL)
    claim_cmd = (f"aicn-agent --gateway {gw_url} --secure "
                 f"--claim-token {srv['claim_token']}") if srv["claim_token"] else None
    return render(request, "server_detail.html", user=user, srv=srv, org=org,
                  gateway=gw, claim_cmd=claim_cmd)


def _owned_server(request: Request, server_id: int):
    user = current_user(request)
    if user is None:
        return None, None
    return user, db.get_server(server_id, owner_user_id=user["id"])


@app.post("/servers/{server_id}/rename")
def server_rename(request: Request, server_id: int, name: str = Form(...)):
    user, srv = _owned_server(request, server_id)
    if srv is None:
        return _deny(request, 404)
    if name.strip():
        db.rename_server(server_id, user["id"], name)
    return RedirectResponse(f"/servers/{server_id}", status_code=303)


@app.post("/servers/{server_id}/remove")
def server_remove(request: Request, server_id: int):
    user, srv = _owned_server(request, server_id)
    if srv is None:
        return _deny(request, 404)
    db.delete_server(server_id, user["id"])
    return RedirectResponse("/servers", status_code=303)


@app.post("/servers/{server_id}/share")
def server_share(request: Request, server_id: int, org_id: int = Form(...)):
    user, srv = _owned_server(request, server_id)
    if srv is None:
        return _deny(request, 404)
    # you can only share into an org you belong to
    if db.get_membership(org_id, user["id"]) is not None:
        db.share_server(server_id, org_id)
    return RedirectResponse(f"/servers/{server_id}", status_code=303)


@app.post("/servers/{server_id}/unshare")
def server_unshare(request: Request, server_id: int, org_id: int = Form(...)):
    user, srv = _owned_server(request, server_id)
    if srv is None:
        return _deny(request, 404)
    db.unshare_server(server_id, org_id)
    return RedirectResponse(f"/servers/{server_id}", status_code=303)


# -- gateway registration (org admin) ---------------------------------------
@app.post("/orgs/{slug}/gateway")
def gateway_create(request: Request, slug: str, name: str = Form("gateway"), url: str = Form("")):
    user, org, m = _member_ctx(request, slug)
    if not (org and m and m["role"] == "admin"):
        return _deny(request, 403)
    token = db.create_gateway(org["id"], name, url)
    # show the token once via a flash param on the org page
    return RedirectResponse(f"/orgs/{slug}?gw_token={token}", status_code=303)


@app.post("/orgs/{slug}/gateway/{gateway_id}/delete")
def gateway_delete(request: Request, slug: str, gateway_id: int):
    user, org, m = _member_ctx(request, slug)
    if not (org and m and m["role"] == "admin"):
        return _deny(request, 403)
    db.delete_gateway(gateway_id, org["id"])
    return RedirectResponse(f"/orgs/{slug}", status_code=303)


@app.post("/orgs/{slug}/servers")
def org_add_server(request: Request, slug: str, name: str = Form(...)):
    """Add a server that belongs to this org (Option A)."""
    user, org, m = _member_ctx(request, slug)
    if not (org and m):
        return _deny(request, 403)
    if name.strip():
        srv = db.create_server(user["id"], name, org["id"])
        return RedirectResponse(f"/servers/{srv['id']}", status_code=303)
    return RedirectResponse(f"/orgs/{slug}", status_code=303)


# -- the gateway API (called by remote per-org gateways) ---------------------
# Every call authenticates with the gateway's bearer token, which resolves to
# exactly one org. A gateway can only ever act for its own org.
def _api_gateway(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    return db.get_gateway_by_token(auth[7:].strip())


def _unauth():
    return JSONResponse({"error": "unauthorized"}, status_code=401)


@app.post("/api/gw/heartbeat")
async def gw_heartbeat(request: Request):
    gw = _api_gateway(request)
    if gw is None:
        return _unauth()
    db.touch_gateway(gw["id"])
    org = db.get_org(gw["org_id"])
    return {"org_id": gw["org_id"], "org_slug": org["slug"] if org else None,
            "org_name": org["name"] if org else None}


@app.post("/api/gw/claim")
async def gw_claim(request: Request):
    gw = _api_gateway(request)
    if gw is None:
        return _unauth()
    body = await request.json()
    sid = db.claim_server_in_org(body.get("claim_token"), body.get("fingerprint"), gw["org_id"])
    return {"ok": sid is not None, "server_id": sid}


@app.post("/api/gw/touch")
async def gw_touch(request: Request):
    gw = _api_gateway(request)
    if gw is None:
        return _unauth()
    body = await request.json()
    db.touch_server(body.get("fingerprint"))
    return {"ok": True}


@app.get("/api/gw/node")
async def gw_node(request: Request, fingerprint: str = ""):
    gw = _api_gateway(request)
    if gw is None:
        return _unauth()
    return {"belongs": db.server_belongs_to_org(fingerprint, gw["org_id"])}


@app.get("/api/gw/jobs/pending")
async def gw_jobs_pending(request: Request):
    gw = _api_gateway(request)
    if gw is None:
        return _unauth()
    return {"jobs": db.pending_web_jobs_for_org(gw["org_id"])}


@app.post("/api/gw/jobs/{job_id}")
async def gw_job_update(request: Request, job_id: int):
    gw = _api_gateway(request)
    if gw is None:
        return _unauth()
    body = await request.json()
    db.update_web_job_fields(job_id, gw["org_id"], **body)
    return {"ok": True}


@app.get("/api/gw/authz")
async def gw_authz(request: Request, api_token: str = ""):
    gw = _api_gateway(request)
    if gw is None:
        return _unauth()
    u = PL_user(api_token)
    if u is None:
        return {"ok": False}
    member = db.get_membership(gw["org_id"], u[0]) is not None
    return {"ok": True, "user_id": u[0], "member": member}


def PL_user(api_token):
    """Resolve an API token to (user_id, email) — reused by gw_authz."""
    if not api_token:
        return None
    conn = db.connect()
    try:
        r = conn.execute(
            "SELECT u.id AS id, u.email AS email FROM api_tokens t JOIN users u ON u.id = t.user_id "
            "WHERE t.token = ? AND t.revoked = 0", (api_token,),
        ).fetchone()
        return (r["id"], r["email"]) if r else None
    finally:
        conn.close()


# -- API tokens (for submitting jobs from the CLI as this user) --------------
@app.get("/tokens", response_class=HTMLResponse)
def tokens_page(request: Request):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login?next=/tokens", status_code=303)
    return render(request, "tokens.html", user=user,
                  tokens=db.list_api_tokens(user["id"]), new_token=None)


@app.post("/tokens", response_class=HTMLResponse)
def token_create(request: Request, name: str = Form("CLI")):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    tok = db.create_api_token(user["id"], name)
    # show the raw token once (it isn't retrievable again)
    return render(request, "tokens.html", user=user,
                  tokens=db.list_api_tokens(user["id"]), new_token=tok)


@app.post("/tokens/{token}/revoke")
def token_revoke(request: Request, token: str):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    db.revoke_api_token(token, user["id"])
    return RedirectResponse("/tokens", status_code=303)
