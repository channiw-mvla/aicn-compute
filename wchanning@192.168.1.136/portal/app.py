"""AICN portal — Phase 1: accounts (register / login / logout).

A separate FastAPI app from the gateway. Serves server-rendered pages and holds
server-side sessions in SQLite. Later phases add organizations, servers, and
job routing on top of the same database.

Run it:
    pip install -r requirements.txt
    uvicorn app:app --host 0.0.0.0 --port 8000
"""

import os

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import auth
import db

HERE = os.path.dirname(os.path.abspath(__file__))
app = FastAPI(title="AICN Portal")
templates = Jinja2Templates(directory=os.path.join(HERE, "templates"))

COOKIE = "aicn_session"
SESSION_DAYS = 30
# Set AICN_PORTAL_SECURE_COOKIES=1 in production (behind HTTPS/the tunnel) so the
# session cookie is only sent over TLS. Off by default for local http testing.
SECURE_COOKIES = os.environ.get("AICN_PORTAL_SECURE_COOKIES", "").lower() in ("1", "true", "yes")

db.init_db()


def render(request: Request, name: str, status_code: int = 200, **ctx):
    """Render a template with the current Starlette signature (request first)."""
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def current_user(request: Request):
    """The logged-in user row, or None."""
    return db.get_session_user(request.cookies.get(COOKIE))


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
    return render(request, "register.html", error=None, email="")


@app.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...),
             confirm: str = Form(...)):
    email = email.strip().lower()

    def fail(msg: str):
        return render(request, "register.html", status_code=400, error=msg, email=email)

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
    resp = RedirectResponse("/dashboard", status_code=303)
    _set_session_cookie(resp, token)
    return resp


# -- login -------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "login.html", error=None, email="")


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    user = db.get_user_by_email(email)
    # One generic error for both cases — don't reveal whether the email exists.
    if user is None or not auth.verify_password(password, user["password_hash"]):
        return render(request, "login.html", status_code=401,
                      error="Incorrect email or password.", email=email)

    token = db.create_session(user["id"], days=SESSION_DAYS)
    resp = RedirectResponse("/dashboard", status_code=303)
    _set_session_cookie(resp, token)
    return resp


# -- logout ------------------------------------------------------------------
@app.post("/logout")
def logout(request: Request):
    db.delete_session(request.cookies.get(COOKIE))
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie(COOKIE, path="/")
    return resp


# -- dashboard (auth required; placeholder until Phase 2 orgs) ----------------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return render(request, "dashboard.html", user=user)
