#!/usr/bin/env python3
"""
Dashboard server for Resource Monitor.
Serves the PWA behind username/password authentication.

Session model:
  - On successful login a signed token is set as an HttpOnly, Secure,
    SameSite=Strict cookie named "dm_session".
  - The token encodes {username, issued_at} and is HMAC-SHA256 signed
    with SECRET_KEY — no database required.
  - Sessions have NO fixed expiry time: they stay valid as long as the
    app is open. The cookie is a session cookie (no Max-Age / Expires),
    so the browser discards it when the tab/app is closed.
  - On every authenticated request the token is re-issued (sliding
    window) so the session never expires mid-use.
  - Unauthenticated requests to any protected path are redirected to
    /login with a `next` query parameter so the user lands back where
    they came from after signing in.

Environment variables (set in docker-compose.yml via .env):
  DASHBOARD_USERNAME   login username          (required)
  DASHBOARD_PASSWORD   login password          (required)
  SECRET_KEY           HMAC signing secret     (required — generate a
                       random 32+ char string; change it to invalidate
                       all existing sessions)
  DASHBOARD_PORT       HTTP port               (default 8080)
  LOG_DIR              path to snapshot files  (default /var/log/docker-monitor)
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

try:
    import docker as docker_sdk
    _docker_client = docker_sdk.from_env()
except Exception:
    _docker_client = None

# ── Config ────────────────────────────────────────────────────────────────────
PORT     = int(os.getenv("DASHBOARD_PORT", "8080"))
LOG_DIR  = Path(os.getenv("LOG_DIR", "/var/log/docker-monitor"))
APP_DIR  = Path("/app")

USERNAME = os.getenv("DASHBOARD_USERNAME", "")
PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
SECRET   = os.getenv("SECRET_KEY",         "")

COOKIE_NAME = "dm_session"

log = logging.getLogger("dashboard")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# Warn loudly on startup if credentials aren't set
if not USERNAME or not PASSWORD:
    log.warning("DASHBOARD_USERNAME or DASHBOARD_PASSWORD not set — dashboard is UNPROTECTED")
if not SECRET:
    log.warning("SECRET_KEY not set — generating a random one (sessions will reset on restart)")
    SECRET = secrets.token_hex(32)

# Pre-hash the password so the plaintext never sits in memory after startup
PASSWORD_HASH = hashlib.sha256(PASSWORD.encode()).hexdigest() if PASSWORD else ""

# ── MIME types ────────────────────────────────────────────────────────────────
MIME = {
    ".html": "text/html; charset=utf-8",
    ".json": "application/json",
    ".js":   "application/javascript",
    ".png":  "image/png",
    ".ico":  "image/x-icon",
    ".svg":  "image/svg+xml",
}

# ── Route maps ────────────────────────────────────────────────────────────────
DATA_FILES = {
    "/data/latest.json": "latest.json",
    "/data/alerts.json": "alerts.json",
}
STATIC = {
    "/manifest.json":        "manifest.json",
    "/sw.js":                "sw.js",
    "/icons/icon-192.png":   "icons/icon-192.png",
    "/icons/icon-512.png":   "icons/icon-512.png",
    "/icons/screenshot.png": "icons/screenshot.png",
}
# Paths that don't require authentication
PUBLIC_PATHS = {"/login", "/login/", *STATIC.keys()}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SESSION TOKEN  (HMAC-signed, no external dependencies)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _sign(payload: str) -> str:
    """Return HMAC-SHA256 hex signature of payload."""
    return hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


def make_token(username: str) -> str:
    """Encode {username}:{issued_at}:{signature} into a URL-safe token."""
    issued = int(time.time())
    payload = f"{username}:{issued}"
    sig = _sign(payload)
    raw = f"{payload}:{sig}"
    return urllib.parse.quote(raw, safe="")


def verify_token(token: str) -> str | None:
    """
    Verify and decode a session token.
    Returns the username on success, None on any failure.
    The token has no hard expiry — it lives as long as the browser session
    cookie exists (i.e. while the tab/app is open).
    """
    try:
        raw = urllib.parse.unquote(token)
        parts = raw.rsplit(":", 1)          # split off signature
        if len(parts) != 2:
            return None
        payload, sig = parts
        expected = _sign(payload)
        if not hmac.compare_digest(sig, expected):
            return None
        username, _ = payload.split(":", 1)  # ignore issued_at
        return username
    except Exception:
        return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# COOKIE HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_cookies(raw: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def session_cookie(token: str) -> str:
    """
    Build a Set-Cookie header value.
    No Max-Age / Expires → session cookie, cleared when browser closes.
    HttpOnly  → not readable by JavaScript.
    Secure    → only sent over HTTPS (nginx-proxy handles TLS).
    SameSite=Strict → CSRF protection.
    """
    return (
        f"{COOKIE_NAME}={token}; "
        "Path=/; "
        "HttpOnly; "
        "Secure; "
        "SameSite=Strict"
    )


def clear_cookie() -> str:
    return (
        f"{COOKIE_NAME}=; "
        "Path=/; "
        "HttpOnly; "
        "Secure; "
        "SameSite=Strict; "
        "Max-Age=0"
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LOGIN PAGE HTML
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def login_page(error: str = "", next_url: str = "/") -> bytes:
    error_block = (
        f'<div class="error">{error}</div>' if error else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#0b0d10">
<title>Sign in — Docker Resource Monitor</title>
<style>
  :root {{
    --bg:#0b0d10; --surface:#13161b; --border:rgba(255,255,255,0.08);
    --text:#e8eaf0; --text-muted:#6b7280;
    --green:#22d3a5; --green-dim:rgba(34,211,165,0.12);
    --red:#f87171; --red-dim:rgba(248,113,113,0.10);
    --input-bg:#1a1e26; --input-border:rgba(255,255,255,0.10);
  }}
  @media(prefers-color-scheme:light) {{
    :root {{
      --bg:#f0f2f5; --surface:#ffffff; --border:rgba(0,0,0,0.08);
      --text:#111827; --text-muted:#6b7280;
      --green:#059669; --green-dim:rgba(5,150,105,0.08);
      --red:#dc2626; --red-dim:rgba(220,38,38,0.08);
      --input-bg:#f5f7fa; --input-border:rgba(0,0,0,0.12);
    }}
  }}
  *, *::before, *::after {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{
    background:var(--bg); color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    min-height:100vh; display:flex; align-items:center; justify-content:center;
    padding:24px;
  }}
  .card {{
    background:var(--surface); border:1px solid var(--border);
    border-radius:16px; padding:36px 32px; width:100%; max-width:380px;
  }}
  .logo {{
    width:44px; height:44px; background:var(--green-dim);
    border:1px solid rgba(34,211,165,.25); border-radius:12px;
    display:flex; align-items:center; justify-content:center; margin-bottom:20px;
  }}
  h1 {{ font-size:20px; font-weight:700; letter-spacing:-.4px; margin-bottom:4px; }}
  .sub {{ font-size:13px; color:var(--text-muted); margin-bottom:28px; }}
  label {{ display:block; font-size:12px; color:var(--text-muted);
           text-transform:uppercase; letter-spacing:.7px; margin-bottom:6px; }}
  .field {{ margin-bottom:16px; }}
  input[type=text], input[type=password] {{
    width:100%; padding:10px 14px; border-radius:8px;
    border:1px solid var(--input-border); background:var(--input-bg);
    color:var(--text); font-size:14px; outline:none;
    transition:border-color .15s;
  }}
  input:focus {{ border-color:var(--green); }}
  .btn {{
    width:100%; padding:11px; border-radius:8px; border:none;
    background:var(--green); color:#fff; font-size:14px; font-weight:600;
    cursor:pointer; margin-top:8px; transition:opacity .15s;
  }}
  .btn:hover {{ opacity:.88; }}
  .error {{
    background:var(--red-dim); border:1px solid rgba(248,113,113,.2);
    border-radius:8px; padding:10px 14px; font-size:13px;
    color:var(--red); margin-bottom:18px;
  }}
  .footer {{ text-align:center; margin-top:24px; font-size:11px; color:var(--text-muted); }}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
         stroke="#22d3a5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1"/>
      <rect x="14" y="3" width="7" height="7" rx="1"/>
      <rect x="3" y="14" width="7" height="7" rx="1"/>
      <rect x="14" y="14" width="7" height="7" rx="1"/>
    </svg>
  </div>
  <h1>Resource Monitor</h1>
  <p class="sub">Sign in to access your dashboard</p>
  {error_block}
  <form method="POST" action="/login" autocomplete="on">
    <input type="hidden" name="next" value="{next_url}">
    <div class="field">
      <label for="username">Username</label>
      <input type="text" id="username" name="username"
             autocomplete="username" autofocus required>
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input type="password" id="password" name="password"
             autocomplete="current-password" required>
    </div>
    <button class="btn" type="submit">Sign in</button>
  </form>
  <p class="footer">Docker Resource Monitor</p>
</div>
</body>
</html>""".encode()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# REQUEST HANDLER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # silence default access log; we log auth events manually

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _cookies(self) -> dict[str, str]:
        return parse_cookies(self.headers.get("Cookie", ""))

    def _authenticated(self) -> str | None:
        """Return username if the request carries a valid session, else None."""
        if not USERNAME:          # auth not configured — allow all
            return "anonymous"
        token = self._cookies().get(COOKIE_NAME, "")
        return verify_token(token) if token else None

    def _redirect(self, location: str, extra_headers: list[tuple] | None = None):
        self.send_response(302)
        self.send_header("Location", location)
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send(self, data: bytes, ct: str, status: int = 200,
              cache: bool = True, extra_headers: list[tuple] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control",
                         "public, max-age=3600" if cache else "no-cache, no-store")
        # Prevent the dashboard from being framed
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, p: Path, extra_headers: list[tuple] | None = None):
        if not p.exists():
            self.send_response(404); self.end_headers(); return
        mime = MIME.get(p.suffix, "application/octet-stream")
        no_cache = p.name in ("sw.js",)
        self._send(p.read_bytes(), mime, cache=not no_cache,
                   extra_headers=extra_headers)

    def _json_response(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self._send(body, "application/json", status=status, cache=False)

    def _require_auth(self) -> str | None:
        """
        Check auth. If valid, re-issue a fresh token (sliding session) and
        return the username. If invalid, redirect to /login and return None.
        """
        path = self.path.split("?")[0]
        user = self._authenticated()
        if user:
            return user
        # Not authenticated → redirect to login
        next_url = urllib.parse.quote(self.path, safe="")
        self._redirect(f"/login?next={next_url}")
        return None

    # ── GET ───────────────────────────────────────────────────────────────────

    def do_GET(self):
        path = self.path.split("?")[0]
        qs   = urllib.parse.parse_qs(self.path.split("?")[1]) if "?" in self.path else {}

        # Login page
        if path in ("/login", "/login/"):
            next_url = qs.get("next", ["/"])[0]
            # Already logged in → skip to dashboard
            if self._authenticated():
                self._redirect(next_url or "/")
                return
            self._send(login_page(next_url=next_url),
                       "text/html; charset=utf-8", cache=False)
            return

        # Logout
        if path == "/logout":
            log.info("Logout")
            self._redirect("/login", extra_headers=[("Set-Cookie", clear_cookie())])
            return

        # PWA static assets (manifest, sw, icons) — public, no auth needed
        # so the PWA installs correctly even before the first login
        if path in STATIC:
            self._send_file(APP_DIR / STATIC[path])
            return

        # Everything else requires auth ──────────────────────────────────────
        user = self._require_auth()
        if user is None:
            return

        # Re-issue token to keep session alive (sliding window)
        fresh_token = make_token(user)
        cookie_header = [("Set-Cookie", session_cookie(fresh_token))]

        # Data endpoints
        if path in DATA_FILES:
            target = LOG_DIR / DATA_FILES[path]
            if target.exists():
                self._send(target.read_bytes(), "application/json",
                           cache=False, extra_headers=cookie_header)
            else:
                self._send(json.dumps({"error": "not yet available"}).encode(),
                           "application/json", status=404,
                           cache=False, extra_headers=cookie_header)
            return

        # Dashboard root
        if path in ("/", "/index.html"):
            self._send_file(APP_DIR / "dashboard.html",
                            extra_headers=cookie_header)
            return

        self.send_response(404)
        self.end_headers()

    # ── POST ──────────────────────────────────────────────────────────────────

    def do_POST(self):
        path = self.path.split("?")[0]

        if path in ("/login", "/login/"):
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode(errors="replace")
            fields = urllib.parse.parse_qs(body)

            submitted_user = fields.get("username", [""])[0].strip()
            submitted_pass = fields.get("password", [""])[0]
            next_url       = fields.get("next",     ["/"])[0] or "/"

            # Constant-time comparisons to prevent timing attacks
            user_ok = hmac.compare_digest(
                submitted_user.lower(), USERNAME.lower()
            )
            pass_hash = hashlib.sha256(submitted_pass.encode()).hexdigest()
            pass_ok = hmac.compare_digest(pass_hash, PASSWORD_HASH)

            if user_ok and pass_ok:
                token = make_token(submitted_user)
                log.info("Login successful: %s", submitted_user)
                # Validate next_url — only allow relative paths
                if not next_url.startswith("/") or next_url.startswith("//"):
                    next_url = "/"
                self._redirect(next_url,
                               extra_headers=[("Set-Cookie", session_cookie(token))])
            else:
                log.warning("Failed login attempt for username: %s", submitted_user)
                self._send(
                    login_page(error="Invalid username or password.", next_url=next_url),
                    "text/html; charset=utf-8", status=401, cache=False
                )
            return

        # ── Stop a Docker container ───────────────────────────────────────────
        if path == "/docker/stop":
            user = self._require_auth()
            if user is None:
                return

            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length))
                container_name = body.get("container", "").strip()
            except Exception:
                self._json_response({"ok": False, "error": "Invalid JSON"}, status=400)
                return

            if not container_name:
                self._json_response({"ok": False, "error": "container name required"}, status=400)
                return

            # Safety: never allow stopping the monitor or dashboard itself
            PROTECTED = {"docker-memory-monitor", "docker-monitor-dashboard"}
            if container_name in PROTECTED:
                log.warning("User %s tried to stop protected container: %s", user, container_name)
                self._json_response(
                    {"ok": False, "error": f"Container '{container_name}' is protected and cannot be stopped from the dashboard."},
                    status=403
                )
                return

            if _docker_client is None:
                self._json_response({"ok": False, "error": "Docker socket not available — mount /var/run/docker.sock into the dashboard container."}, status=503)
                return

            try:
                container = _docker_client.containers.get(container_name)
                container.stop(timeout=10)
                log.warning("Container stopped by %s: %s", user, container_name)
                self._json_response({"ok": True, "message": f"Container '{container_name}' stopped."})
            except docker_sdk.errors.NotFound:
                self._json_response({"ok": False, "error": f"Container '{container_name}' not found."}, status=404)
            except Exception as exc:
                log.error("Failed to stop container %s: %s", container_name, exc)
                self._json_response({"ok": False, "error": str(exc)}, status=500)
            return

        self.send_response(404)
        self.end_headers()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    log.info("Dashboard starting on http://0.0.0.0:%d", PORT)
    log.info("Auth: username=%s password=%s secret=%s",
             "SET" if USERNAME else "NOT SET",
             "SET" if PASSWORD else "NOT SET",
             "SET" if os.getenv("SECRET_KEY") else "RANDOM (sessions reset on restart)")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()