"""HTTP server: the agent API, the web app, and the web app's API. Standard library only.

Agents (Bearer agent key)                 People (session cookie, from /api/web/login)
  POST /v1/actions                          GET  /                       the web app
  GET  /v1/actions/<request_id>             POST /api/web/login, login/two-step, logout;  GET /api/web/me
                                            POST /api/web/two-step/start | confirm | disable, /api/web/password
  GET  /v1/vendors?q=                       GET  /api/web/overview | tickets | activity | audit | vendors | settings
Approvers (Bearer approver key)             POST /api/web/tickets/<id>  approve or reject
  GET  /v1/tickets, POST /v1/tickets/<id>   POST /api/web/settings       admin
  POST /v1/fraud-reports                    POST /api/web/import/vendors | pos   admin, CSV
  GET  /v1/report, /v1/ledger/verify|head   GET  /api/web/export/activity.csv
Anyone: GET /health, GET /v1/public-key?org=

Security, in the order a request meets it:
  1. HTTPS: optional built-in TLS, or behind a proxy; `force_https` redirects plain HTTP (308) and
     sends HSTS. X-Forwarded-* is believed only from configured proxy addresses.
  2. Headers on every response: strict Content-Security-Policy (no inline script, nothing
     third-party), frame-ancestors none, nosniff, no-referrer, Permissions-Policy, COOP,
     no-store for every API answer.
  3. Size limits: 256 KB JSON, 1 MB CSV, before anything is read.
  4. Rate limits: per key and per session (600 a minute); sign-in has its own stricter limits.
  5. Auth on the server for every route; role checks; every query scoped to the caller's company.
  6. Web requests need `X-Requested-With: fetch` (a cross-site page can't add it without a CORS
     preflight, which this server never grants) and a same-site Origin on changes. The session
     cookie is HttpOnly, Secure, SameSite=Strict, __Host- prefixed.
  7. Strict input: unknown fields refused, types and ranges checked.
  8. Trimmed output: view models only (`views.py`), accounts as last four digits.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import ssl
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import qr, totp, views
from .accounts import AuthError
from .gateway import CheckpointError
from .importers import _domains, import_history, import_pos, import_vendors, read_payment_run
from .models import ACTIONS, parse_amount
from .oidc import OIDC, SSOConfig, SSOError, new_flow
from .policy import AgentScope
from .report import shadow_report
from .store import PurchaseOrder, Vendor
from .tenancy import Registry

MAX_JSON = 256 * 1024
MAX_CSV = 1024 * 1024
MAX_CSV_ROWS = 5000

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
}

CSP_PAGE = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
            "manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
CSP_API = "default-src 'none'; frame-ancestors 'none'"


@dataclass(frozen=True)
class ServerConfig:
    secure_cookies: bool = True          # False only for plain-HTTP local development
    force_https: bool = False            # redirect http → https and send HSTS
    trusted_proxies: tuple[str, ...] = ("127.0.0.1", "::1")
    public_origin: str = ""              # e.g. https://checkpoint.acme.com (extra allowed Origin)
    requests_per_minute: int = 600


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.per_minute:
                return False
            q.append(now)
            if len(self._hits) > 50_000:  # bound memory
                for k in [k for k, v in self._hits.items() if not v][:10_000]:
                    del self._hits[k]
            return True


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    max_connections = 200  # one thread per connection: cap them, so idle sockets can't exhaust memory

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)  # over the cap: drop it immediately
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        """Broken or non-TLS connections are routine on the internet: drop them without a traceback."""
        import sys
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError, OSError)):
            return
        super().handle_error(request, client_address)


class HTTPError(Exception):
    def __init__(self, status: int, message: str, headers: dict | None = None):
        super().__init__(message)
        self.status, self.headers = status, headers or {}


def _static(name: str) -> bytes:
    return resources.files("agent_checkpoint").joinpath("web", name).read_bytes()


def make_server(registry: Registry, host: str = "127.0.0.1", port: int = 8077, config: ServerConfig | None = None,
                tls: tuple[str, str] | None = None, oidc: OIDC | None = None) -> ThreadingHTTPServer:
    cfg = config or ServerConfig()
    oidc = oidc or OIDC()
    binding_cookie = "__Host-cp_sso" if cfg.secure_cookies else "cp_sso"

    def sso_config(org_id: str):
        try:
            return SSOConfig.load(registry.org_dir(org_id)) if org_id else None
        except (ValueError, OSError, TypeError):
            return None
    limiter = RateLimiter(cfg.requests_per_minute)
    cookie_name = "__Host-cp_session" if cfg.secure_cookies else "cp_session"
    accounts = registry.accounts()

    class Handler(BaseHTTPRequestHandler):
        server_version = "checkpoint"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = 30  # seconds a connection may sit idle (slow-client protection)

        def log_message(self, fmt, *args):
            pass

        # --- transport ----------------------------------------------------------------

        def _peer_trusted(self) -> bool:
            return self.client_address[0] in cfg.trusted_proxies

        def _scheme(self) -> str:
            if tls:
                return "https"
            headers = getattr(self, "headers", None)
            if headers is not None and self._peer_trusted() and headers.get("X-Forwarded-Proto"):
                return headers["X-Forwarded-Proto"].split(",")[-1].strip()  # the value our proxy added
            return "http"

        def _ip(self) -> str:
            """Walk X-Forwarded-For from the right: the first address that isn't one of our proxies is the client.
            Anything further left was supplied by the client and can be forged."""
            if not self._peer_trusted() or not self.headers.get("X-Forwarded-For"):
                return self.client_address[0]
            hops = [h.strip()[:64] for h in self.headers["X-Forwarded-For"].split(",") if h.strip()]
            for hop in reversed(hops):
                if hop not in cfg.trusted_proxies:
                    return hop
            return self.client_address[0]

        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None, page: bool = False):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP_PAGE if page else CSP_API)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Cache-Control", "no-cache" if page else "no-store")
            if self._scheme() == "https":
                self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, obj, extra: dict | None = None):
            self._send(status, json.dumps(obj).encode(), "application/json", extra)

        def _read(self, limit: int) -> bytes:
            raw = self.headers.get("Content-Length")
            if raw is None:
                if self.command == "POST":
                    raise HTTPError(411, "Content-Length is required")
                return b""
            try:
                length = int(raw)
            except ValueError as exc:
                raise HTTPError(400, "bad Content-Length") from exc
            if length < 0 or length > limit:
                self.close_connection = True  # the unread body makes this connection unusable
                self._consumed = True
                raise HTTPError(413, "request body is too large", {"Connection": "close"})
            self._consumed = True
            return self.rfile.read(length)

        def _body(self, allowed: set[str] | None = None) -> dict:
            try:
                body = json.loads(self._read(MAX_JSON) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise HTTPError(400, "body is not JSON") from exc
            if not isinstance(body, dict):
                raise HTTPError(400, "body must be a JSON object")
            if allowed is not None:
                extra = set(body) - allowed
                if extra:
                    raise HTTPError(422, f"unknown fields: {sorted(extra)}")
            return body

        # --- auth -----------------------------------------------------------------------

        def _bearer(self, kind: str) -> dict:
            auth = self.headers.get("Authorization", "")
            key = auth[7:] if auth.startswith("Bearer ") else ""
            who = registry.lookup(key)
            if who is None or who["kind"] != kind:
                raise HTTPError(401, f"{kind} key required")
            if not limiter.allow(f"key:{who['org']}:{who['kind']}:{who['name']}"):
                raise HTTPError(429, "rate limit: slow down", {"Retry-After": "60"})
            return who

        def _cookie(self, name: str | None = None) -> str:
            for part in self.headers.get("Cookie", "").split(";"):
                key, _, value = part.strip().partition("=")
                if key == (name or cookie_name):
                    return value
            return ""

        def _origin(self) -> str:
            return cfg.public_origin or f"{self._scheme()}://{self.headers.get('Host', '')}"

        def _redirect(self, location: str, cookies: list[str] | None = None):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            if self._scheme() == "https":
                self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            for c in cookies or []:
                self.send_header("Set-Cookie", c)
            self.end_headers()

        def _sso(self, path: str, qp):
            redirect_uri = self._origin() + "/auth/sso/callback"
            secure = "; Secure" if cfg.secure_cookies else ""
            clear = f"{binding_cookie}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}"
            if path == "/auth/sso/start":
                org = qp("org")
                loaded = sso_config(org)
                if not loaded:
                    return self._redirect("/?sso_error=not_configured")
                state, nonce, verifier, binding = new_flow()
                try:
                    url = oidc.authorize_url(loaded[0], redirect_uri, state, nonce, verifier)
                except SSOError as exc:
                    return self._redirect("/?sso_error=" + exc.code)
                accounts.sso_begin(org, state, nonce, verifier, binding)
                # Lax, not Strict: it must come back on the provider's cross-site redirect to the callback.
                return self._redirect(url, [f"{binding_cookie}={binding}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600{secure}"])
            try:
                if qp("error") or not qp("code"):
                    raise SSOError("provider", qp("error")[:40])
                try:
                    org, nonce, verifier = accounts.sso_take(qp("state"), self._cookie(binding_cookie))
                except AuthError as exc:
                    raise SSOError("expired") from exc
                loaded = sso_config(org)
                if not loaded:
                    raise SSOError("not_configured")
                email = oidc.finish(loaded[0], loaded[1], redirect_uri, qp("code", ""), verifier, nonce)
                user = accounts.user(email)
                if user is None or user.org_id != org:
                    raise SSOError("no_account", email)
                token, user = accounts.sso_session(email)
                registry.gateway(org).org.ledger.append("account", "-", {"by": email, "event": "signed in with SSO"})
            except SSOError as exc:
                # Only a fixed code travels in the URL; the page shows its own text for it (never URL text).
                return self._redirect("/?sso_error=" + exc.code, [clear])
            session = f"{cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={12 * 3600}{secure}"
            return self._redirect("/#approvals", [session, clear])

        def _same_site(self):
            if self.headers.get("X-Requested-With") != "fetch":
                raise HTTPError(403, "missing X-Requested-With: fetch")
            origin = self.headers.get("Origin")
            if self.command == "POST" and origin:
                host = self.headers.get("Host", "")
                if origin not in (f"{self._scheme()}://{host}", cfg.public_origin):
                    raise HTTPError(403, "cross-site request refused")

        def _user(self, *roles: str, allow_limited: bool = False):
            user = accounts.session(self._cookie())
            if user is None:
                raise HTTPError(401, "Sign in to continue.")
            if user.limited and not allow_limited:
                raise HTTPError(403, "Set up two-step sign-in to continue.")
            if roles and user.role not in roles:
                raise HTTPError(403, "Your role can't do that.")
            if not limiter.allow("session:" + user.email):
                raise HTTPError(429, "rate limit: slow down", {"Retry-After": "60"})
            return user

        def _set_cookie(self, token: str, max_age: int) -> dict:
            attrs = f"{cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
            if cfg.secure_cookies:
                attrs += "; Secure"
            return {"Set-Cookie": attrs}

        # --- routes ---------------------------------------------------------------------

        def _route(self):
            url = urlparse(self.path)
            path, query = url.path.rstrip("/") or "/", parse_qs(url.query)
            m = self.command if self.command != "HEAD" else "GET"

            def qp(name: str, default: str = "") -> str:
                return (query.get(name) or [default])[0][:200]

            if cfg.force_https and self._scheme() != "https" and path != "/health":
                base = cfg.public_origin or "https://" + self.headers.get("Host", "").split("/")[0]
                raise HTTPError(308, "use https", {"Location": base + (self.path if self.path.startswith("/") else "/")})
            if m == "GET" and path in STATIC:
                name, ctype = STATIC[path]
                return self._send(200, _static(name), ctype, page=True)
            if m == "GET" and path == "/health":
                return self._json(200, {"ok": True})
            if m == "GET" and path == "/v1/public-key":
                try:
                    return self._json(200, {"public_key": registry.gateway(qp("org")).org.signer.public_pem()})
                except (KeyError, ValueError) as exc:
                    raise HTTPError(404, "no such company") from exc

            if path.startswith("/api/web/"):
                return self._web(m, path[len("/api/web/"):], qp)
            if m == "GET" and path in ("/auth/sso/start", "/auth/sso/callback"):
                return self._sso(path, lambda name, default="": (query.get(name) or [default])[0][:4096])
            if path.startswith("/v1/"):
                return self._api(m, path, qp)
            raise HTTPError(404, "not found")

        def _api(self, m: str, path: str, qp):
            if path == "/v1/actions" and m == "POST":
                who = self._bearer("agent")
                return self._json(200, registry.gateway(who["org"]).submit(self._body(), agent_id=who["name"]).to_dict())
            if path.startswith("/v1/actions/") and m == "GET":
                who = self._bearer("agent")
                return self._json(200, registry.gateway(who["org"]).status(path.rsplit("/", 1)[-1], who["name"]))
            if path == "/v1/vendors" and m == "GET":
                from .mcp_server import _vendor_rows
                who = self._bearer("agent")
                if not qp("q").strip():
                    raise HTTPError(422, "q is required")
                return self._json(200, {"vendors": _vendor_rows(registry.gateway(who["org"]).org.store.vendors(), qp("q"))})
            who = self._bearer("approver")
            gw = registry.gateway(who["org"])
            if path == "/v1/tickets" and m == "GET":
                return self._json(200, {"tickets": views.tickets(gw)})
            if path.startswith("/v1/tickets/") and m == "POST":
                b = self._body({"approve", "note", "callback_verified", "fraud", "called_number"})
                return self._json(200, self._resolve(gw, path.rsplit("/", 1)[-1], who["name"], b))
            if path == "/v1/fraud-reports" and m == "POST":
                gw.report_fraud(str(self._body({"request_id"}).get("request_id", "")), who["name"])
                return self._json(200, {"reported": True})
            if path == "/v1/fraud-reports/withdraw" and m == "POST":
                b = self._body({"request_id", "reason"})
                return self._json(200, gw.withdraw_report(str(b.get("request_id", "")), who["name"],
                                                          str(b.get("reason", ""))[:500]))
            if path == "/v1/report" and m == "GET":
                return self._json(200, shadow_report(gw.org.ledger, qp("since"), qp("until")))
            if path == "/v1/ledger/verify" and m == "GET":
                ok, why = gw.org.ledger.verify()
                return self._json(200, {"ok": ok, "detail": why, "head": gw.org.ledger.head()})
            if path == "/v1/ledger/head" and m == "GET":
                return self._json(200, gw.org.ledger.head())
            raise HTTPError(404, "not found")

        @staticmethod
        def _resolve(gw, ticket_id: str, approver: str, b: dict) -> dict:
            if not isinstance(b.get("approve"), bool):
                raise HTTPError(422, "approve must be true or false")
            for flag in ("callback_verified", "fraud"):
                if flag in b and not isinstance(b[flag], bool):
                    raise HTTPError(422, f"{flag} must be true or false")
            note = b.get("note", "")
            if not isinstance(note, str) or len(note) > 500:
                raise HTTPError(422, "note must be text, at most 500 characters")
            called = b.get("called_number", "")
            if not isinstance(called, str) or len(called) > 40:
                raise HTTPError(422, "called_number must be text, at most 40 characters")
            return gw.resolve(ticket_id, approver, b["approve"], note, callback_verified=b.get("callback_verified") is True,
                              fraud=b.get("fraud") is True, called_number=called)

        def _web(self, m: str, route: str, qp):
            self._same_site()
            if route == "login" and m == "POST":
                b = self._body({"email", "password", "website"})
                if b.get("website"):  # honeypot: people never see this field; bots fill it in
                    time.sleep(0.3)
                    raise HTTPError(401, "Email or password is incorrect.")
                if not isinstance(b.get("email"), str) or not isinstance(b.get("password"), str):
                    raise HTTPError(422, "Enter your email and password.")
                result = accounts.login(b["email"], b["password"], self._ip(),
                                        require_two_step=lambda org: registry.gateway(org).org.policy.require_two_step)
                if result.kind == "two_step":
                    return self._json(200, {"two_step_required": True, "pending": result.token})
                return self._json(200, {"signed_in": True}, self._set_cookie(result.token, 12 * 3600))
            if route == "login/two-step" and m == "POST":
                b = self._body({"pending", "code"})
                if not isinstance(b.get("pending"), str) or not isinstance(b.get("code"), str) or len(b["code"]) > 20:
                    raise HTTPError(422, "Enter the code from your authenticator app.")
                result = accounts.login_second_step(b["pending"], b["code"], self._ip())
                return self._json(200, {"signed_in": True}, self._set_cookie(result.token, 12 * 3600))
            if route == "sso" and m == "GET":
                loaded = sso_config(qp("org"))
                return self._json(200, {"enabled": bool(loaded), "label": loaded[0].label if loaded else ""})
            if route == "logout" and m == "POST":
                accounts.logout(self._cookie())
                return self._json(200, {"signed_out": True}, self._set_cookie("", 0))

            user = self._user(allow_limited=route in ("me", "two-step/start", "two-step/confirm", "password"))
            gw = registry.gateway(user.org_id)
            if route == "me" and m == "GET":
                return self._json(200, {"email": user.email, "role": user.role, "company": gw.org.name,
                                        "mode": gw.org.policy.mode, "two_step": user.two_step,
                                        "setup_required": user.limited,
                                        "require_two_step": gw.org.policy.require_two_step,
                                        "recovery_codes_left": accounts.recovery_codes_left(user.email)})
            if route == "two-step/start" and m == "POST":
                self._body(set())
                if user.two_step:
                    raise HTTPError(409, "Two-step sign-in is already on. Turn it off first to move it to a new phone.")
                secret = accounts.start_two_step(user.email)
                uri = totp.otpauth_uri(secret, user.email)
                image = base64.b64encode(qr.svg(uri).encode()).decode()
                return self._json(200, {"key": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
                                        "uri": uri, "qr": "data:image/svg+xml;base64," + image})
            if route == "two-step/confirm" and m == "POST":
                b = self._body({"code"})
                if not isinstance(b.get("code"), str) or len(b["code"]) > 20:
                    raise HTTPError(422, "Enter the 6-digit code from your authenticator app.")
                codes = accounts.confirm_two_step(user.email, b["code"])
                gw.org.ledger.append("account", "-", {"by": user.email, "event": "two-step sign-in turned on"})
                return self._json(200, {"recovery_codes": codes})
            if route == "two-step/disable" and m == "POST":
                b = self._body({"password", "code"})
                if gw.org.policy.require_two_step:
                    raise HTTPError(403, "Your company requires two-step sign-in, so it can't be turned off.")
                if not isinstance(b.get("password"), str) or not isinstance(b.get("code"), str):
                    raise HTTPError(422, "Enter your password and a code.")
                accounts.disable_two_step(user.email, b["password"], b["code"])
                gw.org.ledger.append("account", "-", {"by": user.email, "event": "two-step sign-in turned off"})
                return self._json(200, {"two_step": False}, self._set_cookie("", 0))
            if route == "password" and m == "POST":
                b = self._body({"current", "new"})
                if not isinstance(b.get("current"), str) or not isinstance(b.get("new"), str):
                    raise HTTPError(422, "Enter your current and new password.")
                accounts.change_password(user.email, b["current"], b["new"])
                gw.org.ledger.append("account", "-", {"by": user.email, "event": "password changed"})
                return self._json(200, {"changed": True}, self._set_cookie("", 0))
            if route == "overview" and m == "GET":
                return self._json(200, views.overview(gw))
            if route == "tickets" and m == "GET":
                return self._json(200, {"tickets": views.tickets(gw)})
            if route.startswith("tickets/") and m == "POST":
                self._user("admin", "approver")
                b = self._body({"approve", "note", "callback_verified", "fraud", "called_number"})
                return self._json(200, self._resolve(gw, route.split("/", 1)[1], user.email, b))
            if route == "activity" and m == "GET":
                verdict = qp("verdict")
                if verdict not in ("", "go", "pause", "block"):
                    raise HTTPError(422, "verdict must be go, pause or block")
                return self._json(200, {"rows": views.activity(gw, verdict, qp("agent"), qp("q"))})
            if route == "audit" and m == "GET":
                return self._json(200, views.audit(gw))
            if route == "vendors" and m == "GET":
                return self._json(200, {"vendors": views.vendors(gw)})
            if route == "settings" and m == "GET":
                return self._json(200, views.settings(gw, accounts.users(user.org_id)))
            if route == "settings" and m == "POST":
                self._user("admin")
                return self._json(200, self._save_settings(gw, user, self._body(
                    {"mode", "approval_limit", "dual_approval_limit", "recent_bank_change_days", "ticket_hours",
                     "require_two_step"})))
            if route in ("import/vendors", "import/pos", "import/history") and m == "POST":
                self._user("admin")
                text = self._csv()
                which = route.split("/")[1]
                try:
                    if which == "history":
                        order = qp("date_order", "mdy")
                        if order not in ("mdy", "dmy"):
                            raise HTTPError(422, "date_order must be mdy or dmy")
                        n, already, errors = import_history(gw.org.store, text, order)
                    else:
                        already = 0
                        n, errors = (import_vendors if which == "vendors" else import_pos)(gw.org.store, text)
                except ValueError as exc:
                    raise HTTPError(422, str(exc)) from exc
                gw.org.ledger.append("import", "-", {"by": user.email, "what": which, "rows": n, "errors": len(errors)})
                return self._json(200, {"imported": n, "already_there": already, "errors": errors[:50]})
            if route == "payment-run" and m == "POST":
                self._user("admin", "approver")
                text = self._csv()
                try:
                    rows, errors = read_payment_run(gw.org.store, text)
                except ValueError as exc:
                    raise HTTPError(422, str(exc)) from exc
                if not rows:
                    raise HTTPError(422, "No payments found in the file. " + " ".join(errors[:3]))
                out = gw.check_run(rows, user.email, hashlib.sha256(text.encode()).hexdigest())
                return self._json(200, {**out, "errors": errors[:50]})
            if route == "setup" and m == "GET":
                return self._json(200, views.setup(gw, accounts.users(user.org_id), registry.agent_key_count(user.org_id)))
            if route == "vendors" and m == "POST":
                self._user("admin")
                b = self._body({"vendor_id", "name", "bank_account", "email_domains", "phone"})
                vid, name, acct = (str(b.get(k, "")).strip() for k in ("vendor_id", "name", "bank_account"))
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", vid):
                    raise HTTPError(422, "Vendor ID: letters, digits, dot, dash or underscore, up to 64.")
                if not name or len(name) > 200:
                    raise HTTPError(422, "Enter the vendor's name.")
                if not re.fullmatch(r"[A-Za-z0-9 -]{4,64}", acct) or not any(ch.isdigit() for ch in acct):
                    raise HTTPError(422, "Enter the bank account (IBAN or account number).")
                if gw.org.store.vendor(vid):
                    raise HTTPError(409, "A vendor with that ID already exists.")
                v = Vendor(vid, name, acct, _domains(str(b.get("email_domains", ""))), gw.clock().date(),
                           phone=str(b.get("phone", ""))[:40])
                gw.org.store.upsert_vendor(v)
                gw.org.ledger.append("records", "-", {"by": user.email, "event": "vendor added", "vendor": vid})
                return self._json(200, {"vendors": views.vendors(gw)})
            if route.startswith("vendors/") and route.endswith("/bank-change") and m == "POST":
                self._user("admin", "approver")
                vid = urllib.parse.unquote(route.split("/")[1])
                b = self._body({"new_account", "note"})
                d = gw.submit_person({
                    "request_id": "bank-" + secrets.token_hex(8), "action": "change_bank", "vendor_id": vid,
                    "bank_account": str(b.get("new_account", "")).strip()[:64],
                    "evidence": [{"kind": "other", "ref": (str(b.get("note", "")).strip() or "requested in the web app")[:300]}],
                }, user.email)
                return self._json(200, d.to_dict())
            if route.startswith("vendors/") and m == "POST":
                self._user("admin")
                vid = urllib.parse.unquote(route.split("/", 1)[1])
                b = self._body({"name", "email_domains", "phone"})
                v = gw.org.store.vendor(vid)
                if v is None:
                    raise HTTPError(404, "no such vendor")
                name = str(b.get("name", v.name)).strip()[:200] or v.name
                domains = _domains(str(b["email_domains"])) if "email_domains" in b else v.email_domains
                gw.org.store.upsert_vendor(Vendor(v.vendor_id, name, v.bank_account, domains, v.created_on,
                                                  v.bank_changed_on, str(b.get("phone", v.phone))[:40]))
                gw.org.ledger.append("records", "-", {"by": user.email, "event": "vendor details edited", "vendor": vid,
                                                      "fields": sorted(b)})
                return self._json(200, {"vendors": views.vendors(gw)})
            if route == "pos" and m == "POST":
                self._user("admin")
                b = self._body({"number", "vendor_id", "amount"})
                number = str(b.get("number", "")).strip()
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,63}", number):
                    raise HTTPError(422, "Enter the purchase order number.")
                if gw.org.store.vendor(str(b.get("vendor_id", ""))) is None:
                    raise HTTPError(422, "Choose a vendor from your vendor list.")
                if gw.org.store.po(number):
                    raise HTTPError(409, "That purchase order already exists.")
                try:
                    cents = parse_amount(str(b.get("amount", "")))
                except ValueError as exc:
                    raise HTTPError(422, f"Amount: {exc}") from exc
                gw.org.store.upsert_po(PurchaseOrder(number, str(b["vendor_id"]), cents))
                gw.org.ledger.append("records", "-", {"by": user.email, "event": "purchase order added", "po": number})
                return self._json(200, {"added": number})
            if route == "agents" and m == "POST":
                self._user("admin")
                b = self._body({"agent_id", "made_by", "allowed_actions", "max_amount", "daily_cap"})
                agent_id = str(b.get("agent_id", "")).strip().lower()
                if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,40}", agent_id):
                    raise HTTPError(422, "Agent name: lowercase letters, digits and dashes, 2 to 41 long.")
                if agent_id in gw.org.policy.agents:
                    raise HTTPError(409, "An agent with that name already exists.")
                key = registry.add_agent(user.org_id, agent_id, self._scope(b))
                gw.org.ledger.append("records", "-", {"by": user.email, "event": "agent added", "agent": agent_id})
                return self._json(200, {"agent_id": agent_id, "key": key})
            if route.startswith("agents/") and route.endswith("/remove") and m == "POST":
                self._user("admin")
                agent_id = route.split("/")[1]
                if agent_id not in gw.org.policy.agents:
                    raise HTTPError(404, "no such agent")
                self._body(set())
                revoked = registry.remove_agent(user.org_id, agent_id)
                gw.org.ledger.append("records", "-", {"by": user.email, "event": "agent removed", "agent": agent_id,
                                                      "keys_revoked": revoked})
                return self._json(200, {"removed": agent_id, "keys_revoked": revoked})
            if route.startswith("agents/") and m == "POST":
                self._user("admin")
                agent_id = route.split("/")[1]
                if agent_id not in gw.org.policy.agents:
                    raise HTTPError(404, "no such agent")
                registry.update_agent(user.org_id, agent_id, self._scope(
                    self._body({"made_by", "allowed_actions", "max_amount", "daily_cap"})))
                gw.org.ledger.append("records", "-", {"by": user.email, "event": "agent limits changed", "agent": agent_id})
                return self._json(200, views.settings(gw, accounts.users(user.org_id)))
            if route == "people" and m == "POST":
                self._user("admin")
                b = self._body({"email", "role"})
                if b.get("role") not in ("admin", "approver", "auditor"):
                    raise HTTPError(422, "Role must be admin, approver or auditor.")
                password = secrets.token_urlsafe(15)
                registry.add_user(user.org_id, str(b.get("email", "")), b["role"], password)
                gw.org.ledger.append("records", "-", {"by": user.email, "event": "person added",
                                                      "person": str(b.get("email", "")).lower(), "role": b["role"]})
                return self._json(200, {"email": str(b["email"]).strip().lower(), "temporary_password": password})
            if route.startswith("people/") and m == "POST":
                self._user("admin")
                parts = route.split("/")
                if len(parts) != 3 or parts[2] not in ("disable", "enable", "reset-two-step"):
                    raise HTTPError(404, "not found")
                email = urllib.parse.unquote(parts[1]).lower()
                self._body(set())
                if accounts.org_of(email) != user.org_id:
                    raise HTTPError(404, "no such person")
                if email == user.email and parts[2] == "disable":
                    raise HTTPError(422, "You can't disable your own account.")
                if parts[2] == "reset-two-step":
                    accounts.reset_two_step(email)
                else:
                    accounts.set_disabled(email, parts[2] == "disable")
                gw.org.ledger.append("records", "-", {"by": user.email, "event": f"person: {parts[2]}", "person": email})
                return self._json(200, {"users": accounts.users(user.org_id)})
            if route == "export/activity.csv" and m == "GET":
                body = views.activity_csv(gw).encode()
                return self._send(200, body, "text/csv; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="checkpoint-activity.csv"'})
            raise HTTPError(404, "not found")

        def _csv(self) -> str:
            if not self.headers.get("Content-Type", "").startswith("text/csv"):
                raise HTTPError(415, "upload a .csv file (in Excel: File, Save As, CSV UTF-8)")
            try:
                text = self._read(MAX_CSV).decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise HTTPError(422, "the file must be UTF-8 text (in Excel, save as CSV UTF-8)") from exc
            if "\x00" in text or text.count("\n") > MAX_CSV_ROWS:
                raise HTTPError(422, f"the file must be plain text with at most {MAX_CSV_ROWS} rows")
            return text

        @staticmethod
        def _scope(b: dict) -> AgentScope:
            actions = b.get("allowed_actions")
            if not isinstance(actions, list) or not actions or not set(actions) <= set(ACTIONS):
                raise HTTPError(422, f"Choose what the agent may do: {', '.join(ACTIONS)}.")
            try:
                max_c = parse_amount(str(b.get("max_amount", "")))
                day_c = parse_amount(str(b.get("daily_cap", "")))
            except ValueError as exc:
                raise HTTPError(422, f"Limits: {exc}") from exc
            if day_c < max_c:
                raise HTTPError(422, "The daily limit must be at least the limit per action.")
            return AgentScope(tuple(dict.fromkeys(actions)), max_c, day_c, str(b.get("made_by", ""))[:80])

        @staticmethod
        def _save_settings(gw, user, b: dict) -> dict:
            p = gw.org.policy
            changes = {}
            if "mode" in b:
                if b["mode"] not in ("shadow", "enforce"):
                    raise HTTPError(422, "mode must be shadow or enforce")
                changes["mode"] = b["mode"]
            for field, attr in (("approval_limit", "approval_limit_cents"), ("dual_approval_limit", "dual_approval_cents")):
                if field in b:
                    try:
                        changes[attr] = parse_amount(str(b[field]))
                    except ValueError as exc:
                        raise HTTPError(422, f"{field}: {exc}") from exc
            if "require_two_step" in b:
                if not isinstance(b["require_two_step"], bool):
                    raise HTTPError(422, "require_two_step must be true or false")
                if b["require_two_step"] and not user.two_step:
                    raise HTTPError(422, "Turn on two-step sign-in for your own account first, so you aren't locked out.")
                changes["require_two_step"] = b["require_two_step"]
            for field, lo, hi in (("recent_bank_change_days", 1, 365), ("ticket_hours", 1, 720)):
                if field in b:
                    v = b[field]
                    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                        raise HTTPError(422, f"{field} must be a whole number from {lo} to {hi}")
                    changes[field] = v
            try:
                new = replace(p, **changes)
            except ValueError as exc:
                raise HTTPError(422, str(exc)) from exc
            registry.save_policy(gw.org.org_id, new)
            gw.org.ledger.append("settings_changed", "-", {"by": user.email, "changes": changes})
            return views.settings(gw, accounts.users(user.org_id))

        def _handle(self):
            self._consumed = False
            if self.headers.get("Transfer-Encoding"):
                # Chunked bodies aren't supported. Refuse and close, so no part of the body can be read as
                # another request on a reused connection (request smuggling).
                self._consumed = True
                self.close_connection = True
                return self._json(501, {"error": "send the body with Content-Length, not Transfer-Encoding"},
                                  {"Connection": "close"})
            try:
                self._route()
            except HTTPError as exc:
                self._json(exc.status, {"error": str(exc)}, exc.headers)
            except (CheckpointError, AuthError) as exc:
                self._json(exc.status, {"error": str(exc)})
            except Exception:  # never leak internals
                self._json(500, {"error": "Something went wrong on the server. Nothing was changed."})
            finally:
                self._drain()

        def _drain(self):
            """A body the route didn't read must not be mistaken for the next request on this connection."""
            if self._consumed:
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if 0 < length <= MAX_CSV:
                self.rfile.read(length)
            elif length:
                self.close_connection = True

        def send_error(self, code, message=None, explain=None):
            """Malformed requests and unknown methods: a JSON error with the usual security headers, then close."""
            self.close_connection = True
            if not getattr(self, "request_version", "").startswith("HTTP/1"):
                self.request_version = "HTTP/1.1"
            try:
                self._send(code, json.dumps({"error": (message or "bad request")[:200]}).encode(), "application/json",
                           {"Connection": "close"})
            except Exception:
                pass

        def do_GET(self):
            self._handle()

        def do_HEAD(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def do_PUT(self):
            self._json(405, {"error": "method not allowed"})

        do_DELETE = do_PATCH = do_OPTIONS = do_PUT

    srv = _Server((host, port), Handler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(*tls)
        # Handshake lazily in the request's own thread, so a slow or silent client can't stall accept().
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    return srv
