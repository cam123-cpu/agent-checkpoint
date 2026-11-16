"""HTTP server: the agent API, the web app, and the web app's API. Standard library only.

Agents (Bearer agent key)                 People (session cookie, from /api/web/login)
  POST /v1/actions                          GET  /                       the web app
  GET  /v1/actions/<request_id>             POST /api/web/login | logout,  GET /api/web/me
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

import json
import ssl
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import views
from .accounts import AuthError
from .gateway import CheckpointError
from .importers import import_pos, import_vendors
from .models import parse_amount
from .report import shadow_report
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
                tls: tuple[str, str] | None = None) -> ThreadingHTTPServer:
    cfg = config or ServerConfig()
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
            if self._peer_trusted():
                return self.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip()
            return "http"

        def _ip(self) -> str:
            if self._peer_trusted() and self.headers.get("X-Forwarded-For"):
                return self.headers["X-Forwarded-For"].split(",")[0].strip()[:64]
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
                raise HTTPError(413, "request body is too large", {"Connection": "close"})
            return self.rfile.read(length)

        def _body(self, allowed: set[str] | None = None) -> dict:
            try:
                body = json.loads(self._read(MAX_JSON) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
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

        def _cookie(self) -> str:
            for part in self.headers.get("Cookie", "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == cookie_name:
                    return value
            return ""

        def _same_site(self):
            if self.headers.get("X-Requested-With") != "fetch":
                raise HTTPError(403, "missing X-Requested-With: fetch")
            origin = self.headers.get("Origin")
            if self.command == "POST" and origin:
                host = self.headers.get("Host", "")
                if origin not in (f"{self._scheme()}://{host}", cfg.public_origin):
                    raise HTTPError(403, "cross-site request refused")

        def _user(self, *roles: str):
            user = accounts.session(self._cookie())
            if user is None:
                raise HTTPError(401, "Sign in to continue.")
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
                host = self.headers.get("Host", "")
                raise HTTPError(308, "use https", {"Location": f"https://{host}{self.path}"})
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
                b = self._body({"approve", "note", "callback_verified", "fraud"})
                return self._json(200, self._resolve(gw, path.rsplit("/", 1)[-1], who["name"], b))
            if path == "/v1/fraud-reports" and m == "POST":
                gw.report_fraud(str(self._body({"request_id"}).get("request_id", "")), who["name"])
                return self._json(200, {"reported": True})
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
            return gw.resolve(ticket_id, approver, b["approve"], note, callback_verified=b.get("callback_verified") is True,
                              fraud=b.get("fraud") is True)

        def _web(self, m: str, route: str, qp):
            self._same_site()
            if route == "login" and m == "POST":
                b = self._body({"email", "password", "website"})
                if b.get("website"):  # honeypot: people never see this field; bots fill it in
                    time.sleep(0.3)
                    raise HTTPError(401, "Email or password is incorrect.")
                if not isinstance(b.get("email"), str) or not isinstance(b.get("password"), str):
                    raise HTTPError(422, "Enter your email and password.")
                token, user = accounts.login(b["email"], b["password"], self._ip())
                gw = registry.gateway(user.org_id)
                return self._json(200, {"email": user.email, "role": user.role, "company": gw.org.name},
                                  self._set_cookie(token, 12 * 3600))
            if route == "logout" and m == "POST":
                accounts.logout(self._cookie())
                return self._json(200, {"signed_out": True}, self._set_cookie("", 0))

            user = self._user()
            gw = registry.gateway(user.org_id)
            if route == "me" and m == "GET":
                return self._json(200, {"email": user.email, "role": user.role, "company": gw.org.name,
                                        "mode": gw.org.policy.mode})
            if route == "overview" and m == "GET":
                return self._json(200, views.overview(gw))
            if route == "tickets" and m == "GET":
                return self._json(200, {"tickets": views.tickets(gw)})
            if route.startswith("tickets/") and m == "POST":
                self._user("admin", "approver")
                b = self._body({"approve", "note", "callback_verified", "fraud"})
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
                    {"mode", "approval_limit", "dual_approval_limit", "recent_bank_change_days", "ticket_hours"})))
            if route in ("import/vendors", "import/pos") and m == "POST":
                self._user("admin")
                if not self.headers.get("Content-Type", "").startswith("text/csv"):
                    raise HTTPError(415, "upload a .csv file")
                try:
                    text = self._read(MAX_CSV).decode("utf-8-sig")
                except UnicodeDecodeError as exc:
                    raise HTTPError(422, "the file must be UTF-8 text") from exc
                if "\x00" in text or text.count("\n") > MAX_CSV_ROWS:
                    raise HTTPError(422, f"the file must be plain text with at most {MAX_CSV_ROWS} rows")
                which = route.split("/")[1]
                n, errors = (import_vendors if which == "vendors" else import_pos)(gw.org.store, text)
                gw.org.ledger.append("import", "-", {"by": user.email, "what": which, "rows": n, "errors": len(errors)})
                return self._json(200, {"imported": n, "errors": errors[:50]})
            if route == "export/activity.csv" and m == "GET":
                body = views.activity_csv(gw).encode()
                return self._send(200, body, "text/csv; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="checkpoint-activity.csv"'})
            raise HTTPError(404, "not found")

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
            try:
                self._route()
            except HTTPError as exc:
                self._json(exc.status, {"error": str(exc)}, exc.headers)
            except (CheckpointError, AuthError) as exc:
                self._json(exc.status, {"error": str(exc)})
            except Exception:  # never leak internals
                self._json(500, {"error": "Something went wrong on the server. Nothing was changed."})

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
