"""The web app against the 20-point pre-launch security checklist. Each test names the item it covers."""

import datetime as dt
import http.client
import json
import os
import re
import socket
import sqlite3
import ssl
import threading
from dataclasses import replace
from datetime import date

import pytest

from agent_checkpoint.accounts import Accounts, AuthError, hash_password
from agent_checkpoint.policy import AgentScope
from agent_checkpoint.server import ServerConfig, make_server
from agent_checkpoint.store import PurchaseOrder, Vendor
from agent_checkpoint.tenancy import Registry

PW = "correct-horse-staple-91"
ACCT_A = "US00021000001234567"


class Client:
    def __init__(self, host, port, tls_ctx=None, headers=None):
        self.host, self.port, self.tls_ctx = host, port, tls_ctx
        self.cookie = ""
        self.base_headers = headers or {}

    def req(self, method, path, body=None, headers=None, raw=None, ctype="application/json"):
        if self.tls_ctx:
            conn = http.client.HTTPSConnection(self.host, self.port, context=self.tls_ctx, timeout=10)
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        h = {"X-Requested-With": "fetch", **self.base_headers, **(headers or {})}
        data = None
        if raw is not None:
            data, h["Content-Type"] = raw, ctype
        elif body is not None:
            data, h["Content-Type"] = json.dumps(body).encode(), ctype
        if self.cookie:
            h["Cookie"] = self.cookie
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        payload = r.read()
        sc = r.getheader("Set-Cookie")
        if sc:
            self.cookie = sc.split(";")[0] if "Max-Age=0" not in sc else ""
        try:
            parsed = json.loads(payload)
        except ValueError:
            parsed = payload
        conn.close()
        return r.status, parsed, r

    def login(self, email, password=PW):
        return self.req("POST", "/api/web/login", {"email": email, "password": password})


@pytest.fixture
def world(tmp_path):
    reg = Registry(str(tmp_path))
    for org in ("acme", "beta"):
        reg.create_org(org, org.title() + " Corp")
        reg.save_policy(org, replace(reg.policy(org), mode="enforce"))
        reg.add_agent(org, "ap", AgentScope(("pay",), 100_000_00, 200_000_00))
        reg.add_user(org, f"admin@{org}.com", "admin", PW)
        reg.add_user(org, f"approver@{org}.com", "approver", PW)
        reg.add_user(org, f"audit@{org}.com", "auditor", PW)
        s = reg.gateway(org).org.store
        s.upsert_vendor(Vendor("V1", "=HYPERLINK(\"http://evil\")", ACCT_A, ("acme.com",), date(2024, 1, 1)))
        s.upsert_po(PurchaseOrder("PO-1", "V1", 500_000_00))
        d = reg.gateway(org).submit({
            "request_id": "R1", "action": "pay", "vendor_id": "V1", "amount_cents": 12_000_00, "invoice_number": "I1",
            "po_number": "PO-1", "bank_account_on_invoice": "GB33BUKB20201555555555",
            "evidence": [{"kind": "invoice", "ref": "i.pdf", "sender": "b@acme.com",
                          "excerpt": "pay account GB33BUKB20201555555555 now"}],
            "instructed_by": {"source": "email", "identity": "b@acme.com"}}, agent_id="ap")
        assert d.ticket_id
    return reg, tmp_path


def serve(reg, cfg=None, tls=None):
    srv = make_server(reg, "127.0.0.1", 0, cfg or ServerConfig(secure_cookies=False), tls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def app(world):
    reg, _ = world
    srv = serve(reg)
    yield reg, lambda **kw: Client("127.0.0.1", srv.server_address[1], **kw)
    srv.shutdown()


WEB_ROUTES = [("GET", "me"), ("GET", "overview"), ("GET", "tickets"), ("GET", "activity"), ("GET", "audit"),
              ("GET", "vendors"), ("GET", "settings"), ("GET", "export/activity.csv"), ("POST", "settings"),
              ("POST", "tickets/T-x"), ("POST", "import/vendors")]


# 1, 3, 17. Hide keys; nothing secret reaches the browser; trimmed responses
def test_static_and_api_responses_carry_no_secrets(app, world):
    reg, client = app
    c = client()
    assert c.login("admin@acme.com")[0] == 200
    blobs = [c.req("GET", p)[1] for p in ("/", "/app.js", "/app.css")]
    for route in ("me", "overview", "tickets", "activity", "audit", "vendors", "settings"):
        blobs.append(json.dumps(c.req("GET", "/api/web/" + route)[1]))
    text = " ".join(b if isinstance(b, str) else b.decode() for b in blobs)
    for secret in (ACCT_A, "GB33BUKB20201555555555", "scrypt$", "BEGIN PRIVATE", "password_hash", '"sig"', "receipt"):
        assert secret not in text, secret
    assert not re.search(r"\b(ack|apk)_[a-z0-9-]+_[A-Za-z0-9_-]{20,}", text)  # no agent or approver keys
    assert "...4567" in text  # last four digits only
    keys = (world[1] / "keys.json").read_text()
    assert "ack_" not in keys and "apk_" not in keys  # only hashes stored


# 2. No secrets committed
def test_repository_files_contain_no_secrets():
    root = os.path.join(os.path.dirname(__file__), "..")
    pattern = re.compile(r"(BEGIN [A-Z ]*PRIVATE KEY|ack_[a-z0-9-]+_[A-Za-z0-9_-]{30,}|apk_[a-z0-9-]+_[A-Za-z0-9_-]{30,}"
                         r"|ghp_[A-Za-z0-9]{30,}|sk-ant-[A-Za-z0-9-]{20,})")
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", "dist")]
        for f in files:
            if f.endswith((".py", ".js", ".md", ".toml", ".yml", ".json", ".html", ".css", ".csv", ".txt")):
                with open(os.path.join(base, f), encoding="utf-8", errors="ignore") as fh:
                    assert not pattern.search(fh.read()), f


# 4, 7. One company never sees another's data; roles are enforced
def test_company_isolation_and_roles(app):
    reg, client = app
    a, b = client(), client()
    a.login("approver@acme.com"); b.login("admin@beta.com")
    acme_ticket = a.req("GET", "/api/web/tickets")[1]["tickets"][0]["ticket_id"]
    assert all(t["ticket_id"] != acme_ticket for t in b.req("GET", "/api/web/tickets")[1]["tickets"])
    assert b.req("POST", f"/api/web/tickets/{acme_ticket}", {"approve": True})[0] == 404
    aud = client(); aud.login("audit@acme.com")
    assert aud.req("POST", f"/api/web/tickets/{acme_ticket}", {"approve": True})[0] == 403
    assert a.req("POST", "/api/web/settings", {"mode": "shadow"})[0] == 403  # approver isn't admin
    assert aud.req("GET", "/api/web/audit")[0] == 200
    assert reg.gateway("acme").org.store.ticket(acme_ticket)["status"] == "open"


# 5. Sensitive data encrypted at rest; ciphertext can't be moved between rows
def test_bank_details_encrypted_at_rest(world):
    reg, home = world
    for f in ("books.db", "ledger.db"):
        raw = (home / "orgs" / "acme" / f).read_bytes()
        wal = home / "orgs" / "acme" / (f + "-wal")
        raw += wal.read_bytes() if wal.exists() else b""
        assert ACCT_A.encode() not in raw and b"GB33BUKB20201555555555" not in raw, f
    store = reg.gateway("acme").org.store
    store.upsert_vendor(Vendor("V2", "Other", "US999", (), date(2024, 1, 1)))
    stolen = store.q("SELECT bank_account FROM vendors WHERE vendor_id = 'V1'")[0][0]
    store.q("UPDATE vendors SET bank_account = ? WHERE vendor_id = 'V2'", (stolen,))
    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
        store.vendor("V2")  # associated data binds it to V1


# 6. Every web route needs a session, checked on the server
@pytest.mark.parametrize("method,route", WEB_ROUTES)
def test_every_route_requires_sign_in(app, method, route):
    _, client = app
    status, body, _ = client().req(method, "/api/web/" + route, {} if method == "POST" else None)
    assert status == 401


# 8. Field tampering refused
@pytest.mark.parametrize("route,body", [
    ("login", {"email": "admin@acme.com", "password": PW, "org_id": "beta"}),
    ("login", {"email": "admin@acme.com", "password": PW, "role": "admin"}),
    ("settings", {"mode": "enforce", "org_id": "beta"}),
    ("settings", {"agents": {}}),
    ("tickets/T-x", {"approve": True, "approver": "cfo@acme.com"}),
])
def test_unknown_fields_refused(app, route, body):
    _, client = app
    c = client()
    if route != "login":
        c.login("admin@acme.com")
    assert c.req("POST", "/api/web/" + route, body)[0] == 422


# 9. Session cookie attributes, hashed tokens, logout, idle expiry
def test_session_cookie_hardening(world):
    reg, home = world
    srv = serve(reg, ServerConfig(secure_cookies=True))
    try:
        c = Client("127.0.0.1", srv.server_address[1])
        status, _, r = c.login("admin@acme.com")
        cookie = r.getheader("Set-Cookie")
        assert status == 200 and cookie.startswith("__Host-cp_session=")
        for attr in ("HttpOnly", "SameSite=Strict", "Secure", "Path=/"):
            assert attr in cookie
        assert "Domain=" not in cookie
        token = c.cookie.split("=", 1)[1]
        rows = sqlite3.connect(str(home / "web.db")).execute("SELECT token_hash FROM sessions").fetchall()
        assert all(token not in r[0] for r in rows)  # only the hash is stored
        assert c.req("GET", "/api/web/me")[0] == 200
        saved = c.cookie
        c.req("POST", "/api/web/logout")
        c.cookie = saved
        assert c.req("GET", "/api/web/me")[0] == 401  # logged-out token is dead
    finally:
        srv.shutdown()


def test_idle_sessions_expire(tmp_path):
    acc = Accounts(str(tmp_path / "w.db"), os.urandom(32))
    acc.create_user("a@x.com", "acme", "admin", PW)
    token = acc.login("a@x.com", PW, "1.1.1.1").token
    old = (dt.datetime.now(dt.UTC) - dt.timedelta(minutes=31)).isoformat()
    acc.db.execute("UPDATE sessions SET last_seen = ?", (old,))
    assert acc.session(token) is None


def test_password_change_and_disable_end_sessions(tmp_path):
    acc = Accounts(str(tmp_path / "w.db"), os.urandom(32))
    acc.create_user("a@x.com", "acme", "admin", PW)
    t1 = acc.login("a@x.com", PW, "ip").token
    acc.set_password("a@x.com", "another-long-pass-42")
    assert acc.session(t1) is None
    t2 = acc.login("a@x.com", "another-long-pass-42", "ip").token
    acc.set_disabled("a@x.com", True)
    assert acc.session(t2) is None
    with pytest.raises(AuthError):
        acc.login("a@x.com", "another-long-pass-42", "ip")


# 10. Passwords hashed with scrypt; weak ones refused; no user enumeration
def test_password_hashing_and_policy(tmp_path, world):
    h = hash_password(PW)
    assert h.startswith("scrypt$16384$8$1$") and PW not in h and hash_password(PW) != h  # salted
    acc = Accounts(str(tmp_path / "w.db"), os.urandom(32))
    for weak in ("short", "password123", "aaaaaaaaaaaaaa", "jonathan-1234567"):
        with pytest.raises(AuthError):
            acc.create_user("jonathan@x.com", "acme", "admin", weak)
    stored = sqlite3.connect(str(world[1] / "web.db")).execute("SELECT password_hash FROM users").fetchall()
    assert all(r[0].startswith("scrypt$") for r in stored)


def test_unknown_user_and_wrong_password_look_the_same(app):
    _, client = app
    s1, b1, _ = client().login("nobody@acme.com", "whatever-long-1")
    s2, b2, _ = client().login("admin@acme.com", "wrong-password-1")
    assert (s1, b1) == (s2, b2) == (401, {"error": "Email or password is incorrect."})


# 11. Sign-in rate limit
def test_login_rate_limit(app):
    _, client = app
    c = client()
    for _ in range(5):
        assert c.login("admin@acme.com", "wrong-password-xx")[0] == 401
    status, body, _ = c.login("admin@acme.com")  # even the right password now
    assert status == 429 and "Too many attempts" in body["error"]
    assert client().login("approver@acme.com")[0] == 200  # other accounts unaffected


def test_api_rate_limit(world):
    reg, _ = world
    srv = serve(reg, ServerConfig(secure_cookies=False, requests_per_minute=5))
    try:
        c = Client("127.0.0.1", srv.server_address[1])
        c.login("admin@acme.com")
        codes = [c.req("GET", "/api/web/me")[0] for _ in range(8)]
        assert codes[:4] == [200] * 4 and 429 in codes
    finally:
        srv.shutdown()


# 12. Bot protection: honeypot field, no session for bots
def test_honeypot_blocks_bots(app):
    _, client = app
    c = client()
    status, _, r = c.req("POST", "/api/web/login", {"email": "admin@acme.com", "password": PW, "website": "http://spam"})
    assert status == 401 and not r.getheader("Set-Cookie")


# 13. Parameterized queries: injection strings are just text
def test_sql_injection_is_inert(app):
    reg, client = app
    c = client()
    assert c.login("admin@acme.com' OR '1'='1", "x' OR '1'='1' --")[0] == 401
    c.login("admin@acme.com")
    status, body, _ = c.req("GET", "/api/web/activity?q=%27%20OR%201%3D1%20--")
    assert status == 200 and body["rows"] == []
    assert reg.gateway("acme").org.store.vendor("V1' OR '1'='1") is None


def test_sql_is_never_built_from_input():
    """Every f-string SQL in the code interpolates only module constants or fixed clauses."""
    src = os.path.join(os.path.dirname(__file__), "..", "src", "agent_checkpoint")
    allowed = {"{_PAY_COLS}", "{table}", "{column}", "{ddl}"}  # the last three: the fixed ADDED list in accounts.py
    for f in os.listdir(src):
        if not f.endswith(".py"):
            continue
        text = open(os.path.join(src, f), encoding="utf-8").read()
        for m in re.finditer(r'(?:execute|q|_q)\(\s*f"([^"]*)"', text):
            for expr in re.findall(r"\{[^}]*\}", m.group(1)):
                assert expr in allowed, (f, expr)


# 14. Input validation
@pytest.mark.parametrize("body", [
    {"mode": "yolo"}, {"approval_limit": "-5"}, {"approval_limit": "1e9"}, {"recent_bank_change_days": 0},
    {"ticket_hours": "12"}, {"approval_limit": "60000", "dual_approval_limit": "100"},
])
def test_settings_validation(app, body):
    _, client = app
    c = client(); c.login("admin@acme.com")
    assert c.req("POST", "/api/web/settings", body)[0] == 422


def test_bad_query_and_body(app):
    _, client = app
    c = client(); c.login("admin@acme.com")
    assert c.req("GET", "/api/web/activity?verdict=drop%20table")[0] == 422
    assert c.req("POST", "/api/web/tickets/T-x", raw=b"{not json")[0] == 400
    assert c.req("POST", "/api/web/tickets/T-x", {"approve": "yes"})[0] == 422


# 15. User content escaped: CSV export can't run formulas; JSON is served as JSON
def test_csv_export_neutralises_formulas(app):
    _, client = app
    c = client(); c.login("audit@acme.com")
    status, body, r = c.req("GET", "/api/web/export/activity.csv")
    assert status == 200 and r.getheader("Content-Disposition").startswith("attachment")
    text = body.decode() if isinstance(body, bytes) else body
    assert "'=HYPERLINK" in text and ",=HYPERLINK" not in text


# 16. Uploads restricted
def test_upload_restrictions(app):
    _, client = app
    adm = client(); adm.login("admin@acme.com")
    ok = b"vendor_id,name,bank_account,email_domains,created_on,phone\nV9,New,US1,new.com,2024-01-01,1\n"
    assert adm.req("POST", "/api/web/import/vendors", raw=ok, ctype="text/csv")[1]["imported"] == 1
    assert adm.req("POST", "/api/web/import/vendors", raw=ok, ctype="application/x-msdownload")[0] == 415
    assert adm.req("POST", "/api/web/import/vendors", raw=b"\xff\xfe\x00bad", ctype="text/csv")[0] == 422
    assert adm.req("POST", "/api/web/import/vendors", raw=b"a,b\n" + b"\x00" * 10, ctype="text/csv")[0] == 422
    try:  # refused before the body is read; some systems reset the connection mid-send instead of showing the 413
        assert adm.req("POST", "/api/web/import/vendors", raw=b"x" * (1024 * 1024 + 1), ctype="text/csv")[0] == 413
    except (ConnectionResetError, BrokenPipeError):
        pass
    appr = client(); appr.login("approver@acme.com")
    assert appr.req("POST", "/api/web/import/vendors", raw=ok, ctype="text/csv")[0] == 403


# 18. Security headers
def test_security_headers(app):
    _, client = app
    c = client()
    for path in ("/", "/app.js", "/api/web/me", "/health"):
        _, _, r = c.req("GET", path)
        csp = r.getheader("Content-Security-Policy")
        assert "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert r.getheader("X-Content-Type-Options") == "nosniff"
        assert r.getheader("X-Frame-Options") == "DENY"
        assert r.getheader("Referrer-Policy") == "no-referrer"
        assert "camera=()" in r.getheader("Permissions-Policy")
        assert r.getheader("Server").strip() == "checkpoint"  # no version strings
    assert c.req("GET", "/api/web/me")[2].getheader("Cache-Control") == "no-store"
    assert "script-src 'self'" in c.req("GET", "/")[2].getheader("Content-Security-Policy")


def test_cross_site_requests_refused(app):
    _, client = app
    c = client(); c.login("admin@acme.com")
    assert c.req("GET", "/api/web/me", headers={"X-Requested-With": ""})[0] == 403
    assert c.req("POST", "/api/web/settings", {"mode": "shadow"}, headers={"Origin": "https://evil.example"})[0] == 403
    for method in ("PUT", "DELETE", "OPTIONS"):
        assert c.req(method, "/api/web/me")[0] == 405


# 19. HTTPS: redirect, HSTS, proxy headers only from trusted proxies, and built-in TLS
def test_force_https_and_hsts(world):
    reg, _ = world
    srv = serve(reg, ServerConfig(force_https=True, trusted_proxies=("127.0.0.1",)))
    try:
        port = srv.server_address[1]
        status, _, r = Client("127.0.0.1", port).req("GET", "/api/web/me", headers={"Host": "cp.example"})
        assert status == 308 and r.getheader("Location") == "https://cp.example/api/web/me"
        s2, _, r2 = Client("127.0.0.1", port, headers={"X-Forwarded-Proto": "https"}).req("GET", "/")
        assert s2 == 200 and "max-age=31536000" in r2.getheader("Strict-Transport-Security")
    finally:
        srv.shutdown()
    srv = serve(reg, ServerConfig(force_https=True, trusted_proxies=("10.9.9.9",)))
    try:  # an untrusted client can't claim https
        s3, _, _ = Client("127.0.0.1", srv.server_address[1], headers={"X-Forwarded-Proto": "https"}).req("GET", "/")
        assert s3 == 308
    finally:
        srv.shutdown()


def test_built_in_tls(world, tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    srv = serve(world[0], ServerConfig(), (str(tmp_path / "c.pem"), str(tmp_path / "k.pem")))
    try:
        ctx = ssl.create_default_context(cafile=str(tmp_path / "c.pem"))
        c = Client("localhost", srv.server_address[1], tls_ctx=ctx)
        status, _, r = c.login("admin@acme.com")
        assert status == 200 and "Secure" in r.getheader("Set-Cookie")
        assert r.getheader("Strict-Transport-Security")
        with socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=5) as s:
            s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")  # plain HTTP to a TLS port
            try:
                assert b"200 OK" not in s.recv(100)
            except ConnectionResetError:
                pass  # refused: what we want
        # A client that connects and says nothing must not block others.
        idle = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=5)
        assert Client("localhost", srv.server_address[1], tls_ctx=ctx).req("GET", "/health")[0] == 200
        idle.close()
    finally:
        srv.shutdown()


def test_approve_through_web_writes_audit_trail(app):
    reg, client = app
    c = client(); c.login("approver@acme.com")
    t = c.req("GET", "/api/web/tickets")[1]["tickets"][0]
    status, out, _ = c.req("POST", f"/api/web/tickets/{t['ticket_id']}", {"approve": True, "note": "Called them."})
    assert status == 200 and out["status"] == "approved"
    entries = reg.gateway("acme").org.ledger.entries("human_decision")
    assert entries[-1]["body"]["approver"] == "approver@acme.com" and entries[-1]["body"]["note"] == "Called them."
    assert "GB33BUKB20201555555555" not in json.dumps(reg.gateway("acme").org.ledger.entries())


def test_unread_bodies_never_leak_into_the_next_request(app):
    """Keep-alive: a body a route ignores (sign-out) must not be parsed as the next request."""
    _, client = app
    c = client()
    c.login("admin@acme.com")
    conn = http.client.HTTPConnection("127.0.0.1", c.port, timeout=10)
    h = {"X-Requested-With": "fetch", "Content-Type": "application/json", "Cookie": c.cookie}
    conn.request("POST", "/api/web/logout", body=b'{"ignored": true}', headers=h)
    assert conn.getresponse().read() is not None
    conn.request("POST", "/api/web/login", body=json.dumps({"email": "admin@acme.com", "password": PW}).encode(),
                 headers={"X-Requested-With": "fetch", "Content-Type": "application/json"})
    assert conn.getresponse().status == 200
    conn.close()
