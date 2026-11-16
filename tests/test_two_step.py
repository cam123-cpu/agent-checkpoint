"""Two-step sign-in: codes, replay, recovery codes, required-by-company, and the QR code."""

import os
import time

import pytest
from test_web_security import PW, Client, serve, world  # noqa: F401  (fixture)

from agent_checkpoint import qr, totp
from agent_checkpoint.accounts import Accounts, AuthError
from agent_checkpoint.server import ServerConfig


def test_rfc6238_vectors():
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    for t, want in ((59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (2000000000, "69279037")):
        assert totp.code_at(secret, t // 30, 8) == want


def test_codes_window_and_replay():
    s = totp.new_secret()
    now = 1_800_000_000
    step = int(now // 30)
    assert totp.verify(s, totp.code_at(s, step), None, now) == step
    assert totp.verify(s, totp.code_at(s, step - 1), None, now) == step - 1   # clock drift
    assert totp.verify(s, totp.code_at(s, step - 2), None, now) is None       # too old
    assert totp.verify(s, totp.code_at(s, step), step, now) is None           # replay
    assert totp.verify(s, "12345", None, now) is None


@pytest.fixture
def acc(tmp_path):
    a = Accounts(str(tmp_path / "w.db"), os.urandom(32))
    a.create_user("a@x.com", "acme", "admin", PW)
    return a


def enrol(acc):
    secret = acc.start_two_step("a@x.com")
    codes = acc.confirm_two_step("a@x.com", totp.code_at(secret, int(time.time() // 30)))
    return secret, codes


def test_enrol_then_sign_in_needs_a_code(acc):
    secret, codes = enrol(acc)
    assert len(codes) == 10 and len(set(codes)) == 10
    first = acc.login("a@x.com", PW, "ip")
    assert first.kind == "two_step" and first.user is None  # no session from the password alone
    with pytest.raises(AuthError):
        acc.login_second_step(first.token, "000000", "ip")
    # The enrolment code's step is used; the next one is needed.
    nxt = totp.code_at(secret, int(time.time() // 30) + 1)
    done = acc.login_second_step(first.token, nxt, "ip")
    assert done.kind == "session" and acc.session(done.token).two_step
    with pytest.raises(AuthError):  # pending token is single use
        acc.login_second_step(first.token, nxt, "ip")
    again = acc.login("a@x.com", PW, "ip2")
    with pytest.raises(AuthError):  # same code can't be replayed for a new sign-in
        acc.login_second_step(again.token, nxt, "ip2")


def test_recovery_codes_work_once(acc):
    _, codes = enrol(acc)
    p = acc.login("a@x.com", PW, "ip")
    assert acc.login_second_step(p.token, codes[0].upper().replace("-", " "), "ip").kind == "session"
    p = acc.login("a@x.com", PW, "ip")
    with pytest.raises(AuthError):
        acc.login_second_step(p.token, codes[0], "ip")
    assert acc.recovery_codes_left("a@x.com") == 9


def test_pending_token_allows_only_five_tries(acc):
    enrol(acc)
    p = acc.login("a@x.com", PW, "ip")
    for _ in range(4):
        with pytest.raises(AuthError):
            acc.login_second_step(p.token, "000000", "ip")
    with pytest.raises(AuthError) as e:  # fifth failure also hits the per-address limit
        acc.login_second_step(p.token, "000000", "ip")
    with pytest.raises(AuthError) as e:
        acc.login_second_step(p.token, "000000", "ip")
    assert e.value.status in (401, 429)


def test_secret_and_codes_are_not_stored_in_clear(acc, tmp_path):
    secret, codes = enrol(acc)
    raw = (tmp_path / "w.db").read_bytes()
    wal = tmp_path / "w.db-wal"
    raw += wal.read_bytes() if wal.exists() else b""
    assert secret.encode() not in raw and codes[0].encode() not in raw


def test_disable_needs_password_and_code(acc):
    secret, codes = enrol(acc)
    with pytest.raises(AuthError):
        acc.disable_two_step("a@x.com", "wrong-password-1", codes[0])
    acc.disable_two_step("a@x.com", PW, codes[1])
    assert acc.login("a@x.com", PW, "ip").kind == "session"


def test_required_two_step_gives_a_limited_session(acc):
    r = acc.login("a@x.com", PW, "ip", require_two_step=lambda org: org == "acme")
    assert r.kind == "session" and r.user.limited and acc.session(r.token).limited
    other = acc.login("a@x.com", PW, "ip2", require_two_step=lambda org: org == "acme")  # another limited session
    secret = acc.start_two_step("a@x.com")
    acc.confirm_two_step("a@x.com", totp.code_at(secret, int(time.time() // 30)), r.token)
    assert not acc.session(r.token).limited  # the session that proved the code
    assert acc.session(other.token) is None  # every other password-only session is ended


# --- through the server --------------------------------------------------------------

def test_web_flow_end_to_end(world):  # noqa: F811
    reg, _ = world
    srv = serve(reg, ServerConfig(secure_cookies=False))
    try:
        c = Client("127.0.0.1", srv.server_address[1])
        c.login("admin@acme.com")
        s = c.req("POST", "/api/web/two-step/start", {})[1]
        assert s["qr"].startswith("data:image/svg+xml;base64,") and s["uri"].startswith("otpauth://totp/")
        secret = s["key"].replace(" ", "")
        assert c.req("POST", "/api/web/two-step/confirm", {"code": "000000"})[0] == 422
        out = c.req("POST", "/api/web/two-step/confirm", {"code": totp.code_at(secret, int(time.time() // 30))})[1]
        assert len(out["recovery_codes"]) == 10
        # Require it for the company; an approver without it is limited to set-up.
        assert c.req("POST", "/api/web/settings", {"require_two_step": True})[0] == 200
        a = Client("127.0.0.1", srv.server_address[1])
        assert a.login("approver@acme.com")[0] == 200
        assert a.req("GET", "/api/web/me")[1]["setup_required"] is True
        assert a.req("GET", "/api/web/tickets")[0] == 403
        # A password-only session can't change the password either: that would let someone with a stolen password
        # lock the owner out before two-step is set up.
        assert a.req("POST", "/api/web/password", {"current": PW, "new": "another-long-password-1"})[0] == 403
        # A fresh sign-in for the admin now needs the code.
        b = Client("127.0.0.1", srv.server_address[1])
        status, body, r = b.login("admin@acme.com")
        assert status == 200 and body["two_step_required"] and not r.getheader("Set-Cookie")
        assert b.req("GET", "/api/web/me")[0] == 401
        code = totp.code_at(secret, int(time.time() // 30) + 1)
        assert b.req("POST", "/api/web/login/two-step", {"pending": body["pending"], "code": code})[0] == 200
        assert b.req("GET", "/api/web/me")[1]["two_step"] is True
        # Can't be turned off while the company requires it.
        assert b.req("POST", "/api/web/two-step/disable", {"password": PW, "code": out["recovery_codes"][0]})[0] == 403
        # An admin can't require it before having it themselves (no self-lockout).
        beta = Client("127.0.0.1", srv.server_address[1]); beta.login("admin@beta.com")
        assert beta.req("POST", "/api/web/settings", {"require_two_step": True})[0] == 422
    finally:
        srv.shutdown()


def test_password_change_signs_out_everywhere(world):  # noqa: F811
    reg, _ = world
    srv = serve(reg, ServerConfig(secure_cookies=False))
    try:
        port = srv.server_address[1]
        one, two = Client("127.0.0.1", port), Client("127.0.0.1", port)
        one.login("admin@acme.com"); two.login("admin@acme.com")
        assert one.req("POST", "/api/web/password", {"current": "wrong-password-1", "new": "a-brand-new-pass-77"})[0] == 403
        assert one.req("POST", "/api/web/password", {"current": PW, "new": "short"})[0] == 422
        assert one.req("POST", "/api/web/password", {"current": PW, "new": "a-brand-new-pass-77"})[0] == 200
        assert two.req("GET", "/api/web/me")[0] == 401
        assert Client("127.0.0.1", port).login("admin@acme.com", "a-brand-new-pass-77")[0] == 200
    finally:
        srv.shutdown()


def test_qr_codes_scan():
    cv2 = pytest.importorskip("cv2")
    np = pytest.importorskip("numpy")
    det = cv2.QRCodeDetector()
    ok = 0
    for i in range(60):
        uri = totp.otpauth_uri(totp.new_secret(), f"person{i}@acme-manufacturing.example")
        m = qr.encode(uri)
        n, sc, q = len(m), 6, 4
        img = np.full(((n + 2 * q) * sc,) * 2, 255, np.uint8)
        for y in range(n):
            for x in range(n):
                if m[y][x]:
                    img[(y + q) * sc:(y + q + 1) * sc, (x + q) * sc:(x + q + 1) * sc] = 0
        ok += det.detectAndDecode(img)[0] == uri
    assert ok >= 55  # every mask is valid; OpenCV is pickier than phone cameras about a few
