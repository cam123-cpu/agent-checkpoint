"""Single sign-on against a fake identity provider with real RSA-signed tokens."""

import base64
import json
import threading
import time
import urllib.parse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from test_web_security import Client, world  # noqa: F401

from agent_checkpoint.oidc import OIDC, SSOConfig, SSOError
from agent_checkpoint.server import ServerConfig, make_server

TENANT = "11111111-2222-3333-4444-555555555555"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
CLIENT = "client-123"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk(key, kid):
    nums = key.public_key().public_numbers()
    n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "kid": kid, "n": b64(n), "e": b64(nums.e.to_bytes(3, "big")), "alg": "RS256", "use": "sig"}


class FakeIdP:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "k1"
        self.claims = {}
        self.issued = []
        self.header = {"alg": "RS256", "kid": "k1", "typ": "JWT"}
        self.tamper = None

    def sign(self, claims, header=None, key=None):
        h = b64(json.dumps(header or self.header).encode())
        p = b64(json.dumps(claims).encode())
        sig = (key or self.key).sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{p}.{b64(sig)}"

    def get_json(self, url):
        if url.endswith("openid-configuration"):
            return {"issuer": ISSUER, "authorization_endpoint": "https://idp.example/authorize",
                    "token_endpoint": "https://idp.example/token", "jwks_uri": "https://idp.example/keys"}
        return {"keys": [jwk(self.key, self.kid)]}

    def post_form(self, url, data):
        self.issued.append(data)
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT, "exp": now + 600, "iat": now, "nbf": now, "tid": TENANT,
                  "nonce": self.nonce, "preferred_username": self.email, **self.claims}
        token = self.sign(claims)
        return {"id_token": self.tamper(token) if self.tamper else token}


@pytest.fixture
def idp():
    return FakeIdP()


@pytest.fixture
def site(world, idp):  # noqa: F811
    reg, _ = world
    SSOConfig("microsoft", CLIENT, TENANT, "acme.com").save(reg.org_dir("acme"), "secret-xyz")
    srv = make_server(reg, "127.0.0.1", 0, ServerConfig(secure_cookies=False), oidc=OIDC(idp.get_json, idp.post_form))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield reg, srv.server_address[1]
    srv.shutdown()


def start(port, org="acme"):
    c = Client("127.0.0.1", port)
    status, _, r = c.req("GET", f"/auth/sso/start?org={org}")
    loc = r.getheader("Location")
    binding = (r.getheader("Set-Cookie") or "").split(";")[0]
    return c, status, loc, binding


def callback(c, binding, state, code="the-code", extra=""):
    c.cookie = binding
    return c.req("GET", f"/auth/sso/callback?code={code}&state={urllib.parse.quote(state)}{extra}")


def test_happy_path(site, idp):
    reg, port = site
    c, status, loc, binding = start(port)
    assert status == 302 and loc.startswith("https://idp.example/authorize?")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
    assert q["client_id"] == CLIENT and q["code_challenge_method"] == "S256" and q["redirect_uri"].endswith("/auth/sso/callback")
    assert "SameSite=Lax" in binding or binding.startswith("cp_sso=")
    idp.nonce, idp.email = q["nonce"], "approver@acme.com"
    status, _, r = callback(c, binding, q["state"])
    assert status == 302 and r.getheader("Location") == "/#approvals"
    cookies = r.headers.get_all("Set-Cookie")
    session = next(x for x in cookies if x.startswith("cp_session="))
    assert "HttpOnly" in session and "SameSite=Strict" in session
    c.cookie = session.split(";")[0]
    me = c.req("GET", "/api/web/me")[1]
    assert me["email"] == "approver@acme.com"
    # PKCE: the verifier sent to the token endpoint hashes to the challenge sent to the browser
    import hashlib
    v = idp.issued[-1]["code_verifier"]
    assert b64(hashlib.sha256(v.encode()).digest()) == q["code_challenge"]
    assert idp.issued[-1]["client_secret"] == "secret-xyz"


def _fails(site, idp, *, email="approver@acme.com", claims=None, tamper=None, header=None, reuse=False,
           wrong_binding=False, nonce=None, error=""):
    reg, port = site
    c, _, loc, binding = start(port)
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
    idp.nonce, idp.email, idp.claims, idp.tamper = nonce or q["nonce"], email, claims or {}, tamper
    if header:
        idp.header = header
    if reuse:
        callback(c, binding, q["state"])
    status, _, r = callback(c, "cp_sso=someone-else" if wrong_binding else binding, q["state"], extra=error)
    loc = r.getheader("Location")
    assert status == 302 and loc.startswith("/?sso_error="), loc
    assert not any(x.startswith("cp_session=") and "Max-Age=0" not in x for x in r.headers.get_all("Set-Cookie") or [])
    return urllib.parse.unquote(loc.split("=", 1)[1])


def test_rejections(site, idp):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    assert "Ask an admin" in _fails(site, idp, email="stranger@acme.com")             # not added
    assert "domain" in _fails(site, idp, email="someone@evil.com")                     # wrong domain
    _fails(site, idp, claims={"aud": "another-app"})                                    # audience
    _fails(site, idp, claims={"iss": "https://login.microsoftonline.com/other/v2.0"})   # issuer
    _fails(site, idp, claims={"exp": now - 3600})                                       # expired
    _fails(site, idp, claims={"iat": now + 3600})                                       # from the future
    _fails(site, idp, claims={"tid": "99999999-0000-0000-0000-000000000000"})          # other tenant
    _fails(site, idp, nonce="not-the-nonce")                                            # replayed token
    _fails(site, idp, tamper=lambda t: t[:-6] + ("AAAAAA" if not t.endswith("AAAAAA") else "BBBBBB"))  # bad signature
    _fails(site, idp, tamper=lambda t: FakeIdP.sign(idp, json.loads(base64.urlsafe_b64decode(
        t.split(".")[1] + "==")), key=other_key))                                       # signed by someone else
    _fails(site, idp, header={"alg": "none", "kid": "k1"})                              # alg none
    _fails(site, idp, header={"alg": "HS256", "kid": "k1"})                             # alg confusion
    idp.header = {"alg": "RS256", "kid": "k1", "typ": "JWT"}
    assert "already used" in _fails(site, idp, reuse=True)                              # state single use
    assert "already used" in _fails(site, idp, wrong_binding=True)                      # other browser
    assert "provider" in _fails(site, idp, error="&error=access_denied")


def test_user_from_another_company_cannot_sign_in(site, idp):
    reg, port = site
    reg.accounts().create_user("x@acme.com", "beta", "approver", "correct-horse-staple-91")
    assert "Ask an admin" in _fails(site, idp, email="x@acme.com")


def test_key_rotation_is_followed(site, idp):
    reg, port = site
    c, _, loc, binding = start(port)            # caches the old key set
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
    idp.key, idp.kid = rsa.generate_private_key(public_exponent=65537, key_size=2048), "k2"
    idp.header = {"alg": "RS256", "kid": "k2"}
    idp.nonce, idp.email = q["nonce"], "approver@acme.com"
    assert callback(c, binding, q["state"])[2].getheader("Location") == "/#approvals"


def test_config_refuses_multi_tenant_and_http():
    for tenant in ("common", "organizations", "consumers", ""):
        with pytest.raises(ValueError):
            SSOConfig("microsoft", CLIENT, tenant)
    with pytest.raises(ValueError):
        SSOConfig("oidc", CLIENT, issuer="http://plain.example")


def test_google_rules():
    cfg = SSOConfig("google", CLIENT, domain="acme.com")
    assert OIDC.email_from({"email": "A@acme.com", "email_verified": True, "hd": "acme.com"}, cfg) == "a@acme.com"
    for bad in ({"email": "a@acme.com", "email_verified": False, "hd": "acme.com"},
                {"email": "a@acme.com", "email_verified": True},
                {"email": "a@gmail.com", "email_verified": True, "hd": "acme.com"}):
        with pytest.raises(SSOError):
            OIDC.email_from(bad, cfg)


def test_sso_button_lookup(site):
    reg, port = site
    c = Client("127.0.0.1", port)
    assert c.req("GET", "/api/web/sso?org=acme")[1] == {"enabled": True, "label": "Microsoft"}
    assert c.req("GET", "/api/web/sso?org=beta")[1]["enabled"] is False
    assert c.req("GET", "/api/web/sso?org=../../etc")[1]["enabled"] is False
    status, _, r = Client("127.0.0.1", port).req("GET", "/auth/sso/start?org=beta")
    assert status == 302 and r.getheader("Location").startswith("/?sso_error=")
