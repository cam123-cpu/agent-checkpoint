"""Company single sign-on with OpenID Connect: Microsoft Entra ID, Google Workspace, or any OIDC provider.

The authorization code flow with PKCE:

    browser → /auth/sso/start?org=acme
        server makes state, nonce and a PKCE verifier, stores them (state and verifier encrypted,
        bound to this browser by a short-lived cookie), redirects to the provider
    provider → /auth/sso/callback?code=...&state=...
        server checks state (single use, not expired, same browser), swaps the code + verifier for
        an ID token, verifies the token's RS256 signature against the provider's published keys
        and its claims (issuer, audience, expiry, nonce), then signs in the person *only if an
        admin already added them to that company*. SSO never creates accounts.

Provider rules:
- Microsoft: your own tenant only. The multi-tenant endpoints (common, organizations,
  consumers) are refused, so a stranger's Microsoft account can't get in. The person is
  identified by their directory sign-in name (preferred_username), not the optional email claim,
  which a user can edit in some tenants. The token's tenant id must match.
- Google: the email must be verified, and if you set a domain, the Workspace domain (hd) must match.
- Generic OIDC: the email must be verified.

Sign-ins through SSO count as two-step: the provider applies the company's own second factor.
Network calls are passed in, so tests run against a fake provider with real RSA signatures.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MULTI_TENANT = {"common", "organizations", "consumers"}
SKEW = 120  # seconds of clock difference tolerated


class SSOError(Exception):
    """`code` is one of a fixed set, so nothing from the request is ever shown back to the person."""

    MESSAGES = {
        "not_configured": "Single sign-on isn't set up for this company.",
        "expired": "That sign-in took too long or was already used. Start again.",
        "provider": "The sign-in provider didn't complete the sign-in. Start again.",
        "token": "The sign-in couldn't be verified. Start again, or ask an admin to check the SSO settings.",
        "no_account": "Your company account isn't set up in Checkpoint yet. Ask an admin to add you.",
        "domain": "That account isn't from your company's domain.",
    }

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code = code

    @property
    def message(self) -> str:
        return self.MESSAGES.get(self.code, self.MESSAGES["token"])


@dataclass(frozen=True)
class SSOConfig:
    provider: str            # microsoft | google | oidc
    client_id: str
    tenant: str = ""         # microsoft: tenant id (a GUID) or verified domain
    domain: str = ""         # optional: only emails at this domain (google: also the hd claim)
    issuer: str = ""         # oidc: the issuer URL

    def __post_init__(self):
        if self.provider not in ("microsoft", "google", "oidc"):
            raise ValueError("provider must be microsoft, google or oidc")
        if not self.client_id:
            raise ValueError("client_id is required")
        if self.provider == "microsoft" and (not self.tenant or self.tenant.lower() in MULTI_TENANT):
            raise ValueError("Microsoft needs your own tenant id; common, organizations and consumers are refused")
        if self.provider == "oidc" and not self.issuer.startswith("https://"):
            raise ValueError("oidc needs an https issuer URL")

    @property
    def label(self) -> str:
        return {"microsoft": "Microsoft", "google": "Google", "oidc": "your company account"}[self.provider]

    @property
    def discovery_url(self) -> str:
        if self.provider == "microsoft":
            return f"https://login.microsoftonline.com/{urllib.parse.quote(self.tenant)}/v2.0/.well-known/openid-configuration"
        if self.provider == "google":
            return "https://accounts.google.com/.well-known/openid-configuration"
        return self.issuer.rstrip("/") + "/.well-known/openid-configuration"

    @classmethod
    def load(cls, org_dir: str) -> tuple[SSOConfig, str] | None:
        path = os.path.join(org_dir, "sso.json")
        if not os.path.exists(path):
            return None
        with open(path) as f:
            cfg = cls(**json.load(f))
        with open(os.path.join(org_dir, "sso.secret")) as f:
            return cfg, f.read().strip()

    def save(self, org_dir: str, client_secret: str) -> None:
        with open(os.path.join(org_dir, "sso.json"), "w") as f:
            json.dump(asdict(self), f, indent=2)
        path = os.path.join(org_dir, "sso.secret")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(client_secret)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _https_only(url: str) -> str:
    if not url.startswith("https://"):
        raise SSOError("token", f"refusing non-https endpoint {url[:60]}")
    return url


def _get_json(url: str) -> dict:  # pragma: no cover - network
    with urllib.request.urlopen(urllib.request.Request(_https_only(url), headers={"Accept": "application/json"}),
                                timeout=10) as r:
        return json.loads(r.read(2_000_000))


def _post_form(url: str, data: dict) -> dict:  # pragma: no cover - network
    req = urllib.request.Request(_https_only(url), data=urllib.parse.urlencode(data).encode(), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read(2_000_000))
    except urllib.error.HTTPError as exc:
        raise SSOError("provider", f"token endpoint said {exc.code}") from exc


class OIDC:
    def __init__(self, get_json=_get_json, post_form=_post_form, clock=time.time):
        self.get_json, self.post_form, self.clock = get_json, post_form, clock
        self._cache: dict[str, tuple[float, dict]] = {}

    def _cached(self, url: str, force: bool = False) -> dict:
        hit = self._cache.get(url)
        if hit and not force and self.clock() - hit[0] < 3600:
            return hit[1]
        try:
            doc = self.get_json(url)
        except SSOError:
            raise
        except Exception as exc:
            raise SSOError("provider", f"couldn't fetch {url[:80]}") from exc
        self._cache[url] = (self.clock(), doc)
        return doc

    def discovery(self, cfg: SSOConfig) -> dict:
        d = self._cached(cfg.discovery_url)
        for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not isinstance(d.get(k), str):
                raise SSOError("provider", f"discovery document has no {k}")
        return d

    def authorize_url(self, cfg: SSOConfig, redirect_uri: str, state: str, nonce: str, verifier: str) -> str:
        d = self.discovery(cfg)
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        params = {"response_type": "code", "client_id": cfg.client_id, "redirect_uri": redirect_uri,
                  "scope": "openid email profile", "state": state, "nonce": nonce, "code_challenge": challenge,
                  "code_challenge_method": "S256", "prompt": "select_account", "response_mode": "query"}
        if cfg.provider == "google" and cfg.domain:
            params["hd"] = cfg.domain
        return d["authorization_endpoint"] + ("&" if "?" in d["authorization_endpoint"] else "?") + urllib.parse.urlencode(params)

    def finish(self, cfg: SSOConfig, secret: str, redirect_uri: str, code: str, verifier: str, nonce: str) -> str:
        """Swap the code for an ID token, verify it, and return the person's verified email."""
        d = self.discovery(cfg)
        tokens = self.post_form(d["token_endpoint"], {
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": cfg.client_id, "client_secret": secret, "code_verifier": verifier})
        id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
        if not isinstance(id_token, str):
            raise SSOError("provider", "no id_token in the token response")
        claims = self.verify(id_token, cfg, d, nonce)
        return self.email_from(claims, cfg)

    def _key(self, d: dict, kid: str):
        for force in (False, True):  # unknown key id: the provider may have rotated keys
            for k in self._cached(d["jwks_uri"], force).get("keys", []):
                if k.get("kid") == kid and k.get("kty") == "RSA":
                    n = int.from_bytes(_b64url_decode(k["n"]), "big")
                    e = int.from_bytes(_b64url_decode(k["e"]), "big")
                    return rsa.RSAPublicNumbers(e, n).public_key()
        raise SSOError("token", "signing key not found")

    def verify(self, token: str, cfg: SSOConfig, d: dict, nonce: str) -> dict:
        try:
            head_b64, body_b64, sig_b64 = token.split(".")
            header = json.loads(_b64url_decode(head_b64))
            claims = json.loads(_b64url_decode(body_b64))
            sig = _b64url_decode(sig_b64)
        except (ValueError, json.JSONDecodeError) as exc:
            raise SSOError("token", "malformed ID token") from exc
        if header.get("alg") != "RS256":
            raise SSOError("token", f"refusing alg {header.get('alg')!r}")
        key = self._key(d, str(header.get("kid", "")))
        try:
            key.verify(sig, f"{head_b64}.{body_b64}".encode(), padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature as exc:
            raise SSOError("token", "bad signature") from exc
        now = self.clock()
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        checks = [
            (claims.get("iss") == d["issuer"], "issuer"),
            (cfg.client_id in auds, "audience"),
            (len(auds) == 1 or claims.get("azp") == cfg.client_id, "authorized party"),
            (isinstance(claims.get("exp"), int | float) and now < claims["exp"] + SKEW, "expired"),
            (isinstance(claims.get("iat"), int | float) and claims["iat"] < now + SKEW, "issued in the future"),
            (not isinstance(claims.get("nbf"), int | float) or claims["nbf"] < now + SKEW, "not yet valid"),
            (isinstance(claims.get("nonce"), str) and secrets.compare_digest(claims["nonce"], nonce), "nonce"),
        ]
        for ok, what in checks:
            if not ok:
                raise SSOError("token", what)
        return claims

    @staticmethod
    def email_from(claims: dict, cfg: SSOConfig) -> str:
        if cfg.provider == "microsoft":
            if str(claims.get("tid", "")).lower() != cfg.tenant.lower() and "." not in cfg.tenant:
                raise SSOError("token", "different tenant")
            email = claims.get("preferred_username") or claims.get("upn") or ""
        else:
            if claims.get("email_verified") not in (True, "true"):
                raise SSOError("token", "email not verified")
            email = claims.get("email") or ""
            if cfg.provider == "google" and cfg.domain and claims.get("hd") != cfg.domain:
                raise SSOError("domain", "hd")
        email = str(email).strip().lower()
        if "@" not in email:
            raise SSOError("token", "no email")
        if cfg.domain and not email.endswith("@" + cfg.domain.lower()):
            raise SSOError("domain", email.split("@")[1])
        return email


def new_flow() -> tuple[str, str, str, str]:
    """state, nonce, PKCE verifier, and the browser-binding value for the cookie."""
    return (secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48), secrets.token_urlsafe(32))
