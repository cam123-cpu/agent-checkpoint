#!/usr/bin/env python3
"""Check a deployed checkpoint from the outside, the way an attacker on the internet sees it.

    python3 deploy/external_check.py https://checkpoint.example.com
    python3 deploy/external_check.py https://checkpoint.example.com --login-limit throwaway@example.com

Standard library only, so it runs on any machine with Python 3.10+. Run it from a different network
than the server (a laptop, not the server itself), after every deploy and before any outside pen test.
It is a smoke test, not a pen test: it confirms the basics are in place so a paid tester spends their
time on what a script can't find.

Only run it against a server you own or have written permission to test. --login-limit sends failed
sign-ins for the email you give, which locks that email (and your address) out for 15 minutes.
"""

from __future__ import annotations

import argparse
import http.client
import json
import secrets
import socket
import ssl
import sys
import urllib.parse
from datetime import UTC, datetime

# Ports that should never answer on a checkpoint server: the app itself, databases, admin panels.
EXPOSED_PORTS = {8077: "checkpoint (should be behind Caddy only)", 2019: "Caddy admin API", 5432: "PostgreSQL",
                 3306: "MySQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 2375: "Docker API",
                 8080: "alternate HTTP", 8000: "alternate HTTP", 5000: "dev server", 11211: "memcached"}


class Check:
    def __init__(self):
        self.results: list[tuple[str, str, str]] = []

    def ok(self, name, detail=""):
        self.results.append(("PASS", name, detail))

    def fail(self, name, detail=""):
        self.results.append(("FAIL", name, detail))

    def warn(self, name, detail=""):
        self.results.append(("WARN", name, detail))

    def that(self, cond, name, detail=""):
        (self.ok if cond else self.fail)(name, detail)


def request(host, port, method, path, *, ctx, body=None, headers=None, tls=True, timeout=10):
    conn = (http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout) if tls
            else http.client.HTTPConnection(host, port, timeout=timeout))
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        data = r.read(200_000)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.headers.get_all("Set-Cookie") or [], data
    finally:
        conn.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="https://your-checkpoint-domain")
    ap.add_argument("--insecure", action="store_true", help="accept a self-signed certificate (testing only)")
    ap.add_argument("--skip-http", action="store_true", help="don't check that port 80 redirects to HTTPS")
    ap.add_argument("--skip-ports", action="store_true", help="don't probe other ports")
    ap.add_argument("--login-limit", metavar="EMAIL", help="also check sign-in rate limiting (locks EMAIL for 15 min)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    u = urllib.parse.urlparse(a.url)
    if u.scheme != "https" or not u.hostname:
        print("give the https:// address of the server")
        return 2
    host, port = u.hostname, u.port or 443
    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    c = Check()
    origin = f"https://{host}" + (f":{port}" if port != 443 else "")
    fetch = {"X-Requested-With": "fetch", "Content-Type": "application/json", "Origin": origin}

    # --- TLS -------------------------------------------------------------------------
    try:
        with socket.create_connection((host, port), timeout=10) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            version, cert = s.version(), s.getpeercert()
        c.that(version in ("TLSv1.2", "TLSv1.3"), "TLS version", version or "?")
        if cert and not a.insecure:
            left = (datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), UTC) - datetime.now(UTC)).days
            c.that(left >= 14, "certificate valid and not about to expire", f"{left} days left")
        elif a.insecure:
            c.warn("certificate", "not verified (--insecure)")
    except ssl.SSLCertVerificationError as exc:
        c.fail("certificate trusted", str(exc.verify_message))
        return report(c, a.json)
    except OSError as exc:
        c.fail("HTTPS reachable", str(exc))
        return report(c, a.json)
    for old in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        try:
            octx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            octx.check_hostname, octx.verify_mode = False, ssl.CERT_NONE
            octx.minimum_version = octx.maximum_version = old
            with socket.create_connection((host, port), timeout=10) as raw, octx.wrap_socket(raw, server_hostname=host):
                c.fail(f"{old.name} refused", "server accepted an obsolete TLS version")
        except ValueError:
            c.warn(f"{old.name} refused", "couldn't test: this machine's OpenSSL won't offer it")
        except ssl.SSLError as exc:
            if exc.reason in ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE"):
                c.warn(f"{old.name} refused", "couldn't test: this machine's OpenSSL won't offer it")
            else:
                c.ok(f"{old.name} refused", exc.reason or "")
        except OSError as exc:
            c.warn(f"{old.name} refused", f"couldn't test: {exc}")

    # --- plain HTTP redirects --------------------------------------------------------
    if not a.skip_http:
        try:
            st, h, _, _ = request(host, 80, "GET", "/", ctx=ctx, tls=False)
            c.that(st in (301, 302, 307, 308) and h.get("location", "").startswith("https://"),
                   "port 80 redirects to HTTPS", f"{st} {h.get('location', '')}")
        except OSError as exc:
            c.warn("port 80 redirects to HTTPS", f"port 80 closed ({exc}); fine if intended")

    # --- headers on the page ---------------------------------------------------------
    st, h, _, body = request(host, port, "GET", "/", ctx=ctx)
    c.that(st == 200, "page loads", str(st))
    hsts = h.get("strict-transport-security", "")
    c.that("max-age=" in hsts and int(hsts.split("max-age=")[1].split(";")[0] or 0) >= 15552000,
           "HSTS for at least 180 days", hsts or "missing")
    csp = h.get("content-security-policy", "")
    script = next((d for d in csp.split(";") if d.strip().startswith("script-src")), "")
    c.that(bool(csp) and "'unsafe-inline'" not in script and "'unsafe-eval'" not in script,
           "Content-Security-Policy without inline or eval script", csp[:80] or "missing")
    c.that("frame-ancestors 'none'" in csp or h.get("x-frame-options", "").upper() == "DENY", "can't be framed")
    c.that(h.get("x-content-type-options", "").lower() == "nosniff", "nosniff")
    c.that(h.get("referrer-policy", "") in ("no-referrer", "same-origin", "strict-origin"), "referrer policy",
           h.get("referrer-policy", "missing"))
    server = h.get("server", "")
    c.that(not any(ch.isdigit() for ch in server), "server header gives no version", server or "(none)")
    c.that(b"<script>" not in body.lower() or b"<script src" in body.lower(), "no inline script in the page")

    # --- authentication and CSRF -----------------------------------------------------
    st, _, _, _ = request(host, port, "GET", "/api/web/me", ctx=ctx, headers={"X-Requested-With": "fetch"})
    c.that(st == 401, "web API needs a session", str(st))
    st, _, _, _ = request(host, port, "POST", "/v1/actions", ctx=ctx, body=b"{}",
                          headers={"Content-Type": "application/json"})
    c.that(st == 401, "agent API needs a key", str(st))
    st, _, _, _ = request(host, port, "GET", "/v1/actions/x", ctx=ctx, headers={"Authorization": "Bearer wrong"})
    c.that(st == 401, "agent API refuses a wrong key", str(st))
    login = json.dumps({"email": "nobody@example.invalid", "password": "wrong-" + secrets.token_hex(8)}).encode()
    st, _, cookies, _ = request(host, port, "POST", "/api/web/login", ctx=ctx, body=login, headers=fetch)
    c.that(st in (401, 429), "wrong password refused", str(st))
    c.that(not any("session" in x.split("=")[0] and "Max-Age=0" not in x for x in cookies),
           "no session cookie on a failed sign-in")
    st, _, _, _ = request(host, port, "POST", "/api/web/login", ctx=ctx, body=login,
                          headers={"Content-Type": "application/json"})
    c.that(st == 403, "sign-in refuses requests without the same-site header (CSRF)", str(st))
    st, _, _, _ = request(host, port, "POST", "/api/web/login", ctx=ctx, body=login,
                          headers={**fetch, "Origin": "https://evil.example"})
    c.that(st == 403, "sign-in refuses another site's Origin (CSRF)", str(st))

    # --- request handling ------------------------------------------------------------
    for path in ("/../../etc/passwd", "/static/..%2f..%2fsrv/checkpoint", "/.git/config", "/.env", "/admin"):
        st, _, _, data = request(host, port, "GET", path, ctx=ctx)
        c.that(st in (400, 403, 404) and b"Traceback" not in data and b"root:" not in data, f"nothing at {path}",
               str(st))
    st, _, _, _ = request(host, port, "TRACE", "/", ctx=ctx)
    c.that(st in (400, 403, 404, 405, 501), "TRACE refused", str(st))
    try:
        st = request(host, port, "POST", "/api/web/login", ctx=ctx, body=b"x" * (3 * 1024 * 1024), headers=fetch)[0]
        c.that(st in (400, 413), "oversized body refused", str(st))
    except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
        c.ok("oversized body refused", "connection closed before the body was read")

    # --- sign-in rate limit (opt-in) -------------------------------------------------
    if a.login_limit:
        body = json.dumps({"email": a.login_limit, "password": "wrong-" + secrets.token_hex(8)}).encode()
        codes = [request(host, port, "POST", "/api/web/login", ctx=ctx, body=body, headers=fetch)[0] for _ in range(8)]
        c.that(429 in codes, "repeated wrong passwords are slowed down", " ".join(map(str, codes)))

    # --- other ports -----------------------------------------------------------------
    if not a.skip_ports:
        for p, what in sorted(EXPOSED_PORTS.items()):
            try:
                with socket.create_connection((host, p), timeout=2):
                    c.fail(f"port {p} closed", f"open: {what}")
            except OSError:
                c.ok(f"port {p} closed")

    return report(c, a.json)


def report(c: Check, as_json: bool) -> int:
    if as_json:
        print(json.dumps([{"result": r, "check": n, "detail": d} for r, n, d in c.results], indent=2))
    else:
        for r, n, d in c.results:
            print(f"{r:<5} {n}" + (f"  ({d})" if d else ""))
        fails = sum(r == "FAIL" for r, _, _ in c.results)
        print(f"\n{len(c.results)} checks, {fails} failed.")
    return 1 if any(r == "FAIL" for r, _, _ in c.results) else 0


if __name__ == "__main__":
    sys.exit(main())
