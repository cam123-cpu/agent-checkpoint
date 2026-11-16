# Deploying Checkpoint

A production install is three pieces: the checkpoint, a TLS proxy (Caddy), and, if the sign-in
page is on the public internet, Cloudflare in front for bot protection.

```
browser ──HTTPS──▶ Cloudflare (bot protection, rate limits) ──HTTPS──▶ Caddy (TLS) ──▶ checkpoint :8077
agents' MCP servers ─────────────────────────HTTPS──────────────────────▶ Caddy ──▶ checkpoint
```

## 1. The checkpoint

```bash
pip install agent-checkpoint            # or: pip install -e . from the repo
export CHECKPOINT_HOME=/srv/checkpoint  # data folder: keep it on an encrypted disk, back it up
agent-checkpoint create-org acme --name "Acme Manufacturing"
agent-checkpoint add-user acme cfo@acme.com --role admin
agent-checkpoint serve --host 127.0.0.1 --port 8077 --force-https \
    --public-origin https://checkpoint.example.com --trusted-proxy 127.0.0.1
```

Run it under systemd (or similar) as its own unprivileged user. The data folder holds the
companies' keys (`data.key`, `ledger.key`, `signing.pem`, `web.key`): back them up separately from
the databases, and never into the same place.

## 2. TLS with Caddy

Use `deploy/Caddyfile`. Caddy gets certificates from Let's Encrypt automatically. The checkpoint
believes `X-Forwarded-For` and `X-Forwarded-Proto` only from `--trusted-proxy` addresses.

## 3. Bot protection with Cloudflare (free plan is enough)

Sign-in already has rate limits, a honeypot field and equal-time answers. A CAPTCHA-style check
belongs at the edge, where it stops automated traffic before it reaches the server at all.

1. Put the domain on Cloudflare and proxy the `checkpoint` record (orange cloud).
2. **Security, Bots:** turn on Bot Fight Mode.
3. **Security, WAF, Rate limiting rules:** one rule for
   `http.request.uri.path wildcard "/api/web/login*" and http.request.method eq "POST"`,
   for example 20 requests per minute per IP, action Block.
4. **Security, WAF, Custom rules (optional):** a Managed Challenge on `http.request.uri.path eq "/"`
   for traffic you don't expect (for example, outside the countries your team works in). The
   challenge runs on the page load, so the app's own requests that follow carry Cloudflare's
   clearance cookie. Don't challenge `/v1/*`: that's where agents connect, with keys.
5. In the Caddyfile, enable the `trusted_proxies` block with Cloudflare's ranges so the checkpoint
   sees real visitor addresses. Without it, everyone appears to come from a few Cloudflare
   addresses and would share one sign-in limit.

## 4. Single sign-on (recommended for companies that have it)

```bash
# Microsoft Entra ID: App registrations, New registration, Web redirect URI:
#   https://checkpoint.example.com/auth/sso/callback
# then Certificates & secrets, New client secret.
echo "$CLIENT_SECRET" | agent-checkpoint set-sso acme --provider microsoft \
    --tenant <directory-tenant-id> --client-id <application-id> --domain acme.com

# Google Workspace: APIs & Services, Credentials, OAuth client ID (Web application), same redirect URI.
echo "$CLIENT_SECRET" | agent-checkpoint set-sso acme --provider google --client-id <id> --domain acme.com
```

People sign in at `https://checkpoint.example.com/?org=acme`. An admin still adds each person
(`add-user`), so SSO never creates accounts. Sign-ins through SSO count as two-step, because the
provider applies the company's own second factor.

## 5. Two-step sign-in

Each person turns it on from **Your account**. An admin can require it for the whole company in
**Settings** (after turning it on for themselves). If someone loses their phone and their recovery
codes: `agent-checkpoint reset-two-step person@acme.com`.
