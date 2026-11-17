# Deploying Checkpoint

A production install is three pieces: the checkpoint, a TLS proxy (Caddy), and, if the sign-in
page is on the public internet, Cloudflare in front for bot protection.

```
browser ──HTTPS──▶ Cloudflare (bot protection, rate limits) ──HTTPS──▶ Caddy (TLS) ──▶ checkpoint :8077
agents' MCP servers ─────────────────────────HTTPS──────────────────────▶ Caddy ──▶ checkpoint
```

## 0. The quick way: one script on a fresh server

On a new Ubuntu 22.04/24.04 or Debian 12 server, with the domain's DNS already pointing at it and your
SSH key installed:

```bash
git clone https://github.com/cam123-cpu/agent-checkpoint && cd agent-checkpoint
sudo bash deploy/install.sh checkpoint.example.com you@example.com
```

It sets up everything in sections 1 and 2 below, plus:

- **HTTPS only.** Caddy gets and renews certificates, redirects plain HTTP, and allows TLS 1.2 and 1.3 only.
- **Firewall.** Only SSH, 80 and 443 are open. The checkpoint itself listens on 127.0.0.1 only.
- **SSH.** Keys only, no passwords (skipped, with a warning, if no key is installed yet).
- **Automatic security updates, daily.** System packages, Python, OpenSSL and Caddy, through
  `unattended-upgrades`, with an automatic reboot at 04:00 when an update needs one.
- **Weekly dependency update.** `cryptography`, the checkpoint's one runtime dependency, is upgraded and
  audited for known vulnerabilities (`pip-audit`). A finding fails the job:
  `systemctl status agent-checkpoint-update` shows it. The checkpoint's own code is never updated
  automatically. A new version is a reviewed release you install.
- **Sandbox.** The checkpoint runs as its own user under systemd. It can write only its data and keys
  folders, and has no capabilities.
- **Keys apart.** Keys live in `/etc/agent-checkpoint/keys`, not in the data folder. Better still, put
  them on a separate encrypted volume.

Then check it from another machine:

```bash
python3 deploy/external_check.py https://checkpoint.example.com
```

## 1. The checkpoint (by hand)

```bash
pip install agent-checkpoint            # or: pip install -e . from the repo
export CHECKPOINT_HOME=/srv/checkpoint  # data folder: keep it on an encrypted disk, back it up
agent-checkpoint create-org acme --name "Acme Manufacturing"
agent-checkpoint add-user acme cfo@acme.com --role admin
agent-checkpoint serve --host 127.0.0.1 --port 8077 --force-https \
    --public-origin https://checkpoint.example.com --trusted-proxy 127.0.0.1
```

Run it under systemd as its own unprivileged user (`deploy/agent-checkpoint.service`). Set
`AGENT_CHECKPOINT_KEYS` to a folder outside the data folder, so a copy of the data alone can't be
read (`agent-checkpoint move-keys` moves an existing install). Back the keys up separately from the
databases, and never into the same place. `agent-checkpoint doctor` checks this.

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
(`add-user`), so SSO never creates accounts.

Admins, and everyone in a company that requires two-step, get in through SSO only if the provider
says a second factor was used (the ID token's `amr` claim). Microsoft Entra ID sends this when MFA is
on. Google usually doesn't, so with Google those people sign in with their password and authenticator
code instead.

## 5. Two-step sign-in

**Every admin must use it.** An admin who signs in with only a password can do nothing but set it up,
and admins can't turn it off. Other people turn it on from **Your account**, and an admin can require it
for the whole company in **Settings**. If someone loses their phone and their recovery codes, another
admin resets it (People page, or `agent-checkpoint reset-two-step person@acme.com`), and they set it up
again at next sign-in. `agent-checkpoint doctor` lists admins who haven't set it up yet.

## 6. An outside pen test of the deployed server

The tests in this repository were written by the people who wrote the code, and they test the code.
Before any company's money depends on enforce mode, have an independent firm test the deployed server.

1. **First, run the smoke test yourself.** `python3 deploy/external_check.py https://your-domain` must
   show no failures. Don't pay a tester to find a missing header.
2. **Stand up a test server** with the same install script, a test company in enforce mode with the
   sandbox rail, and made-up vendors. Never use a real company's data or a real bank connection.
3. **Scope it in writing:**
   - The web app and `/api/web/*`, with one account of each role and two test companies.
   - The agent API `/v1/*`, with one agent key.
   - Single sign-on, if used.
   - The server: TLS, open ports, SSH.

   Ask for the OWASP ASVS level 2 checks plus business-logic attacks: paying a different account than
   the one approved, crossing between companies, replaying a release or receipt, getting around the
   bank-change call, importing a file that moves money.
4. **Give them written permission** naming the host, the dates and their source addresses. Tell the
   hosting provider and Cloudflare if they require it. Put their addresses on an allow-list for the
   test window, or the sign-in limits will block them.
5. **Ask for a report with reproducible steps** and a free retest of the fixes. Add a regression test
   for every finding before closing it, as the first pen test did.

Get at least two quotes; prices vary a lot with scope. A public bug bounty can come later, once there
are paying customers.
