# Security

Checkpoint guards money, so its own security is part of the product. The table below maps the
20-point pre-launch checklist to where each item is implemented and which test proves it. All
tests run in CI on every push.

| # | Item | How | Proven by |
|---|---|---|---|
| 1 | Hide API keys | Agent and approver keys exist only on the server and in the agent's environment. The browser gets none: it signs in with a password and an HttpOnly cookie. Keys are stored only as SHA-256 hashes | `test_static_and_api_responses_carry_no_secrets` |
| 2 | Purge Git secrets | No secrets in the repo or its history. `.gitignore` excludes data, keys and `.pem` files. Gitleaks scans the whole history in CI | `test_repository_files_contain_no_secrets`, CI `secrets` job |
| 3 | Public DB key only | The browser never talks to a database and holds no database credential. The only key ever published is the Ed25519 *public* key for verifying receipts | same as 1 |
| 4 | Row-level security | Stronger than row policies: each company has its own database files, and every web and API call is scoped to the company in the caller's session or key | `test_company_isolation_and_roles`, `test_full_flow_and_isolation` |
| 5 | Encrypt sensitive data | Bank accounts, stored requests, tickets and receipts are encrypted with AES-256-GCM using a per-company key, with associated data binding each value to its row. The audit log keeps only last 4 digits and a keyed fingerprint | `test_bank_details_encrypted_at_rest` |
| 6 | Server-side auth | Every route checks the session or key on the server; the web app's page checks are convenience only | `test_every_route_requires_sign_in` (all routes) |
| 7 | Lock record access | Roles (admin, approver, auditor) checked per route. Agents see only their own requests. The person who asked for an action can't approve it | `test_company_isolation_and_roles`, `test_only_approvers_and_never_the_requester` |
| 8 | Block field tampering | Every request body has an allow-list of fields; unknown fields are refused (422). Company, role, agent identity and dates never come from the client | `test_unknown_fields_refused`, `test_malformed_requests_refused_and_logged` |
| 9 | Secure session cookies | `__Host-` prefix, HttpOnly, Secure, SameSite=Strict, Path=/, no Domain. Random 256-bit tokens, stored hashed. Sessions end after 30 minutes idle or 12 hours, at sign-out, on password change or when disabled. Cross-site requests are refused | `test_session_cookie_hardening`, `test_idle_sessions_expire`, `test_cross_site_requests_refused` |
| 10 | Hash passwords | scrypt (N=2^14, r=8, p=1, 16-byte salt). Weak or email-based passwords refused. Unknown users and wrong passwords get the same answer in the same time. People change their own password in the app (which signs them out everywhere) | `test_password_hashing_and_policy`, `test_unknown_user_and_wrong_password_look_the_same`, `test_password_change_signs_out_everywhere` |
| 11 | Rate limit login | 5 failures per address and email in 15 minutes, 30 per address; shared across threads and processes. Every key and session is also limited per minute | `test_login_rate_limit`, `test_api_rate_limit` |
| 12 | Bot protection | Hidden honeypot field on sign-in, rate limits, constant-time checks, and two-step codes. On the public internet, Cloudflare in front adds Bot Fight Mode, an edge rate limit on sign-in and an optional Managed Challenge on the page ([deploy/DEPLOY.md](deploy/DEPLOY.md)) | `test_honeypot_blocks_bots` |
| 13 | Parameterize queries | Every SQL value is a parameter. A test fails the build if any SQL string interpolates anything but a fixed constant | `test_sql_injection_is_inert`, `test_sql_is_never_built_from_input` |
| 14 | Validate all input | Types, ranges, formats and sizes checked at the boundary. Money parsed exactly from decimal strings | `test_settings_validation`, `test_bad_query_and_body`, `test_malformed_requests_refused_and_logged` |
| 15 | Escape user content | The web app inserts text only with `textContent` (a test bans `innerHTML` and friends). CSV exports neutralise formulas. A browser test injects `<img onerror>` as a vendor name and checks it never runs | `test_no_banned_patterns`, `test_csv_export_neutralises_formulas`, `test_approve_flow_and_no_script_injection` |
| 16 | Restrict file uploads | CSV only (content type checked), 1 MB, UTF-8, no NUL bytes, at most 5,000 rows, admins only. Files are parsed as text and never stored | `test_upload_restrictions` |
| 17 | Trim API responses | The web API returns explicit view models (`views.py`): no hashes, ciphertexts, receipts or internal fields; accounts as last 4 digits | `test_static_and_api_responses_carry_no_secrets` |
| 18 | Security headers | Strict CSP (no inline or third-party script, no eval; even test tools' string eval is blocked), frame-ancestors none, nosniff, no-referrer, Permissions-Policy, COOP/CORP, no-store on API answers, no server version | `test_security_headers` |
| 19 | Force HTTPS | Built-in TLS (1.2+) or a proxy (`deploy/Caddyfile`). `--force-https` redirects with 308 and sends HSTS. Forwarded headers are trusted only from configured proxies. Plain HTTP refuses to start except on localhost with `--dev` | `test_force_https_and_hsts`, `test_built_in_tls` |
| 20 | Scan dependencies | `pip-audit --strict` in CI on every push and weekly; Dependabot for Python packages and GitHub Actions. One runtime dependency (`cryptography`) | CI `dependencies` job, `.github/dependabot.yml` |

## Sign-in beyond passwords

| Feature | How | Proven by |
|---|---|---|
| Two-step sign-in | TOTP (RFC 6238) from any authenticator app; ±1 step for clock drift; the last used step is stored with a conditional update so a code can't be replayed, even by two requests racing. The secret is encrypted at rest. The set-up QR code is drawn on the server (no third-party service ever sees the secret) and decoded with OpenCV in tests | `test_two_step.py` (RFC vectors, replay, window, QR scans) |
| Password alone gets nothing | A correct password with two-step on returns a 5-minute, single-use, 5-try pending token that can only be exchanged for a session with a valid code; failed codes count toward the sign-in limits | `test_enrol_then_sign_in_needs_a_code`, `test_pending_token_allows_only_five_tries` |
| Recovery codes | Ten one-time codes, shown once, stored as keyed hashes, consumed atomically | `test_recovery_codes_work_once`, `test_secret_and_codes_are_not_stored_in_clear` |
| Company can require it | People without it get a limited session that can only set it up; admins can't require it before having it (no self-lockout); it can't be turned off while required; turning it off needs password and a code | `test_web_flow_end_to_end`, `test_required_two_step_gives_a_limited_session` |
| Single sign-on | OpenID Connect authorization code flow with PKCE (S256); `state` single-use, encrypted, expiring and bound to the browser by a cookie (stops sign-in CSRF); `nonce` checked; ID token RS256 signature verified against the provider's published keys (refetched on rotation); `alg` none/HS256 refused; issuer, audience, authorized party, expiry, issued-at and not-before checked; Microsoft own tenant only, identified by directory sign-in name with tenant id checked; Google needs verified email and Workspace domain; optional domain allow-list; never creates accounts; person must belong to that company; error messages come from a fixed list (nothing reflected) | `test_sso.py` (15 rejection cases, key rotation, PKCE), mutation-checked |

Also: slow or silent connections time out (30 s) and TLS handshakes happen off the accept loop;
failures inside a check block the action (fail closed); the audit log is tamper-evident.

## Penetration test

A pen test on 16 November 2026 ran 30 attacks against a live server. 13 succeeded at first,
including 5 rated high (most important: a payment approved for one account could be paid to
another, and a CSV import could change where a vendor is paid). All 13 are fixed, and every attack
is kept as a regression test. Report: [docs/PENTEST.md](docs/PENTEST.md).

## Known limits

- One server process holds per-minute API limits in memory; sign-in limits are shared via SQLite.
  With several servers behind a load balancer, move the per-minute limiter to shared storage.
- No passkeys (WebAuthn) yet; two-step sign-in uses authenticator codes.
- No emailed password reset: an admin sets a new one (`set-password`), which ends the person's sessions.
- No SCIM: when someone leaves, disable them (`disable-user`) or remove them at your identity provider.

## Reporting a problem

Please email the maintainer privately rather than opening a public issue.
