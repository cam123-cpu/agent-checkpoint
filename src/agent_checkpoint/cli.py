"""Command line: set up companies and keys, run the server or the MCP server, read reports.

    agent-checkpoint demo                         one-command sandbox company with keys, for trying the MCP tools
    agent-checkpoint create-org acme --name "Acme Manufacturing"
    agent-checkpoint add-agent acme ap-agent --actions pay,change_bank --max 100000 --daily 150000
    agent-checkpoint add-approver acme controller@acme.com           (API key for an approver tool)
    agent-checkpoint add-user acme cfo@acme.com --role admin         (web sign-in; prints a password once)
    agent-checkpoint import-vendors acme vendors.csv      /  import-pos acme pos.csv
    agent-checkpoint set-mode acme enforce
    agent-checkpoint serve --port 8077 --tls-cert cert.pem --tls-key key.pem   (or behind a proxy: --force-https)
    agent-checkpoint serve --dev                  (plain HTTP on localhost for development only)
    agent-checkpoint mcp                          (reads CHECKPOINT_AGENT_KEY; --url for a remote checkpoint)
    agent-checkpoint tickets acme | approve acme T-... --as cfo@acme.com [--callback-verified] | reject ...
    agent-checkpoint report acme [--since 2026-10-01] | verify acme | head acme | public-key acme
    agent-checkpoint simulate [--seeds 10]

Home folder: --home, or CHECKPOINT_HOME, or ./checkpoint-data.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from dataclasses import replace
from datetime import date

from .accounts import AuthError
from .gateway import CheckpointError
from .importers import import_pos, import_vendors
from .models import parse_amount
from .policy import AgentScope
from .report import render_text, shadow_report
from .store import PurchaseOrder, Vendor
from .tenancy import Registry


def _registry(args) -> Registry:
    return Registry(args.home or os.environ.get("CHECKPOINT_HOME", "./checkpoint-data"))


def cmd_demo(args) -> int:
    reg = _registry(args)
    if os.path.isdir(os.path.join(reg.home, "orgs", "demo")):
        print("demo company already exists; delete the folder to start again", file=sys.stderr)
        return 1
    reg.create_org("demo", "Demo Manufacturing")
    p = reg.policy("demo")
    reg.save_policy("demo", replace(p, mode="enforce", internal_domains=("demo.example",)))
    agent_key = reg.add_agent("demo", "claude-ap", AgentScope(("pay", "change_bank", "refund"), 100_000_00,
                                                              150_000_00, "Claude"))
    approver_key = reg.add_approver("demo", "controller@demo.example")
    web_password = secrets.token_urlsafe(15)
    reg.add_user("demo", "controller@demo.example", "admin", web_password)
    store = reg.gateway("demo").org.store
    for vid, name, acct, domain in (("V-NORTH", "Northwind Supplies", "US00021000001234", "northwind-supplies.com"),
                                    ("V-CONTO", "Contoso Packaging", "US00021000005678", "contoso.com"),
                                    ("V-FABRI", "Fabrikam Freight", "US00021000009012", "fabrikam.com")):
        store.upsert_vendor(Vendor(vid, name, acct, (domain,), date(2024, 1, 1), phone="+1 415 555 0100"))
    store.upsert_po(PurchaseOrder("PO-1001", "V-CONTO", 4_800_00))
    store.upsert_po(PurchaseOrder("PO-1002", "V-NORTH", 6_200_00))
    store.upsert_po(PurchaseOrder("PO-1003", "V-CONTO", 4_800_00))
    print(json.dumps({"home": reg.home, "org": "demo", "mode": "enforce",
                      "agent_key": agent_key, "approver_key": approver_key,
                      "web_sign_in": {"email": "controller@demo.example", "password": web_password,
                                      "start": f"agent-checkpoint --home {reg.home} serve --dev"},
                      "try": ["pay V-CONTO invoice INV-77 for 4800.00 on PO-1001 (goes through)",
                              "pay V-CONTO invoice INV-78 for 48000.00 on PO-1003 (blocked: decimal slip)",
                              "pay V-CONTO invoice INV-77 again (blocked: duplicate)",
                              "change V-NORTH bank account, email from billing@northwind-supp1ies.com (blocked)",
                              "pay V-NORTH 6200.00 on PO-1002, invoice printing another account (paused)"]},
                     indent=2))
    print("\nKeys are shown once. Keep them out of git.", file=sys.stderr)
    return 0


def cmd_create_org(args) -> int:
    _registry(args).create_org(args.org, args.name)
    print(f"created {args.org}; edit orgs/{args.org}/policy.json, then add agents and approvers")
    return 0


def cmd_add_agent(args) -> int:
    scope = AgentScope(tuple(a.strip() for a in args.actions.split(",") if a.strip()),
                       parse_amount(args.max) if args.max else 0, parse_amount(args.daily) if args.daily else 0,
                       args.vendor or "")
    key = _registry(args).add_agent(args.org, args.agent, scope)
    print(key)
    print(f"agent key for {args.agent} (shown once). Give it to the agent's MCP server as CHECKPOINT_AGENT_KEY.",
          file=sys.stderr)
    return 0


def cmd_add_approver(args) -> int:
    print(_registry(args).add_approver(args.org, args.email))
    print(f"approver key for {args.email} (shown once).", file=sys.stderr)
    return 0


def cmd_add_user(args) -> int:
    password = sys.stdin.readline().rstrip("\n") if args.password_stdin else secrets.token_urlsafe(15)
    _registry(args).add_user(args.org, args.email, args.role, password)
    if not args.password_stdin:
        print(password)
        print(f"password for {args.email} (shown once; they can't change it in the app yet, so send it securely)",
              file=sys.stderr)
    return 0


def cmd_user_state(args, disabled: bool) -> int:
    _registry(args).accounts().set_disabled(args.email, disabled)
    print(f"{args.email} {'disabled; their sessions are ended' if disabled else 'enabled'}")
    return 0


def cmd_set_password(args) -> int:
    password = sys.stdin.readline().rstrip("\n") if args.password_stdin else secrets.token_urlsafe(15)
    _registry(args).accounts().set_password(args.email, password)
    if not args.password_stdin:
        print(password)
    print("password changed; existing sessions are ended", file=sys.stderr)
    return 0


def cmd_set_mode(args) -> int:
    reg = _registry(args)
    reg.save_policy(args.org, replace(reg.policy(args.org), mode=args.mode))
    print(f"{args.org} is now in {args.mode} mode")
    return 0


def cmd_import(args, which) -> int:
    store = _registry(args).gateway(args.org).org.store
    with open(args.file, encoding="utf-8-sig") as f:
        n, errors = (import_vendors if which == "vendors" else import_pos)(store, f.read())
    print(f"imported {n} {which}")
    for e in errors:
        print("  " + e, file=sys.stderr)
    return 1 if errors else 0


def cmd_serve(args) -> int:
    from .server import ServerConfig, make_server
    tls = (args.tls_cert, args.tls_key) if args.tls_cert else None
    if args.tls_cert and not args.tls_key:
        raise ValueError("--tls-cert needs --tls-key")
    if not (tls or args.force_https or args.dev):
        raise ValueError("choose --tls-cert/--tls-key, --force-https (behind a TLS proxy), or --dev (localhost only)")
    if args.dev and args.host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("--dev serves plain HTTP and is only allowed on localhost")
    cfg = ServerConfig(secure_cookies=not args.dev, force_https=args.force_https,
                       trusted_proxies=tuple(args.trusted_proxy or ("127.0.0.1", "::1")), public_origin=args.public_origin or "")
    srv = make_server(_registry(args), args.host, args.port, cfg, tls)
    scheme = "https" if tls else "http"
    print(f"agent-checkpoint listening on {scheme}://{args.host}:{args.port}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_mcp(args) -> int:
    from .mcp_server import main
    main(args.home or os.environ.get("CHECKPOINT_HOME"), args.url or os.environ.get("CHECKPOINT_URL"), None)
    return 0


def cmd_tickets(args) -> int:
    gw = _registry(args).gateway(args.org)
    gw.expire()
    for t in gw.org.store.tickets("open"):
        r = t["request"]
        print(f"{t['ticket_id']}  {r['action']} {r['vendor_id']} {r['amount_cents'] / 100:,.2f}  "
              f"needs {t['needed'] - len(t['approvals'])} more  expires {t['expires_at'][:16]}")
        for f in t["findings"]:
            print(f"    - {f['message']}")
    return 0


def cmd_resolve(args, approve: bool) -> int:
    gw = _registry(args).gateway(args.org)
    out = gw.resolve(args.ticket, args.as_, approve, args.note or "",
                     callback_verified=getattr(args, "callback_verified", False), fraud=getattr(args, "fraud", False))
    print(json.dumps(out, indent=2))
    return 0


def cmd_report(args) -> int:
    rep = shadow_report(_registry(args).gateway(args.org).org.ledger, args.since or "", args.until or "")
    print(json.dumps(rep, indent=2) if args.json else render_text(rep))
    return 0


def cmd_verify(args) -> int:
    led = _registry(args).gateway(args.org).org.ledger
    head = json.loads(args.expect) if args.expect else None
    ok, why = led.verify(head)
    print(("OK: " if ok else "FAILED: ") + why)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent-checkpoint", description="Independent checkpoint for AI agents and money")
    p.add_argument("--home", help="data folder (default: $CHECKPOINT_HOME or ./checkpoint-data)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo").set_defaults(fn=cmd_demo)
    s = sub.add_parser("create-org"); s.add_argument("org"); s.add_argument("--name", required=True)
    s.set_defaults(fn=cmd_create_org)
    s = sub.add_parser("add-agent"); s.add_argument("org"); s.add_argument("agent")
    s.add_argument("--actions", required=True, help="comma list of pay,change_bank,refund,edit_record")
    s.add_argument("--max", help="per-action limit, e.g. 100000"); s.add_argument("--daily", help="daily cap")
    s.add_argument("--vendor", help="who makes the agent"); s.set_defaults(fn=cmd_add_agent)
    s = sub.add_parser("add-approver"); s.add_argument("org"); s.add_argument("email"); s.set_defaults(fn=cmd_add_approver)
    s = sub.add_parser("add-user", help="someone who signs in to the web app")
    s.add_argument("org"); s.add_argument("email")
    s.add_argument("--role", choices=["admin", "approver", "auditor"], required=True)
    s.add_argument("--password-stdin", action="store_true", help="read the password from stdin instead of generating one")
    s.set_defaults(fn=cmd_add_user)
    s = sub.add_parser("set-password"); s.add_argument("email"); s.add_argument("--password-stdin", action="store_true")
    s.set_defaults(fn=cmd_set_password)
    for name, dis in (("disable-user", True), ("enable-user", False)):
        s = sub.add_parser(name); s.add_argument("email"); s.set_defaults(fn=lambda a, d=dis: cmd_user_state(a, d))
    s = sub.add_parser("set-mode"); s.add_argument("org"); s.add_argument("mode", choices=["shadow", "enforce"])
    s.set_defaults(fn=cmd_set_mode)
    for which in ("vendors", "pos"):
        s = sub.add_parser(f"import-{which}"); s.add_argument("org"); s.add_argument("file")
        s.set_defaults(fn=lambda a, w=which: cmd_import(a, w))
    s = sub.add_parser("serve"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8077)
    s.add_argument("--tls-cert"); s.add_argument("--tls-key")
    s.add_argument("--force-https", action="store_true", help="behind a TLS proxy: redirect http and send HSTS")
    s.add_argument("--trusted-proxy", action="append", help="address whose X-Forwarded-* headers are believed")
    s.add_argument("--public-origin", help="e.g. https://checkpoint.acme.com")
    s.add_argument("--dev", action="store_true", help="plain HTTP on localhost, cookies without Secure")
    s.set_defaults(fn=cmd_serve)
    s = sub.add_parser("mcp", help="MCP server over stdio for an agent")
    s.add_argument("--url", help="remote checkpoint URL (otherwise uses the local home folder)")
    s.set_defaults(fn=cmd_mcp)
    s = sub.add_parser("tickets"); s.add_argument("org"); s.set_defaults(fn=cmd_tickets)
    for name, approve in (("approve", True), ("reject", False)):
        s = sub.add_parser(name); s.add_argument("org"); s.add_argument("ticket")
        s.add_argument("--as", dest="as_", required=True, help="approver email"); s.add_argument("--note")
        if approve:
            s.add_argument("--callback-verified", action="store_true", help="you phoned the number on file")
        else:
            s.add_argument("--fraud", action="store_true", help="report to the shared fraud network")
        s.set_defaults(fn=lambda a, ap=approve: cmd_resolve(a, ap))
    s = sub.add_parser("report"); s.add_argument("org"); s.add_argument("--since"); s.add_argument("--until")
    s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_report)
    s = sub.add_parser("verify"); s.add_argument("org"); s.add_argument("--expect", help='published head JSON')
    s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("head"); s.add_argument("org")
    s.set_defaults(fn=lambda a: print(json.dumps(_registry(a).gateway(a.org).org.ledger.head())) or 0)
    s = sub.add_parser("public-key"); s.add_argument("org")
    s.set_defaults(fn=lambda a: print(_registry(a).gateway(a.org).org.signer.public_pem(), end="") or 0)
    s = sub.add_parser("simulate"); s.add_argument("--seeds", type=int, default=1)
    s.set_defaults(fn=lambda a: __import__("agent_checkpoint.simulate", fromlist=["main"]).main(a.seeds) or 0)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except CheckpointError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ValueError, KeyError, FileExistsError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
