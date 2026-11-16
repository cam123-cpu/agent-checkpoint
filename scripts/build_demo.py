"""Build the sample-data demo of the web app, and optionally a real company folder with the same data.

    python scripts/build_demo.py --out dist/demo            # static demo: index.html + assets + data
    python scripts/build_demo.py --home ./demo-home         # also keep a real company to `serve --dev`

The quarter comes from the simulation (enforce mode). Requests from the last week are left
waiting, so the Approvals page has real work on it. The demo's data is produced by the same view
functions the server uses (`views.py`), so the demo shows exactly what the real app shows.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from dataclasses import replace
from datetime import UTC, date, datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_checkpoint import views  # noqa: E402
from agent_checkpoint.evidence import evidence, usage  # noqa: E402
from agent_checkpoint.notify import CollectingNotifier  # noqa: E402
from agent_checkpoint.simulate import account, company_policy, events, setup  # noqa: E402
from agent_checkpoint.store import PurchaseOrder  # noqa: E402
from agent_checkpoint.tenancy import Registry  # noqa: E402

WEB = os.path.join(os.path.dirname(__file__), "..", "src", "agent_checkpoint", "web")
CUTOFF = date(2026, 10, 6)  # decisions after this are left for the demo's approver
ADMIN = "controller@acme-manufacturing.example"


def seed(home: str, password: str | None = None):
    reg = Registry(home)
    reg.create_org("acme", "Acme Manufacturing")
    policy = replace(company_policy("enforce"), approvers=(ADMIN, "cfo@acme-manufacturing.example"), ticket_hours=720)
    reg.save_policy("acme", policy)
    if password:
        reg.add_user("acme", ADMIN, "admin", password)
    gw = reg.gateway("acme")
    gw.org.notifier = CollectingNotifier()
    now = [datetime(2026, 8, 1, tzinfo=UTC)]
    gw.clock = lambda: now[0]
    evs, pos, extra = events(0)
    setup(gw, pos, extra)
    for dt, agent, raw, label, _note in evs:
        now[0] = dt
        d = gw.submit(raw, agent_id=agent)
        if d.ticket_id and dt.date() < CUTOFF:
            ok = label == "policy_hold"
            gw.resolve(d.ticket_id, ADMIN, ok, "Called the vendor; confirmed." if ok else "Not genuine.",
                       callback_verified=ok, fraud=not ok and label == "incident",
                       called_number=(gw.org.store.vendor(raw.get("vendor_id", "")) or type("V", (), {"phone": ""})).phone)
            if gw.org.store.ticket(d.ticket_id)["status"] == "open":
                gw.resolve(d.ticket_id, "cfo@acme-manufacturing.example", True)
    # Two more for the demo: a genuine-looking bank change, and a payment that needs two people.
    now[0] = datetime(2026, 10, 29, 16, 10, tzinfo=UTC)
    gw.submit({"request_id": "DEMO-BANK-1", "action": "change_bank", "vendor_id": "V-CLOUD",
               "bank_account": "US4402100000918273", "evidence": [
                   {"kind": "email", "ref": "proseware-new-bank.eml", "sender": "accounts@proseware.com"}],
               "instructed_by": {"source": "email", "identity": "accounts@proseware.com"}}, agent_id="ap-agent")
    gw.org.store.upsert_po(PurchaseOrder("PO-ADVEN-CAP-7", "V-ADVEN", 62_400_00))
    now[0] = datetime(2026, 10, 30, 9, 40, tzinfo=UTC)
    gw.submit({"request_id": "DEMO-CAPEX-1", "action": "pay", "vendor_id": "V-ADVEN", "amount_cents": 62_400_00,
               "invoice_number": "AW-2026-1180", "po_number": "PO-ADVEN-CAP-7", "bank_account_on_invoice": account(4),
               "evidence": [{"kind": "invoice", "ref": "AW-2026-1180.pdf", "sender": "billing@adventure-works.com"},
                            {"kind": "purchase_order", "ref": "PO-ADVEN-CAP-7"}],
               "instructed_by": {"source": "email", "identity": "billing@adventure-works.com via ap@company.com"}},
              agent_id="ap-agent")
    now[0] = datetime(2026, 10, 30, 17, tzinfo=UTC)
    return reg, gw


SAMPLE_RUN = """Supplier,Invoice #,Amount,Pay to account,PO number
Northwind Supplies,INV-NORTH-0099,"6,180.00",{north},
Contoso Packaging,INV-CONTO-0010,"4,512.30",{conto},
Fabrikam Freight,INV-FABRI-0001,"{fab1}",{fabri},
Litware Components,INV-LITWA-0099,"8,950.00",GB29NWBK60161331926819,
Wide World Importers,WW-9001,"5,310.00",{wide},
Wide World Importers,WW-9001,"5,310.00",{wide},
Tailspin Logistics,TS-7001,"9,000.00",{tails},
Tailspin Logistics,TS-7002,"8,500.00",{tails},
Globex Consulting,GX-44,"3,400.00",US12000333344445555,
Proseware Cloud,INV-CLOUD-0004,"1,200.00",{cloud},
Adventure Works Tooling,AW-9100,"112,000.00",{adven},
"""


def sample_run(gw) -> dict:
    from agent_checkpoint.importers import read_payment_run
    accts = {v.vendor_id: v.bank_account for v in gw.org.store.vendors()}
    fab1 = next(p for p in gw.org.store.payments("V-FABRI", "pay"))
    text = SAMPLE_RUN.format(north=accts["V-NORTH"], conto=accts["V-CONTO"], fabri=accts["V-FABRI"],
                             wide=accts["V-WIDE"], tails=accts["V-TAILS"], cloud=accts["V-CLOUD"], adven=accts["V-ADVEN"],
                             fab1=f"{fab1.amount_cents / 100:.2f}")
    rows, errors = read_payment_run(gw.org.store, text)
    out = gw.check_run(rows, ADMIN, "sample")
    return {**out, "errors": errors}


def snapshot(reg, gw) -> dict:
    return {
        "payment_run_sample": sample_run(gw),
        "setup": views.setup(gw, [{"email": ADMIN, "role": "admin", "disabled": False},
                                  {"email": "cfo@acme-manufacturing.example", "role": "approver", "disabled": False}],
                             {"ap-agent": 1, "crm-agent": 1, "ops-agent": 1}),
        "now": gw.clock().isoformat(),
        "me": {"email": ADMIN, "role": "admin", "company": gw.org.name, "mode": gw.org.policy.mode, "two_step": True,
               "setup_required": False, "require_two_step": True, "recovery_codes_left": 10},
        "overview": views.overview(gw), "tickets": views.tickets(gw), "activity": views.activity(gw, limit=10_000),
        "audit": views.audit(gw), "vendors": views.vendors(gw),
        "evidence": {**evidence(gw.org.ledger, hold_limit_pct=gw.org.policy.pilot_hold_limit_pct),
                     "usage": usage(gw.org.ledger), "public_key": gw.org.signer.public_pem()},
        "settings": {**views.settings(gw, [
            {"email": ADMIN, "role": "admin", "disabled": False, "two_step": True},
            {"email": "cfo@acme-manufacturing.example", "role": "approver", "disabled": False, "two_step": True},
            {"email": "audit@acme-manufacturing.example", "role": "auditor", "disabled": False, "two_step": True}]),
            "require_two_step": True},
    }


DEMO_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Checkpoint demo</title>
<link rel="icon" href="icon.svg" type="image/svg+xml">
<link rel="stylesheet" href="app.css">
<script src="demo-data.js" defer></script>
<script src="demo.js" defer></script>
<script src="app.js" defer></script>
</head>
<body>
<div id="app"><noscript>This demo needs JavaScript turned on.</noscript></div>
</body>
</html>
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist/demo")
    ap.add_argument("--home", help="keep a real company folder here (for `serve --dev`)")
    ap.add_argument("--password", help="web password for the admin in --home")
    args = ap.parse_args()
    home = args.home or tempfile.mkdtemp()
    reg, gw = seed(home, args.password)
    data = snapshot(reg, gw)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "demo-data.js"), "w") as f:
        f.write("window.CHECKPOINT_DEMO = " + json.dumps(data) + ";\n")
    for name in ("app.js", "app.css", "icon.svg", "demo.js"):
        src = os.path.join(WEB, name) if name != "demo.js" else os.path.join(os.path.dirname(__file__), "demo.js")
        shutil.copy(src, os.path.join(args.out, name))
    with open(os.path.join(args.out, "index.html"), "w") as f:
        f.write(DEMO_HTML)
    print(f"demo written to {args.out}: {len(data['tickets'])} waiting, {len(data['activity'])} actions")
    if not args.home:
        shutil.rmtree(home)


if __name__ == "__main__":
    main()
