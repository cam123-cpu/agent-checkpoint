"""What the web app is allowed to see: explicit, trimmed view models.

Nothing here returns a stored row as-is. Every field is chosen; account numbers appear only as
their last four digits; no keys, hashes, ciphertexts, receipts or internal ids leave the server.
The demo build (`scripts/build_demo.py`) uses these same functions, so the demo shows exactly
what the real app would.
"""

from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import timedelta

from .models import ActionRequest
from .store import last4

_RANK = {"block": 2, "pause": 1, "go": 0}


def _vendor_name(gw, vendor_id: str) -> str:
    v = gw.org.store.vendor(vendor_id)
    return v.name if v else f"{vendor_id} (not in your vendor list)"


def _status(gw, entry_body: dict) -> str:
    rid = entry_body["request_id"]
    t = gw.org.store.ticket_for(rid)
    if t:
        return {"open": "waiting", "approved": "approved", "rejected": "rejected", "expired": "expired",
                "blocked_on_recheck": "blocked"}.get(t["status"], t["status"])
    if entry_body["returned"] == "block":
        return "blocked"
    return "observed" if entry_body["mode"] == "shadow" else "done"


def tickets(gw) -> list[dict]:
    gw.expire()
    out = []
    for t in gw.org.store.tickets("open"):
        r = t["request"]
        decision = gw.org.ledger.find(t["request_id"], "decision") or {}
        vendor = gw.org.store.vendor(r["vendor_id"])
        out.append({
            "ticket_id": t["ticket_id"], "request_id": t["request_id"], "created_at": t["created_at"],
            "expires_at": t["expires_at"], "needed": t["needed"], "approved_by": [a["by"] for a in t["approvals"]],
            "action": r["action"], "vendor_id": r["vendor_id"], "vendor_name": _vendor_name(gw, r["vendor_id"]),
            "amount_cents": r["amount_cents"], "currency": r["currency"], "agent_id": r["agent_id"],
            "invoice_number": r["invoice_number"], "po_number": r["po_number"], "memo": r["memo"][:200],
            "requested_by": r["instructed_by"], "risk": decision.get("risk", 0),
            "reasons": [f["message"] for f in t["findings"] if f["verdict"] != "go"],
            "account_on_file": last4(vendor.bank_account) if vendor else "",
            "pays_to": last4(gw._payee(ActionRequest.from_stored(r))) if r["action"] in ("pay", "refund") else "",
            "account_on_invoice": last4(r["bank_account_on_invoice"]) if r["bank_account_on_invoice"] else "",
            "new_account": last4(r["bank_account"]) if r["action"] == "change_bank" else "",
            "phone_on_file": vendor.phone if vendor else "",
            "evidence": [{"kind": e["kind"], "ref": e["ref"], "sender": e["sender"]} for e in r["evidence"]],
        })
    return sorted(out, key=lambda t: (-t["risk"], t["created_at"]))


def activity(gw, verdict: str = "", agent: str = "", search: str = "", limit: int = 200) -> list[dict]:
    rows = []
    q = search.lower().strip()
    for e in reversed(gw.org.ledger.entries("decision")):
        b, r = e["body"], e["body"]["request"]
        if verdict and b["verdict"] != verdict:
            continue
        if agent and r["agent_id"] != agent:
            continue
        name = _vendor_name(gw, r["vendor_id"])
        if q and q not in name.lower() and q not in r["invoice_number"].lower() and q not in r["vendor_id"].lower():
            continue
        rows.append({
            "request_id": b["request_id"], "at": e["at"], "on": r["on"], "agent_id": r["agent_id"],
            "action": r["action"], "vendor_name": name, "invoice_number": r["invoice_number"],
            "amount_cents": r["amount_cents"], "verdict": b["verdict"], "status": _status(gw, b),
            "risk": b["risk"], "seq": e["seq"],
            "reasons": [f["message"] for f in sorted(b["findings"], key=lambda f: _RANK.get(f["verdict"], 0), reverse=True)],
        })
    for e in gw.org.ledger.entries("payment_run_checked"):
        for line in e["body"].get("lines", []):
            if line["verdict"] == "go" and verdict != "go":
                continue
            if verdict and line["verdict"] != verdict:
                continue
            if agent and agent != "payment-run":
                continue
            hay = f"{line['vendor_name']} {line['invoice_number']} {line['vendor_id']}".lower()
            if q and q not in hay:
                continue
            rows.append({
                "request_id": f"run-{e['seq']}-L{line['line']}", "at": e["at"], "on": e["at"][:10],
                "agent_id": "payment-run", "action": "pay", "vendor_name": line["vendor_name"],
                "invoice_number": line["invoice_number"], "amount_cents": line["amount_cents"],
                "verdict": line["verdict"], "status": "checked", "risk": line["risk"], "seq": e["seq"],
                "reasons": line["reasons"],
            })
    rows.sort(key=lambda r: (r["at"], r["seq"]), reverse=True)
    for r in rows:
        r.pop("seq", None)
    return rows[:limit]


def overview(gw, days: int = 90) -> dict:
    today = gw.clock().date()
    since = (today - timedelta(days=days)).isoformat()
    counts, money, agents = Counter(), Counter(), Counter()
    for e in gw.org.ledger.entries("decision"):
        b, r = e["body"], e["body"]["request"]
        if r["on"] < since:
            continue
        counts[b["verdict"]] += 1
        agents[r["agent_id"]] += 1
        if r["action"] in ("pay", "refund"):
            money[b["verdict"]] += r["amount_cents"]
    for e in gw.org.ledger.entries("payment_run_checked"):
        if e["at"][:10] < since:
            continue
        agents["payment-run"] += 1
        for line in e["body"].get("lines", []):
            counts[line["verdict"]] += 1
            money[line["verdict"]] += line["amount_cents"]
    ok, _ = gw.org.ledger.verify()
    return {
        "company": gw.org.name, "mode": gw.org.policy.mode, "days": days, "since": since,
        "waiting": len(gw.org.store.tickets("open")),
        "checked": sum(counts.values()), "allowed": counts["go"], "paused": counts["pause"], "blocked": counts["block"],
        "allowed_cents": money["go"], "paused_cents": money["pause"], "blocked_cents": money["block"],
        "agents": [{"agent_id": a, "actions": n,
                    "made_by": gw.org.policy.agents[a].vendor if a in gw.org.policy.agents else ""}
                   for a, n in agents.most_common()],
        "ledger_ok": ok,
        "stopped": [row for row in activity(gw, limit=500) if row["verdict"] == "block"][:5],
    }


def audit(gw, limit: int = 100) -> dict:
    ok, detail = gw.org.ledger.verify()
    entries = gw.org.ledger.entries()
    kinds = Counter(e["kind"] for e in entries)
    recent = []
    for e in entries[-limit:][::-1]:
        b = e["body"]
        summary = {
            "decision": lambda: f"{b['request']['action']} by {b['request']['agent_id']}: {b['verdict']}",
            "human_decision": lambda: f"{b.get('approver', 'system')}: {b.get('status', '')}",
            "executed": lambda: f"{b.get('action', '')} {b.get('status', '')}",
            "rejected": lambda: "malformed request refused",
            "fraud_report": lambda: f"reported to fraud network by {b.get('by', '')}",
            "fraud_report_withdrawn": lambda: f"fraud report withdrawn by {b.get('by', '')}",
            "release_issued": lambda: (f"{b.get('by', '')} signed a release: {b.get('released', 0)} lines "
                                       f"(${b.get('released_cents', 0) / 100:,.2f}), {b.get('held', 0)} held"),
            "allowed_accounts_issued": lambda: (f"{b.get('by', '')} signed allowed-accounts list version "
                                                f"{b.get('version', '')} ({b.get('accounts', 0)} accounts)"),
            "line_outcome": lambda: f"{b.get('by', '')} marked line {b.get('line', '')} as {b.get('outcome', '')}",
            "miss_reported": lambda: (f"{b.get('by', '')} recorded fraud that got through: "
                                      f"${b.get('amount_cents', 0) / 100:,.2f}"),
            "execution_failed": lambda: "payment rail refused the receipt",
            "payment_run_checked": lambda: (
                f"{b.get('by', 'someone')} checked a payment file: "
                f"{b.get('summary', {}).get('block', {}).get('count', 0)} don't pay, "
                f"{b.get('summary', {}).get('pause', {}).get('count', 0)} review, "
                f"{b.get('summary', {}).get('go', {}).get('count', 0)} ready. Nothing was paid."),
        }.get(e["kind"], lambda: e["kind"])()
        recent.append({"seq": e["seq"], "at": e["at"], "kind": e["kind"], "request_id": e["request_id"],
                       "summary": summary, "hash": e["hash"][:16]})
    return {"ok": ok, "detail": detail, "head": gw.org.ledger.head(), "counts": dict(kinds), "recent": recent}


def vendors(gw) -> list[dict]:
    paid = Counter()
    count = Counter()
    for p in gw.org.store.payments(kind="pay"):
        paid[p.vendor_id] += p.amount_cents
        count[p.vendor_id] += 1
    return [{"vendor_id": v.vendor_id, "name": v.name, "account_on_file": last4(v.bank_account),
             "email_domains": list(v.email_domains), "phone": v.phone,
             "bank_changed_on": v.bank_changed_on.isoformat() if v.bank_changed_on else "",
             "payments": count[v.vendor_id], "paid_cents": paid[v.vendor_id]} for v in gw.org.store.vendors()]


def settings(gw, users: list[dict]) -> dict:
    p = gw.org.policy
    return {
        "mode": p.mode, "currency": p.currency, "approval_limit_cents": p.approval_limit_cents,
        "dual_approval_cents": p.dual_approval_cents, "recent_bank_change_days": p.recent_bank_change_days,
        "ticket_hours": p.ticket_hours, "require_two_step": p.require_two_step,
        "agents": [{"agent_id": a, "made_by": s.vendor, "allowed_actions": list(s.allowed_actions),
                    "connected": True,
                    "max_amount_cents": s.max_amount_cents, "daily_cap_cents": s.daily_cap_cents}
                   for a, s in sorted(p.agents.items())],
        "users": users,
    }


def _cell(value) -> str:
    """Spreadsheet-safe text: a leading = + - @ (or tab/CR) would run as a formula in Excel."""
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def activity_csv(gw) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Date", "Agent", "Action", "Vendor", "Invoice", "Amount", "Decision", "Status", "Reasons", "Request id"])
    for r in activity(gw, limit=100_000):
        w.writerow([_cell(x) for x in (r["on"], r["agent_id"], r["action"], r["vendor_name"], r["invoice_number"],
                                       f"{r['amount_cents'] / 100:.2f}" if r["amount_cents"] else "", r["verdict"],
                                       r["status"], "; ".join(r["reasons"]), r["request_id"])])
    return buf.getvalue()



def _n(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def setup(gw, users: list[dict], agent_keys: dict[str, int]) -> dict:
    """What a company has connected, and what the checks still need to work well."""
    store, p = gw.org.store, gw.org.policy
    c = store.counts()
    vendors = store.vendors()
    no_domain = [v.name for v in vendors if not v.email_domains]
    no_phone = [v.name for v in vendors if not v.phone]
    approvers = [u for u in users if u["role"] in ("admin", "approver") and not u["disabled"]]
    live_agents = [a for a in p.agents if agent_keys.get(a)]
    steps = [
        {"id": "vendors", "done": c["vendors"] > 0, "title": "Import your vendor list",
         "detail": f"{c['vendors']} vendors" if c["vendors"] else
         "Who you pay, their bank accounts, email domains and phone numbers."},
        {"id": "pos", "done": c["pos"] > 0, "title": "Import open purchase orders",
         "detail": f"{c['pos']} purchase orders" if c["pos"] else "So amounts can be matched to what was ordered."},
        {"id": "history", "done": c["history"] > 0, "title": "Import past payments",
         "detail": f"{c['history']} past payments" if c["history"] else
         "6 to 12 months, so duplicates and unusual amounts are caught from day one."},
        {"id": "people", "done": len(approvers) >= 2, "title": "Add at least two approvers",
         "detail": f"{len(approvers)} can approve" + ("" if len(approvers) >= 2 else ". Large payments need two different "
                                                       "people, and nobody can approve their own request.")},
        {"id": "two_step", "done": p.require_two_step, "title": "Require two-step sign-in",
         "detail": "Required" if p.require_two_step else "So a stolen password alone can't approve a payment."},
        {"id": "agents", "done": bool(live_agents), "title": "Connect an agent, or check a payment run",
         "detail": f"{len(live_agents)} agents connected" if live_agents else
         "No agents yet? Upload the bills you're about to pay on the Payment run page."},
        {"id": "enforce", "done": p.mode == "enforce", "title": "Switch to enforce",
         "detail": "Enforcing" if p.mode == "enforce" else "After a few weeks of the watch-only report, when you trust it."},
    ]
    health = []
    if no_domain:
        health.append({"level": "warn", "text": f"{_n(len(no_domain), 'vendor has', 'vendors have')} no email domain, "
                       "so emails claiming to be "
                       f"from them can't be checked: {', '.join(no_domain[:5])}{'...' if len(no_domain) > 5 else ''}"})
    if no_phone:
        health.append({"level": "warn", "text": f"{_n(len(no_phone), 'vendor has', 'vendors have')} no phone number "
                       "on file for confirming "
                       f"bank changes: {', '.join(no_phone[:5])}{'...' if len(no_phone) > 5 else ''}"})
    if c["vendors"]:
        health.append({"level": "info", "text": f"{c['vendors_with_history']} of {c['vendors']} vendors have enough "
                       "payment history (8 or more) for the unusual-amount check."})
    return {"steps": steps, "done": sum(s["done"] for s in steps), "health": health, "counts": c}
