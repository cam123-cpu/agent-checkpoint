"""The shadow-mode report: what the checkpoint would have stopped, from the company's own traffic.

This is the document that sells enforcement. It is built only from the ledger, so every line
traces to the entry (and the evidence) that produced it.
"""

from __future__ import annotations

from collections import Counter

from .models import money


def shadow_report(ledger, since: str = "", until: str = "") -> dict:
    blocked, paused, total, by_agent = [], [], 0, Counter()
    for e in ledger.entries("decision"):
        b = e["body"]
        req = b["request"]
        if (since and req["on"] < since) or (until and req["on"] > until):
            continue
        total += 1
        by_agent[req["agent_id"]] += 1
        if b["verdict"] == "go":
            continue
        item = {
            "request_id": b["request_id"], "on": req["on"], "agent": req["agent_id"], "action": req["action"],
            "vendor": req["vendor_id"], "amount_cents": req["amount_cents"], "verdict": b["verdict"],
            "risk": b["risk"], "reasons": [f["message"] for f in b["findings"]], "ledger_seq": e["seq"],
            "told_agent": b["returned"],
        }
        (blocked if b["verdict"] == "block" else paused).append(item)
    key = lambda i: (-i["risk"], i["on"])  # noqa: E731
    money_moves = ("pay", "refund")
    runs = []
    for e in ledger.entries("payment_run_checked"):
        b = e["body"]
        when = e["at"][:10]
        if (since and when < since) or (until and when > until):
            continue
        runs.append({"at": e["at"], "by": b.get("by", ""), "file_sha256": b.get("file_sha256", ""),
                     "summary": b.get("summary", {}), "lines": b.get("lines", []), "ledger_seq": e["seq"]})
    return {
        "actions_checked": total, "by_agent": dict(by_agent),
        "would_block": sorted(blocked, key=key), "would_pause": sorted(paused, key=key),
        "blocked_money_cents": sum(i["amount_cents"] for i in blocked if i["action"] in money_moves),
        "paused_money_cents": sum(i["amount_cents"] for i in paused if i["action"] in money_moves),
        "payment_runs": runs,
    }


def render_text(rep: dict, title: str = "Shadow-mode report") -> str:
    agents = ", ".join(f"{a} ({n})" for a, n in sorted(rep["by_agent"].items()))
    lines = [title, "=" * len(title),
             f"{rep['actions_checked']} agent actions checked from {len(rep['by_agent'])} agents: {agents}.",
             f"Would have BLOCKED {len(rep['would_block'])} ({money(rep['blocked_money_cents'])} in payments) "
             f"and sent {len(rep['would_pause'])} to a human ({money(rep['paused_money_cents'])}).", ""]
    for label, items in (("Would have blocked", rep["would_block"]), ("Would have paused", rep["would_pause"])):
        if not items:
            continue
        lines.append(label + ":")
        for i in items:
            amt = f" {money(i['amount_cents'])}" if i["amount_cents"] else ""
            lines.append(f"  [{i['risk']:>3}] {i['on']}  {i['action']}{amt} → {i['vendor']}  "
                         f"(agent {i['agent']}, ledger #{i['ledger_seq']})")
            lines.extend(f"        - {r}" for r in i["reasons"])
        lines.append("")
    for run in rep.get("payment_runs", []):
        summary = run.get("summary") or {}
        ready = summary.get("go", {}).get("count", 0)
        review = summary.get("pause", {}).get("count", 0)
        stop = summary.get("block", {}).get("count", 0)
        lines.append(f"Payment file checked by {run['by']} (ledger #{run['ledger_seq']}): "
                     f"{ready} ready, {review} review, {stop} don't pay. Nothing was paid.")
        for row in run.get("lines", []):
            if row.get("verdict") == "go":
                continue
            lines.append(f"  [{row['verdict']}] line {row['line']}  {money(row['amount_cents'])}  "
                         f"{row['vendor_name']}  {row['invoice_number']}")
            lines.extend(f"        - {r}" for r in row.get("reasons", []))
        lines.append("")
    return "\n".join(lines)
