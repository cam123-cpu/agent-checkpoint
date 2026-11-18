"""Two numbers outsiders will ask for, read straight from the tamper-evident log.

* **Usage** is what a fee is charged on: payment files checked, lines, releases issued and the money
  they released, allowed-accounts lists issued, agent actions checked. A per-file or per-release
  price can be billed from this without a separate meter that could disagree with the log.

* **Evidence** is what a cyber insurer or a bank's risk team asks for before relying on the control:
  how much of real files was held, how many held lines turned out to be fraud or real mistakes, how
  many were fine, and how much fraud got through anyway (misses). A miss rate is only honest if
  misses are reported as faithfully as catches, so the pack says how many were recorded and says
  plainly when there are too few files to mean anything.
"""

from __future__ import annotations

from collections import Counter


def _in(e: dict, since: str, until: str) -> bool:
    return (not since or e["at"][:10] >= since) and (not until or e["at"][:10] <= until)


def usage(ledger, since: str = "", until: str = "") -> dict:
    entries = [e for e in ledger.entries() if _in(e, since, until)]
    kinds = Counter(e["kind"] for e in entries)
    runs = [e["body"] for e in entries if e["kind"] == "payment_run_checked"]
    releases = [e["body"] for e in entries if e["kind"] == "release_issued"]
    return {
        "since": since, "until": until,
        "payment_files_checked": len(runs),
        "payment_lines_checked": sum(r.get("rows", 0) for r in runs),
        "releases_issued": len(releases),
        "lines_released": sum(r["released"] for r in releases),
        "released_cents": sum(r["released_cents"] for r in releases),
        "allowed_lists_issued": kinds["allowed_accounts_issued"],
        "agent_actions_checked": kinds["decision"],
    }


def evidence(ledger, since: str = "", until: str = "", hold_limit_pct: float = 15.0) -> dict:
    entries = [e for e in ledger.entries() if _in(e, since, until)]
    runs = [e["body"] for e in entries if e["kind"] == "payment_run_checked"]
    lines = sum(r.get("rows", 0) for r in runs)
    held = sum(r["summary"]["pause"]["count"] + r["summary"]["block"]["count"] for r in runs)
    # The latest outcome per line wins (someone corrected a label).
    outcomes: dict[tuple[str, int], dict] = {}
    for e in entries:
        if e["kind"] == "line_outcome":
            outcomes[(e["body"]["run_id"], e["body"]["line"])] = e["body"]
    held_out = [o for o in outcomes.values() if o["verdict"] != "go"]
    caught = [o for o in held_out if o["outcome"] in ("fraud", "error")]
    fine = [o for o in held_out if o["outcome"] == "fine"]
    misses = [e["body"] for e in entries if e["kind"] == "miss_reported"]
    # Lines marked fraud after being released Ready are misses too, even if nobody filed a separate report.
    marked_misses = [o for o in outcomes.values() if o["verdict"] == "go" and o["outcome"] == "fraud"]
    fraud_caught = [o for o in held_out if o["outcome"] == "fraud"]
    n_miss = len(misses) + len(marked_misses)
    fraud_seen = len(fraud_caught) + n_miss
    per_file = [r.get("not_ready_pct", 0.0) for r in runs]
    ok, detail = ledger.verify()
    out = {
        "since": since, "until": until,
        "payment_files": len(runs), "lines_checked": lines,
        "lines_held": held, "held_pct": round(100 * held / lines, 1) if lines else 0.0,
        "files_over_hold_limit": sum(p > hold_limit_pct for p in per_file), "hold_limit_pct": hold_limit_pct,
        "held_lines_reviewed": len(held_out),
        "held_and_real": len(caught), "held_fraud": len(fraud_caught), "held_but_fine": len(fine),
        "precision_pct": round(100 * len(caught) / len(held_out), 1) if held_out else None,
        "misses_recorded": n_miss,
        "missed_cents": sum(m["amount_cents"] for m in misses) + sum(o["amount_cents"] for o in marked_misses),
        "fraud_miss_rate_pct": round(100 * n_miss / fraud_seen, 1) if fraud_seen else None,
        "audit_log": {"ok": ok, "detail": detail, "head": ledger.head()},
    }
    caveats = []
    if len(runs) < 12:
        caveats.append(f"Only {len(runs)} payment file(s). Rates from fewer than about 12 files are anecdotes.")
    if fraud_seen < 5:
        caveats.append(f"Only {fraud_seen} fraud attempt(s) recorded. A miss rate needs many more to mean anything.")
    if held and len(held_out) < held:
        caveats.append(f"{held - len(held_out)} held line(s) have no recorded outcome, so precision is partial.")
    out["caveats"] = caveats
    return out


def render_evidence(company: str, ev: dict) -> str:
    def pct(v):
        return "not enough data" if v is None else f"{v}%"
    lines = [
        f"Control evidence: {company}" + (f", {ev['since']} to {ev['until'] or 'today'}" if ev["since"] else ""),
        "",
        f"Payment files checked     {ev['payment_files']} ({ev['lines_checked']} lines)",
        f"Lines held for review     {ev['lines_held']} ({ev['held_pct']}%); files over the {ev['hold_limit_pct']}% "
        f"limit: {ev['files_over_hold_limit']}",
        f"Held lines with outcome   {ev['held_lines_reviewed']}: {ev['held_and_real']} real ({ev['held_fraud']} fraud), "
        f"{ev['held_but_fine']} fine. Precision {pct(ev['precision_pct'])}",
        f"Misses recorded           {ev['misses_recorded']} (${ev['missed_cents'] / 100:,.2f}). "
        f"Fraud miss rate {pct(ev['fraud_miss_rate_pct'])}",
        f"Audit log                 {'intact' if ev['audit_log']['ok'] else 'BROKEN'}, head "
        f"{ev['audit_log']['head']['seq']}:{ev['audit_log']['head']['hash'][:16]}",
    ]
    if ev["caveats"]:
        lines += ["", "Read with care:"] + [f"  - {c}" for c in ev["caveats"]]
    return "\n".join(lines)
