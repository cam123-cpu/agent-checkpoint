"""The checkpoint: every agent action goes through `submit`, every human decision through `resolve`.

Modes (set per company in policy.json):

- **shadow**: the agent is told GO and its own tools carry on; the checkpoint records what it
  *would* have done. Builds the "here's what I would have stopped" report with no risk to
  the customer.
- **enforce**: the agent gets the real verdict, and money moves only through the checkpoint's
  rail with a signed receipt. PAUSE opens a ticket and notifies approvers. Above the dual-approval
  limit, two different people must approve. Unanswered tickets expire (fail closed). When the
  last approval arrives, the checks run again, so something that changed in the meantime (the
  same invoice paid another way, say) is caught before money moves.

Every step is written to the ledger: the request, the verdict and why, who approved, the receipt.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .checks import Context, _sender_strings, domain_of, evaluate, learned_weights
from .intel import Intel, shared_domain
from .ledger import Ledger
from .models import RANK, ActionRequest, Decision, Finding, Verdict, money
from .notify import Notifier
from .policy import Policy
from .rails import Rail
from .receipts import ReceiptError, Signer
from .release import account_tag
from .release import sign as sign_doc
from .store import Payment, Store, last4, norm_account, norm_invoice


class CheckpointError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


@dataclass
class Org:
    org_id: str
    name: str
    store: Store
    ledger: Ledger
    policy: Policy
    signer: Signer
    rail: Rail
    notifier: Notifier
    intel: Intel | None = None


def utcnow() -> datetime:
    return datetime.now(UTC)


def phone_message(org: Org, req: ActionRequest, findings) -> str:
    v = org.store.vendor(req.vendor_id)
    who = v.name if v else req.vendor_id
    verb = {"pay": f"pay {money(req.amount_cents)} to", "refund": f"refund {money(req.amount_cents)} to",
            "change_bank": f"change the bank account (to {last4(req.bank_account)}) for",
            "edit_record": f"edit invoice {req.invoice_number} for"}[req.action]
    reasons = "; ".join(f.message for f in findings if f.verdict is Verdict.PAUSE)
    return f"{org.name}: agent {req.agent_id} wants to {verb} {who}. {reasons}. Approve?"


_ACCOUNTISH = re.compile(r"\b(?=[A-Za-z0-9 ]*\d{6})[A-Za-z]{0,4}\d[\dA-Za-z ]{7,40}\d\b")


def masked_request(req: dict, crypto) -> dict:
    """What the audit log keeps: account numbers as last 4 + a keyed fingerprint, never in full."""
    d = json.loads(json.dumps(req))
    for k in ("bank_account", "bank_account_on_invoice"):
        if d.get(k):
            d[k] = f"{last4(d[k])} fp:{crypto.fingerprint(norm_account(d[k]))}"
    for e in d.get("evidence", []):
        if e.get("excerpt"):
            e["excerpt"] = _ACCOUNTISH.sub(lambda m: f"[account {last4(m.group(0))}]", e["excerpt"])
    return d


def pilot_measure(summary: dict, limit_pct: float) -> dict:
    """The number that decides a pilot: how much of an ordinary file was held. Over the limit, people stop
    working the queue, and the checks don't fit their books."""
    total = sum(v["count"] for v in summary.values())
    held = summary["pause"]["count"] + summary["block"]["count"]
    pct = round(100 * held / total, 1) if total else 0.0
    return {"lines": total, "not_ready": held, "not_ready_pct": pct, "limit_pct": limit_pct,
            "over_limit": pct > limit_pct}


def _digits(phone: str) -> str:
    return "".join(ch for ch in (phone or "") if ch.isdigit())


def _run_row(row: dict) -> dict:
    return {"line": row["line"], "vendor_id": row["vendor_id"], "vendor_name": row["vendor_name"],
            "invoice_number": row["invoice_number"], "amount_cents": row["amount_cents"],
            "account_in_file": last4(row["bank_account"]) if row.get("bank_account") else ""}


def _findings_from(rows) -> tuple[Finding, ...]:
    return tuple(Finding(f["check"], Verdict(f["verdict"]), f["message"], f.get("weight", 0.0)) for f in rows)


class Gateway:
    def __init__(self, org: Org, clock: Callable[[], datetime] = utcnow):
        self.org = org
        self.clock = clock

    # --- agents -----------------------------------------------------------------------

    def submit(self, raw: dict, *, agent_id: str, actor: str = "agent") -> Decision:
        org, start, now = self.org, time.perf_counter(), self.clock()
        try:
            req = ActionRequest.from_dict(raw, agent_id=agent_id, on=now.date())
        except ValueError as exc:
            rid = str(raw.get("request_id", "-"))[:128] if isinstance(raw, dict) else "-"
            org.ledger.append("rejected", rid, {"agent_id": agent_id, "error": str(exc)})
            raise CheckpointError(422, str(exc)) from exc

        notify = None
        with org.store.tx():
            previous = org.ledger.find(req.request_id, "decision")
            if previous is not None:
                old = ActionRequest.from_stored(org.store.get_request(req.request_id))
                if old.agent_id != agent_id or old.fingerprint() != req.fingerprint():
                    raise CheckpointError(409, "request_id was already used for a different action")
                return self._replay(previous)

            org.store.note_activity(agent_id, now)
            ctx = Context(
                store=org.store, policy=org.policy, now=now, intel=org.intel, org_id=org.org_id, actor=actor,
                spent_today_cents=org.store.spent_on(agent_id, req.on),
                recent_actions=org.store.activity_since(agent_id, now - timedelta(minutes=1)) - 1,
                weights=learned_weights(org.store.tickets("approved") + org.store.tickets("rejected")),
            )
            verdict, risk, findings = evaluate(req, ctx)
            mode = org.policy.mode
            returned = Verdict.GO if mode == "shadow" else verdict
            d = Decision(req.request_id, verdict, returned, mode, risk, findings)
            if returned is Verdict.PAUSE:
                d.ticket_id, d.status = "T-" + uuid.uuid4().hex[:12], "awaiting_approval"
                needed = 2 if req.amount_cents >= org.policy.dual_approval_cents else 1
                org.store.add_ticket(d.ticket_id, req.to_dict(), self._rows(findings), needed, now,
                                     now + timedelta(hours=org.policy.ticket_hours), self._payee_fp(req))
                notify = (d.ticket_id, phone_message(org, req, findings))
            elif returned is Verdict.BLOCK:
                d.status = "blocked"
            d.elapsed_ms = (time.perf_counter() - start) * 1000
            full = req.to_dict()
            org.store.save_request(full)
            org.ledger.append("decision", req.request_id, {
                **d.to_dict(), "request": masked_request(full, org.store.crypto),
                "request_sha256": hashlib.sha256(json.dumps(full, sort_keys=True).encode()).hexdigest(),
                "findings_full": self._rows(findings)})
            if returned is Verdict.GO:
                # Shadow tells the agent to go on. A block is still not written into the books: not the
                # vendor's account, not the payment, and not the purchase order it would have used up.
                # Those writes are what a later enforce-mode payment would trust.
                d.status, d.transfer_id = self._execute(req, [], now, apply_books=verdict is not Verdict.BLOCK)
        if notify:
            org.notifier.send(*notify, org.policy.approvers)
        return d

    # --- people (web app) -------------------------------------------------------------

    def submit_person(self, raw: dict, person: str) -> Decision:
        """A request made by a signed-in person (for example a bank change after a vendor phoned). Same checks as
        an agent's, except agent limits; it always needs a *different* person to approve (the requester rule)."""
        raw = {**raw, "instructed_by": {"source": "human", "identity": person}}
        return self.submit(raw, agent_id="person:" + person, actor="person")

    # --- payment runs -----------------------------------------------------------------

    def check_run(self, rows: list[dict], person: str, file_sha256: str) -> dict:
        """Check a list of bills about to be paid, without paying or changing anything.

        Every row goes through the same checks as an agent's payment. Rows are checked in order inside a
        transaction that is always rolled back: each row that would be paid is recorded *temporarily*, so a
        later row in the same file is seen as a duplicate or a split, and then nothing is kept.
        """
        org, now = self.org, self.clock()
        results = []
        weights = learned_weights(org.store.tickets("approved") + org.store.tickets("rejected"))
        with org.store.scratch():
            for row in rows:
                raw = {"request_id": f"run-L{row['line']}", "action": "pay", "vendor_id": row["vendor_id"],
                       "amount_cents": row["amount_cents"], "invoice_number": row["invoice_number"],
                       "evidence": [{"kind": "invoice", "ref": f"payment run line {row['line']}"}],
                       "instructed_by": {"source": "human", "identity": person}}
                if row.get("po_number"):
                    raw["po_number"] = row["po_number"]
                if row.get("bank_account"):
                    raw["bank_account_on_invoice"] = row["bank_account"]
                # No currency column: the file is in the company's currency. A column names it per line, and an
                # amount in another currency is never converted: it's held.
                raw["currency"] = row.get("currency") or org.policy.currency
                try:
                    req = ActionRequest.from_dict(raw, agent_id="payment-run", on=now.date())
                except ValueError as exc:
                    results.append({**_run_row(row), "verdict": "block", "risk": 100, "reasons": [str(exc)]})
                    continue
                ctx = Context(org.store, org.policy, now, org.intel, org.org_id, weights=weights, actor="run")
                verdict, risk, findings = evaluate(req, ctx)
                if row.get("invoice_missing"):
                    findings = list(findings) + [Finding("no_invoice_number", Verdict.PAUSE,
                                                         "No invoice number on this line, so a duplicate can't be "
                                                         "caught. Add it, or check by hand.", 0.4)]
                    if verdict is Verdict.GO:
                        verdict = Verdict.PAUSE
                results.append({**_run_row(row), "verdict": verdict.value, "risk": risk,
                                "reasons": [f.message for f in sorted(findings, key=lambda f: -RANK[f.verdict])]})
                if verdict is not Verdict.BLOCK:
                    vendor = org.store.vendor(req.vendor_id)
                    org.store.record_payment(Payment(req.request_id, "payment-run", req.vendor_id,
                                                     norm_invoice(req.invoice_number), req.amount_cents,
                                                     norm_account(vendor.bank_account if vendor else ""), req.on, "pay",
                                                     "observed"), po_number=req.po_number)
        summary = {v: {"count": sum(r["verdict"] == v for r in results),
                       "amount_cents": sum(r["amount_cents"] for r in results if r["verdict"] == v)}
                   for v in ("go", "pause", "block")}
        order = {"block": 0, "pause": 1, "go": 2}
        shown = sorted(results, key=lambda r: (order[r["verdict"]], -r["risk"], r["line"]))
        pilot = pilot_measure(summary, org.policy.pilot_hold_limit_pct)
        run_id = f"run-{now.strftime('%Y%m%dT%H%M%S')}-{file_sha256[:10]}"
        org.ledger.append("payment_run_checked", run_id, {
            "run_id": run_id, "by": person, "checked_at": now.isoformat(), "file_sha256": file_sha256,
            "rows": len(rows), "summary": summary,
            "not_ready_pct": pilot["not_ready_pct"],
            "lines": [{k: r[k] for k in ("line", "vendor_id", "vendor_name", "invoice_number", "amount_cents",
                                         "account_in_file", "verdict", "risk", "reasons")} for r in shown],
        })
        return {"run_id": run_id, "rows": shown, "summary": summary, "pilot": pilot}

    # --- in the path: documents a payment system can check -------------------------------

    def release_run(self, run_id: str, person: str) -> dict:
        """Sign which lines of a checked payment file may be released, and where each may go.

        Only lines that were Ready are released. The file is named by its SHA-256, so a changed file has no
        release. A release is issued at most once per run and expires after policy.release_hours.
        """
        org, now = self.org, self.clock()
        if person not in org.policy.approvers:
            raise CheckpointError(403, "only approvers can release a payment file")
        run = org.ledger.find(run_id, "payment_run_checked")
        if run is None:
            raise CheckpointError(404, "no such payment run")
        if org.ledger.find(run_id, "release_issued"):
            raise CheckpointError(409, "this payment run was already released. Check the file again for a new one.")
        checked_at = datetime.fromisoformat(run["checked_at"])
        if now - checked_at > timedelta(hours=org.policy.release_hours):
            raise CheckpointError(409, f"this check is more than {org.policy.release_hours} hours old. Check the "
                                       "file again: the books may have changed.")
        salt = uuid.uuid4().hex
        release, hold = [], []
        for line in sorted(run["lines"], key=lambda r: r["line"]):
            vendor = org.store.vendor(line["vendor_id"])
            if line["verdict"] != "go" or vendor is None:
                hold.append(line["line"])
                continue
            release.append({"line": line["line"], "vendor_id": line["vendor_id"], "invoice_number": line["invoice_number"],
                            "amount_cents": line["amount_cents"], "account_tag": account_tag(salt, vendor.bank_account),
                            "account_last4": last4(vendor.bank_account)})
        body = {"release_id": "RL-" + uuid.uuid4().hex, "org_id": org.org_id, "company": org.name, "run_id": run_id,
                "file_sha256": run["file_sha256"], "checked_at": checked_at.isoformat(), "issued_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=org.policy.release_hours)).isoformat(), "issued_by": person,
                "currency": org.policy.currency, "salt": salt, "release": release, "hold": hold,
                "released_cents": sum(r["amount_cents"] for r in release),
                "held_cents": sum(r["amount_cents"] for r in run["lines"] if r["line"] in set(hold))}
        doc = sign_doc(org.signer, "release", body)
        org.ledger.append("release_issued", run_id, {
            "release_id": body["release_id"], "by": person, "file_sha256": body["file_sha256"],
            "released": len(release), "released_cents": body["released_cents"], "held": len(hold),
            "held_cents": body["held_cents"], "doc_sha256": doc["sha256"]})
        return doc

    def allowed_accounts(self, person: str) -> dict:
        """The locked list of where this company pays, signed, for a bank or payment system to check against.

        Every account on it was set by an import before go-live or by a bank change that a second person
        approved after calling the number on file. Versions only go up; a partner keeps the newest it has seen.
        """
        org, now = self.org, self.clock()
        if person not in org.policy.approvers:
            raise CheckpointError(403, "only approvers can issue the allowed-accounts list")
        version = len(org.ledger.entries("allowed_accounts_issued")) + 1
        salt = uuid.uuid4().hex
        accounts = [{"vendor_id": v.vendor_id, "vendor_name": v.name, "account_tag": account_tag(salt, v.bank_account),
                     "account_last4": last4(v.bank_account)} for v in org.store.vendors() if norm_account(v.bank_account)]
        body = {"list_id": f"AL-{org.org_id}-{version}", "org_id": org.org_id, "company": org.name, "version": version,
                "issued_at": now.isoformat(), "issued_by": person,
                "expires_at": (now + timedelta(days=org.policy.allowed_list_days)).isoformat(),
                "salt": salt, "accounts": accounts}
        doc = sign_doc(org.signer, "allowed_accounts", body)
        org.ledger.append("allowed_accounts_issued", body["list_id"], {
            "version": version, "by": person, "accounts": len(accounts), "doc_sha256": doc["sha256"]})
        return doc

    # --- outcomes: what actually happened, for the miss rate -----------------------------

    OUTCOMES = ("fraud", "error", "fine")

    def mark_line(self, run_id: str, line: int, outcome: str, person: str, note: str = "") -> dict:
        """After the fact: was a held line really fraud, a real mistake (duplicate, wrong amount), or fine?"""
        if outcome not in self.OUTCOMES:
            raise CheckpointError(422, "outcome must be fraud, error or fine")
        run = self.org.ledger.find(run_id, "payment_run_checked")
        if run is None:
            raise CheckpointError(404, "no such payment run")
        match = [r for r in run["lines"] if r["line"] == line]
        if not match:
            raise CheckpointError(404, f"line {line} is not in that payment run")
        entry = {"run_id": run_id, "line": line, "verdict": match[0]["verdict"], "outcome": outcome,
                 "amount_cents": match[0]["amount_cents"], "by": person, "note": note[:500]}
        self.org.ledger.append("line_outcome", run_id, entry)
        return entry

    def report_miss(self, person: str, amount_cents: int, vendor_id: str = "", run_id: str = "", line: int = 0,
                    note: str = "") -> dict:
        """Money that was lost or nearly lost and the checkpoint said Ready, or never saw. This is the number an
        insurer asks for first; it only means something if misses are recorded as faithfully as catches."""
        if amount_cents <= 0:
            raise CheckpointError(422, "amount must be positive")
        verdict = ""
        if run_id:
            run = self.org.ledger.find(run_id, "payment_run_checked")
            if run is None:
                raise CheckpointError(404, "no such payment run")
            verdict = next((r["verdict"] for r in run["lines"] if r["line"] == line), "")
        entry = {"by": person, "amount_cents": amount_cents, "vendor_id": vendor_id[:64], "run_id": run_id,
                 "line": line, "verdict_given": verdict or "not checked", "note": note[:500]}
        self.org.ledger.append("miss_reported", run_id or "-", entry)
        return entry

    def status(self, request_id: str, agent_id: str | None = None) -> dict:
        previous = self.org.ledger.find(request_id, "decision")
        if previous is None or (agent_id and previous["request"]["agent_id"] != agent_id):
            raise CheckpointError(404, "no such request")
        return self._replay(previous).to_dict()

    def _replay(self, previous: dict) -> Decision:
        rid = previous["request_id"]
        d = Decision(rid, Verdict(previous["verdict"]), Verdict(previous["returned"]), previous["mode"],
                     previous["risk"], _findings_from(previous["findings_full"]), previous.get("ticket_id"),
                     replayed=True)
        t = self.org.store.ticket_for(rid)
        transfer = self.org.store.transfer_for(rid)
        executed = self.org.ledger.find(rid, "executed")
        if t:
            d.status = {"open": "awaiting_approval"}.get(t["status"], t["status"])
            if t["status"] == "approved" and executed:
                d.status, d.returned = executed["status"], Verdict.GO
            elif t["status"] in ("rejected", "expired", "blocked_on_recheck"):
                d.returned = Verdict.BLOCK
        elif executed:
            d.status = executed["status"]
        else:
            d.status = "blocked" if d.returned is Verdict.BLOCK else previous.get("status", "")
        d.transfer_id = transfer
        return d

    # --- humans -----------------------------------------------------------------------

    def resolve(self, ticket_id: str, approver: str, approve: bool, note: str = "", *,
                callback_verified: bool = False, fraud: bool = False, called_number: str = "") -> dict:
        org, now = self.org, self.clock()
        with org.store.tx():
            t = org.store.ticket(ticket_id)
            if t is None:
                raise CheckpointError(404, "no such ticket")
            if t["status"] != "open":
                raise CheckpointError(409, f"ticket is already {t['status']}")
            req = ActionRequest.from_stored(t["request"])
            if approver not in org.policy.approvers:
                raise CheckpointError(403, f"{approver} is not an approver for {org.name}")
            if req.instructed_by and req.instructed_by.identity.lower() == approver.lower():
                raise CheckpointError(403, "the person who asked for an action can't approve it")
            if now > datetime.fromisoformat(t["expires_at"]):
                org.store.update_ticket(ticket_id, status="expired", approvals=t["approvals"])
                org.ledger.append("human_decision", req.request_id, {"ticket_id": ticket_id, "status": "expired"})
                raise CheckpointError(409, "ticket has expired")
            approvals = list(t["approvals"])
            if approve:
                if req.action == "change_bank":
                    vendor = org.store.vendor(req.vendor_id)
                    on_file = _digits(vendor.phone if vendor else "")
                    if not callback_verified:
                        raise CheckpointError(422, "bank changes need callback_verified: confirm by phone with "
                                                   "the number on file first")
                    if not on_file:
                        raise CheckpointError(422, "This vendor has no phone number on file, so the change can't be "
                                                   "confirmed. Add one first (a second person approves it).")
                    if _digits(called_number) != on_file:
                        raise CheckpointError(422, "Enter the number you called. It must be the number on file, not "
                                                   "one from the request.")
                if any(a["by"] == approver for a in approvals):
                    raise CheckpointError(409, "you have already approved this; a second approver is needed")
                approvals.append({"by": approver, "at": now.isoformat(), "note": note[:500],
                                  "callback_verified": callback_verified,
                                  "called_number": _digits(called_number) if req.action == "change_bank" else ""})
                status = "approved" if len(approvals) >= t["needed"] else "open"
            else:
                status = "rejected"
            entry = {"ticket_id": ticket_id, "approver": approver, "approve": approve, "status": status,
                     "note": note[:500], "fraud": fraud, "callback_verified": callback_verified}
            if approve and req.action == "change_bank":
                entry["called_number"] = _digits(called_number)

            if status == "approved":
                # Re-check: anything that changed since the pause and now blocks wins.
                ctx = Context(org.store, org.policy, now, org.intel, org.org_id,
                              org.store.spent_on(req.agent_id, now.date()),
                              actor="person" if req.agent_id.startswith("person:") else "agent")
                verdict, _, findings = evaluate(req, ctx)
                new_blocks = [f for f in findings if f.verdict is Verdict.BLOCK]
                if t.get("payee_fp") and t["payee_fp"] != self._payee_fp(req):
                    new_blocks.append(Finding("payee_changed", Verdict.BLOCK,
                                              f"The account this would be paid to changed after it was paused (now "
                                              f"{last4(self._payee(req)) or 'none'}), so it isn't the one you were "
                                              "shown. Nothing was paid; review it again as a new request.", 1.0))
                seen = {f["check"] for f in t["findings"]}
                new_pauses = [f for f in findings if f.verdict is Verdict.PAUSE and f.check not in seen]
                if new_blocks:
                    status = "blocked_on_recheck"
                    entry.update(status=status, recheck=[f.message for f in new_blocks])
                elif new_pauses:
                    # Something new needs a look (a split the earlier approval couldn't see, a daily cap...).
                    # Approvals so far were given without it, so they're cleared and the ticket stays open.
                    status, approvals = "open", []
                    org.store.set_ticket_findings(ticket_id, t["findings"] + self._rows(new_pauses))
                    entry.update(status="reopened", recheck=[f.message for f in new_pauses])
            org.store.update_ticket(ticket_id, status=status, approvals=approvals,
                                    closed_by=approver if status != "open" else None, note=note[:500], fraud=fraud)
            org.ledger.append("human_decision", req.request_id, entry)
            result = {"ticket_id": ticket_id, "status": status, "approvals": len(approvals), "needed": t["needed"]}
            if status == "approved":
                result["execution"], result["transfer_id"] = self._execute(req, [a["by"] for a in approvals], now)
            if status == "blocked_on_recheck" or entry.get("status") == "reopened":
                result["reasons"] = entry["recheck"]
                result["reopened"] = entry.get("status") == "reopened"
            if fraud and not approve:
                self._report_fraud(req)
        return result

    def report_fraud(self, request_id: str, reporter: str) -> None:
        """For blocked actions (no ticket): send what was seen to the shared fraud network."""
        if reporter not in self.org.policy.approvers:
            raise CheckpointError(403, "only approvers can report fraud")
        previous = self.org.ledger.find(request_id, "decision")
        if previous is None:
            raise CheckpointError(404, "no such request")
        req = ActionRequest.from_stored(self.org.store.get_request(request_id))
        self._report_fraud(req)
        self.org.ledger.append("fraud_report", request_id, {"by": reporter})

    def _reportable(self, req: ActionRequest) -> tuple[set[str], set[str]]:
        """What a fraud report on this request would list: only what the fraudster supplied."""
        vendor = self.org.store.vendor(req.vendor_id)
        on_file = norm_account(vendor.bank_account) if vendor else ""
        accounts = {a for a in {req.bank_account, req.bank_account_on_invoice} - {""}
                    if norm_account(a) != on_file or req.action == "change_bank"}
        # Only the address each message really came from, never the vendor's or our own domains, and never a
        # free-mail domain: a report must not put a real company (or ourselves, or gmail.com) on the list.
        protected = set(vendor.email_domains if vendor else ()) | set(self.org.policy.internal_domains)
        domains = {d for d in {domain_of(s) for s in _sender_strings(req)} - protected - {""} if not shared_domain(d)}
        return accounts, domains

    def _report_fraud(self, req: ActionRequest) -> None:
        if self.org.intel is None:
            return
        accounts, domains = self._reportable(req)
        for acct in accounts:
            self.org.intel.report(self.org.org_id, account=acct)
        for d in domains:
            self.org.intel.report(self.org.org_id, domain=d)

    def withdraw_report(self, request_id: str, person: str, reason: str = "") -> dict:
        """Take back this company's fraud report for a request (it was the real vendor after all)."""
        if person not in self.org.policy.approvers:
            raise CheckpointError(403, "only approvers can withdraw a fraud report")
        stored = self.org.store.get_request(request_id)
        if stored is None or self.org.intel is None:
            raise CheckpointError(404, "no such request")
        req = ActionRequest.from_stored(stored)
        accounts, domains = self._reportable(req)
        n = sum(self.org.intel.withdraw(self.org.org_id, account=a) for a in accounts)
        n += sum(self.org.intel.withdraw(self.org.org_id, domain=d) for d in domains)
        if not n:
            raise CheckpointError(404, "this company has no fraud report for that request")
        self.org.ledger.append("fraud_report_withdrawn", request_id, {"by": person, "reason": reason[:500],
                                                                      "entries": n})
        return {"request_id": request_id, "withdrawn": n}

    def expire(self) -> list[str]:
        now, done = self.clock(), []
        with self.org.store.tx():
            for t in self.org.store.tickets("open"):
                if now > datetime.fromisoformat(t["expires_at"]):
                    self.org.store.update_ticket(t["ticket_id"], status="expired", approvals=t["approvals"])
                    self.org.ledger.append("human_decision", t["request_id"],
                                           {"ticket_id": t["ticket_id"], "status": "expired"})
                    done.append(t["ticket_id"])
        return done

    # --- doing it ---------------------------------------------------------------------

    def _payee(self, req: ActionRequest) -> str:
        """Where money for this action would go right now. Payments: the account on file. Refunds: the account
        the original payment used. This is what the approver is shown, and what is paid."""
        if req.action == "pay":
            vendor = self.org.store.vendor(req.vendor_id)
            return vendor.bank_account if vendor else ""
        if req.action == "refund":
            key = norm_invoice(req.invoice_number)
            originals = [p for p in self.org.store.payments(req.vendor_id, "pay") if p.invoice_key == key]
            return originals[0].bank_account if originals else req.bank_account
        return ""

    def _payee_fp(self, req: ActionRequest) -> str:
        payee = self._payee(req)
        return self.org.store.crypto.fingerprint(norm_account(payee)) if payee else ""

    @staticmethod
    def _rows(findings) -> list[dict]:
        return [{"check": f.check, "verdict": f.verdict.value, "message": f.message, "weight": f.weight}
                for f in findings]

    def _execute(self, req: ActionRequest, approved_by: list[str], now: datetime, *,
                 apply_books: bool = True) -> tuple[str, str | None]:
        org, store = self.org, self.org.store
        vendor = store.vendor(req.vendor_id)
        shadow = org.policy.mode == "shadow"
        key = norm_invoice(req.invoice_number)
        transfer_id = None
        if req.action in ("pay", "refund"):
            payee = self._payee(req) or req.bank_account_on_invoice
            if not shadow:
                receipt = org.signer.issue(request_id=req.request_id, action=req.action, vendor_id=req.vendor_id,
                                           amount_cents=req.amount_cents, payee_account=payee, invoice_key=key,
                                           approved_by=approved_by, now=now)
                try:
                    transfer_id = org.rail.execute(receipt, payee_account=payee, amount_cents=req.amount_cents,
                                                   now=now)
                except ReceiptError as exc:
                    org.ledger.append("execution_failed", req.request_id, {"error": str(exc)})
                    return "failed", None
            if apply_books:
                store.record_payment(Payment(req.request_id, req.agent_id, req.vendor_id, key, req.amount_cents,
                                             norm_account(payee), req.on, req.action,
                                             "observed" if shadow else "rail"),
                                     po_number=req.po_number if req.action == "pay" else "")
        elif req.action == "change_bank" and vendor and apply_books:
            store.set_bank(req.vendor_id, req.bank_account, req.on)
        status = "observed" if shadow else "executed"
        done = {
            "agent_id": req.agent_id, "action": req.action, "on": req.on.isoformat(), "status": status,
            "approved_by": approved_by, "transfer_id": transfer_id, "books_changed": bool(apply_books),
        }
        if req.action == "change_bank":
            done["bank_change_applied"] = bool(vendor and apply_books)
        org.ledger.append("executed", req.request_id, done)
        return status, transfer_id
