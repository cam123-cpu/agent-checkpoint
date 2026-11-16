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
from .intel import Intel
from .ledger import Ledger
from .models import RANK, ActionRequest, Decision, Finding, Verdict, money
from .notify import Notifier
from .policy import Policy
from .rails import Rail
from .receipts import ReceiptError, Signer
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
                try:
                    req = ActionRequest.from_dict(raw, agent_id="payment-run", on=now.date())
                except ValueError as exc:
                    results.append({**_run_row(row), "verdict": "block", "risk": 100, "reasons": [str(exc)]})
                    continue
                ctx = Context(org.store, org.policy, now, org.intel, org.org_id, weights=weights, actor="run")
                verdict, risk, findings = evaluate(req, ctx)
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
        org.ledger.append("payment_run_checked", "-", {
            "by": person, "file_sha256": file_sha256, "rows": len(rows), "summary": summary,
            "lines": [{k: r[k] for k in ("line", "vendor_id", "vendor_name", "invoice_number", "amount_cents",
                                         "account_in_file", "verdict", "risk", "reasons")} for r in shown],
        })
        return {"rows": shown, "summary": summary}

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

    def _report_fraud(self, req: ActionRequest) -> None:
        if self.org.intel is None:
            return
        vendor = self.org.store.vendor(req.vendor_id)
        on_file = norm_account(vendor.bank_account) if vendor else ""
        # Only what the fraudster supplied: never the vendor's real account or real domain.
        accounts = {req.bank_account, req.bank_account_on_invoice} - {""}
        for acct in accounts:
            if norm_account(acct) != on_file or req.action == "change_bank":
                self.org.intel.report(self.org.org_id, account=acct)
        # Only the address each message really came from, and never the vendor's or our own domains: a report
        # must not put a real company (or ourselves) on everyone's block list.
        protected = set(vendor.email_domains if vendor else ()) | set(self.org.policy.internal_domains)
        for d in {domain_of(s) for s in _sender_strings(req)} - protected - {""}:
            self.org.intel.report(self.org.org_id, domain=d)

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
