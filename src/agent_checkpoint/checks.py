"""The checks. Each is a pure function of (request, context) → findings.

Checks don't know about each other: adding one means writing a function and adding it to
CHECKS. The verdict is the strictest any check returns (block > pause > go). The risk score
is a noisy-OR of the findings' weights, `1 − Π(1 − wᵢ)`, as in the invoice detector, with
weights tuned per company from approvers' past decisions (`learned_weights`). Learning changes
only the *ranking* of the approval queue, never a verdict, so feedback can't train the
checkpoint into letting something through.

If a check itself fails (a bug, bad data), the checkpoint **fails closed**: the action is
blocked and the error is recorded.
"""

from __future__ import annotations

import math
import re
import statistics
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher

from .intel import Intel
from .models import RANK, ActionRequest, Finding, Verdict, money
from .policy import Policy
from .store import Store, last4, norm_account, norm_invoice

B, P = Verdict.BLOCK, Verdict.PAUSE


@dataclass
class Context:
    store: Store
    policy: Policy
    now: datetime
    intel: Intel | None = None
    org_id: str = ""
    spent_today_cents: int = 0
    recent_actions: int = 0
    weights: dict[str, float] = field(default_factory=dict)
    actor: str = "agent"  # agent | person (a request made in the web app) | run (a row of an uploaded payment run)


_ADDR = re.compile(r"[^\s<>\"'(),;:@]+@([^\s<>\"'(),;:@]+)")


def domain_of(address: str) -> str:
    """The domain that actually sent it: the address in <angle brackets> if there is one, else the first address."""
    folded = unicodedata.normalize("NFKC", address or "")
    bracket = re.findall(r"<([^<>]*)>", folded)
    target = bracket[-1] if bracket else folded
    m = _ADDR.search(target)
    return m.group(1).strip(".").lower() if m else ""


def display_spoof(address: str) -> str | None:
    """'"billing@vendor.com" <x@evil.example>': the name shows one address, the mail came from another."""
    folded = unicodedata.normalize("NFKC", address or "")
    if "<" not in folded:
        return None
    real = domain_of(folded)
    shown = {m.group(1).strip(".").lower() for m in _ADDR.finditer(re.sub(r"<[^<>]*>", " ", folded))}
    other = sorted(d for d in shown if d != real)
    return other[0] if other and real else None


def _sender_strings(req: ActionRequest) -> list[str]:
    out = [e.sender for e in req.evidence if e.kind == "email" and e.sender]
    out += [e.sender for e in req.evidence if e.kind == "invoice" and e.sender]
    if req.instructed_by and req.instructed_by.source == "email":
        out.append(req.instructed_by.identity)
    return out


def _senders(req: ActionRequest) -> list[str]:
    """Every sending domain mentioned, real sender first. Forwarded 'x@vendor via ap@us' yields both."""
    out = []
    for s in _sender_strings(req):
        for d in [domain_of(s)] + [m.group(1).strip(".").lower() for m in _ADDR.finditer(unicodedata.normalize("NFKC", s))]:
            if d and d not in out:
                out.append(d)
    return out


def check_display_spoof(req, ctx):
    if req.action not in ("pay", "change_bank", "refund"):
        return []
    for s in _sender_strings(req):
        shown = display_spoof(s)
        if shown:
            return [Finding("display_name_spoof", B, f"The sender's name shows an address at {shown}, but the message "
                                                     f"came from {domain_of(s)}", 0.95)]
    return []


# --- every action ---------------------------------------------------------------------

def check_scope(req, ctx):
    if ctx.actor != "agent":
        return []  # people and payment runs aren't agents; their limits are the approval rules
    scope = ctx.policy.agents.get(req.agent_id)
    if scope is None:
        return [Finding("agent_scope", B, f"Agent {req.agent_id} is not registered with the checkpoint", 1.0)]
    out = []
    if req.action not in scope.allowed_actions:
        out.append(Finding("agent_scope", B, f"Agent {req.agent_id} is not allowed to {req.action.replace('_', ' ')}",
                           1.0))
    if req.amount_cents > scope.max_amount_cents and req.action in ("pay", "refund"):
        out.append(Finding("agent_scope", B, f"{money(req.amount_cents)} is over this agent's per-action limit "
                                             f"of {money(scope.max_amount_cents)}", 0.9))
    elif req.action in ("pay", "refund") and ctx.spent_today_cents + req.amount_cents > scope.daily_cap_cents:
        out.append(Finding("daily_cap", P, f"Would take this agent to {money(ctx.spent_today_cents + req.amount_cents)}"
                                           f" today, over its daily cap of {money(scope.daily_cap_cents)}", 0.5))
    return out


def check_burst(req, ctx):
    if ctx.actor == "agent" and ctx.recent_actions >= ctx.policy.burst_per_minute:
        return [Finding("burst", P, f"{ctx.recent_actions} actions from this agent in the last minute: "
                                    "possible runaway loop", 0.6)]
    return []


def check_provenance(req, ctx):
    out = []
    if req.instructed_by is None:
        out.append(Finding("provenance", B, "No one is recorded as having asked for this", 0.9))
    if not req.evidence:
        out.append(Finding("provenance", B, "No evidence attached (invoice, PO, email or ticket)", 0.9))
    elif req.action == "pay" and not any(e.kind == "invoice" for e in req.evidence):
        out.append(Finding("provenance", B, "Payment with no invoice attached", 0.9))
    return out


def check_currency(req, ctx):
    if req.action in ("pay", "refund") and req.currency != ctx.policy.currency:
        return [Finding("currency", B, f"Amount is in {req.currency}; this company pays in {ctx.policy.currency}",
                        0.8)]
    return []


def check_vendor_known(req, ctx):
    if ctx.store.vendor(req.vendor_id) is None:
        return [Finding("unknown_vendor", B, f"Vendor {req.vendor_id} is not in the vendor master", 0.9)]
    return []


def check_fraud_network(req, ctx):
    if ctx.intel is None:
        return []
    out = []
    for acct in {req.bank_account, req.bank_account_on_invoice} - {""}:
        n = ctx.intel.account_reports(acct)
        if n:
            out.append(Finding("known_fraud", B, f"Account {last4(acct)} was reported as fraud by {n} "
                                                 f"compan{'y' if n == 1 else 'ies'} on the network", 0.99))
    for d in set(_senders(req)):
        n = ctx.intel.domain_reports(d)
        if n:
            out.append(Finding("known_fraud", B, f"Requests from {d} were reported as fraud by {n} "
                                                 f"compan{'y' if n == 1 else 'ies'} on the network", 0.97))
    return out


# --- payments -------------------------------------------------------------------------

def check_invoice_account(req, ctx):
    """The invoice prints a different account: the classic redirection attempt (or prompt injection)."""
    v = ctx.store.vendor(req.vendor_id)
    if req.action != "pay" or v is None or not req.bank_account_on_invoice:
        return []
    if norm_account(req.bank_account_on_invoice) != norm_account(v.bank_account):
        if ctx.actor == "run":  # in a payment file, this IS where the money would go
            return [Finding("payment_file_account", B,
                            f"The payment file sends this to account {last4(req.bank_account_on_invoice)}, but the "
                            f"account on file for {v.name} is {last4(v.bank_account)}", 0.95)]
        return [Finding("invoice_account_differs", P,
                        f"Invoice lists account {last4(req.bank_account_on_invoice)}, but the account on file for "
                        f"{v.name} is {last4(v.bank_account)}. Payment would go to the account on file; "
                        "confirm with the vendor by phone before changing anything", 0.8)]
    return []


def check_sender(req, ctx):
    """An invoice or refund request from a domain that isn't the vendor's (look-alikes are blocked)."""
    v = ctx.store.vendor(req.vendor_id)
    if req.action not in ("pay", "refund") or v is None or not v.email_domains:
        return []
    known = set(v.email_domains)
    out: list[Finding] = []
    for d in _senders(req):
        if d in known or d in ctx.policy.internal_domains:
            continue
        lookalike = _lookalike(d, known)
        if lookalike:
            return [Finding("lookalike_domain", B, f"Sent from {d}, a look-alike of {lookalike}, the real domain "
                                                   f"for {v.name}", 0.95)]
        out = out or [Finding("unknown_sender", P, f"Sent from {d}, which is not a known domain for {v.name}", 0.6)]
    return out


def _lookalike(domain: str, known: set[str]) -> str | None:
    """Close spelling, a known domain hidden in a longer one (vendor.com.evil.example), or punycode."""
    for k in known:
        if SequenceMatcher(None, domain, k).ratio() >= 0.8 or domain.startswith(k + ".") or (
                domain.startswith("xn--") or ".xn--" in domain):
            return k
    return None


def check_recent_bank_change(req, ctx):
    v = ctx.store.vendor(req.vendor_id)
    if req.action != "pay" or v is None or v.bank_changed_on is None:
        return []
    age = (req.on - v.bank_changed_on).days
    if 0 <= age <= ctx.policy.recent_bank_change_days:
        when = "today" if age == 0 else f"{age} day{'s' if age != 1 else ''} ago"
        return [Finding("recent_bank_change", P, f"Bank account for {v.name} changed {when}", 0.8)]
    return []


def check_po(req, ctx):
    if req.action != "pay":
        return []
    if not req.po_number:
        # Payment runs list bills already approved in accounts payable, and rarely carry PO numbers.
        if ctx.actor != "run" and req.amount_cents > ctx.policy.require_po_above_cents:
            return [Finding("no_po", P, f"No purchase order for a {money(req.amount_cents)} payment", 0.5)]
        return []
    po = ctx.store.po(req.po_number)
    if po is None:
        return [Finding("po_unknown", P, f"Purchase order {req.po_number} is not in the books", 0.6)]
    if po.vendor_id != req.vendor_id:
        return [Finding("po_wrong_vendor", B, f"PO {po.number} belongs to a different vendor", 0.85)]
    remaining = po.remaining_cents
    if remaining <= 0:
        return [Finding("po_exhausted", B, f"PO {po.number} is already fully billed", 0.8)]
    if req.amount_cents > remaining * (1 + ctx.policy.po_tolerance):
        ratio = req.amount_cents / remaining
        for factor in (10, 100, 1000):
            if abs(ratio - factor) / factor < 0.01:
                return [Finding("amount_magnitude", B, f"{money(req.amount_cents)} is {factor}x the {money(remaining)} "
                                                       f"left on PO {po.number}: looks like a misplaced decimal", 0.9)]
        return [Finding("po_overrun", P, f"{money(req.amount_cents)} is more than the {money(remaining)} left on "
                                         f"PO {po.number}", 0.6)]
    return []


def check_duplicate(req, ctx):
    if req.action != "pay":
        return []
    key = norm_invoice(req.invoice_number)
    prior = ctx.store.payments(req.vendor_id, "pay")
    for p in prior:
        if key and p.invoice_key == key:
            if p.request_id.startswith("run-L"):
                return [Finding("duplicate_payment", B, f"Invoice {req.invoice_number} is also on line "
                                                        f"{p.request_id[5:]} of this payment run", 0.95)]
            return [Finding("duplicate_payment", B, f"Invoice {req.invoice_number} was already paid on "
                                                    f"{p.on.isoformat()} ({money(p.amount_cents)})", 0.95)]
    waiting = ctx.store.open_ticket_for_invoice(req.vendor_id, key)
    if waiting and waiting["request_id"] != req.request_id:
        return [Finding("duplicate_pending", B, f"Invoice {req.invoice_number} is already waiting for approval "
                                                f"(ticket {waiting['ticket_id']})", 0.9)]
    for p in prior:
        if p.amount_cents == req.amount_cents and abs((p.on - req.on).days) <= ctx.policy.near_duplicate_days:
            if p.request_id.startswith("run-L"):
                return [Finding("near_duplicate", P, f"Same amount to the same vendor on line {p.request_id[5:]} of this "
                                                     "payment run, under a different invoice number", 0.5)]
            return [Finding("near_duplicate", P, f"Same amount paid to this vendor {abs((p.on - req.on).days)} days "
                                                 "earlier under a different invoice number", 0.5)]
    return []


def check_approval_limit(req, ctx):
    if req.action in ("pay", "refund") and req.amount_cents >= ctx.policy.approval_limit_cents:
        extra = " (two approvers)" if req.amount_cents >= ctx.policy.dual_approval_cents else ""
        return [Finding("approval_limit", P, f"{money(req.amount_cents)} is at or above the "
                                             f"{money(ctx.policy.approval_limit_cents)} approval limit{extra}", 0.3)]
    return []


def check_split(req, ctx):
    """Several bills just under the limit, close together, that add up to more than it."""
    lim = ctx.policy.approval_limit_cents
    if req.action != "pay" or req.amount_cents >= lim:
        return []
    window = [p for p in ctx.store.payments(req.vendor_id, "pay")
              if abs((req.on - p.on).days) <= ctx.policy.split_window_days and p.amount_cents < lim]
    total = sum(p.amount_cents for p in window) + req.amount_cents
    if window and total >= lim:
        return [Finding("split_payment", P, f"{len(window) + 1} payments to this vendor within "
                                            f"{ctx.policy.split_window_days} days, each under the approval limit, "
                                            f"total {money(total)}", 0.5)]
    return []


def check_amount_outlier(req, ctx):
    """Robust z-score on log amounts against this vendor's own history (median and MAD)."""
    if req.action != "pay":
        return []
    hist = [p.amount_cents for p in ctx.store.payments(req.vendor_id, "pay")]
    if len(hist) < ctx.policy.outlier_min_history:
        return []
    logs = [math.log(a) for a in hist]
    med = statistics.median(logs)
    mad = max(statistics.median(abs(x - med) for x in logs), 0.08)
    z = 0.6745 * (math.log(req.amount_cents) - med) / mad
    if z > ctx.policy.outlier_z:
        typical = round(math.exp(med))
        return [Finding("amount_outlier", P, f"{money(req.amount_cents)} is {req.amount_cents / typical:.1f} times this "
                                             f"vendor's usual {money(typical)}, well outside its normal range",
                        0.75 if z > 8 else 0.55)]
    return []


def check_new_vendor(req, ctx):
    v = ctx.store.vendor(req.vendor_id)
    if req.action != "pay" or v is None or (req.on - v.created_on).days > ctx.policy.new_vendor_days:
        return []
    amounts = ctx.store.all_pay_amounts()
    if len(amounts) >= 10 and req.amount_cents > ctx.policy.new_vendor_multiple * statistics.median(amounts):
        return [Finding("new_vendor_large", P, f"{v.name} was added {(req.on - v.created_on).days} days ago and "
                                               f"this is over {ctx.policy.new_vendor_multiple:g}x a typical payment", 0.4)]
    return []


def _norm_name(name: str) -> str:
    out = "".join(ch for ch in name.lower() if ch.isalnum() or ch == " ")
    for suffix in (" inc", " llc", " ltd", " corp", " co", " gmbh"):
        out = out.removesuffix(suffix)
    return " ".join(out.split())


def check_lookalike_vendor(req, ctx):
    v = ctx.store.vendor(req.vendor_id)
    if req.action != "pay" or v is None:
        return []
    mine = _norm_name(v.name)
    for other in ctx.store.vendors():
        if other.vendor_id == v.vendor_id or other.created_on > v.created_on:
            continue  # flag the newer of the two names only
        if SequenceMatcher(None, mine, _norm_name(other.name)).ratio() >= ctx.policy.lookalike_name_ratio:
            return [Finding("lookalike_vendor", P, f"{v.name} looks like existing vendor {other.name}", 0.5)]
    return []


# --- bank changes, refunds, edits -------------------------------------------------------

def check_bank_change(req, ctx):
    v = ctx.store.vendor(req.vendor_id)
    if req.action != "change_bank" or v is None:
        return []
    out = [Finding("bank_change", P, f"Bank change for {v.name}: the approver must call "
                                     f"{v.phone or 'the number on file'} (not a number from the request) "
                                     "and confirm before approving", 0.6)]
    if norm_account(req.bank_account) == norm_account(v.bank_account):
        return [Finding("bank_change_noop", B, "That is already the account on file", 0.3)]
    shared = ctx.store.vendor_using_account(req.bank_account, v.vendor_id)
    if shared:
        out.append(Finding("shared_account", B, f"Account {last4(req.bank_account)} already belongs to another "
                                                f"vendor, {shared.name}", 0.9))
    known = set(v.email_domains)
    for d in _senders(req):
        if d in known or d in ctx.policy.internal_domains:
            continue
        lookalike = _lookalike(d, known)
        if lookalike:
            out.append(Finding("lookalike_domain", B, f"Request came from {d}, a look-alike of {lookalike}, the real "
                                                      f"domain for {v.name}", 0.95))
        else:
            out.append(Finding("unknown_sender", B, f"Request came from {d}, which is not a known domain for "
                                                    f"{v.name}", 0.85))
        break
    return out


def check_refund(req, ctx):
    if req.action != "refund":
        return []
    key = norm_invoice(req.invoice_number)
    original = [p for p in ctx.store.payments(req.vendor_id, "pay") if p.invoice_key == key]
    if not original:
        return [Finding("refund_no_original", B, f"No payment for invoice {req.invoice_number} to refund", 0.9)]
    paid = sum(p.amount_cents for p in original)
    refunded = sum(p.amount_cents for p in ctx.store.payments(req.vendor_id, "refund") if p.invoice_key == key)
    out = []
    if refunded + req.amount_cents > paid:
        out.append(Finding("refund_exceeds", B, f"Refunds would total {money(refunded + req.amount_cents)}, more "
                                                f"than the {money(paid)} originally paid", 0.9))
    if req.bank_account and norm_account(req.bank_account) not in {p.bank_account for p in original}:
        out.append(Finding("refund_new_account", B, "Refund going to an account the original payment didn't use", 0.9))
    return out


def check_edit(req, ctx):
    if req.action != "edit_record":
        return []
    key = norm_invoice(req.invoice_number)
    if any(p.invoice_key == key for p in ctx.store.payments(req.vendor_id)):
        return [Finding("edit_paid_record", B, f"Invoice {req.invoice_number} is paid; paid records are corrected "
                                               "with a credit note, not edited", 0.8)]
    return []


CHECKS = (
    check_scope, check_burst, check_provenance, check_currency, check_vendor_known, check_fraud_network, check_display_spoof,
    check_sender, check_invoice_account, check_recent_bank_change, check_po, check_duplicate, check_approval_limit,
    check_split, check_amount_outlier, check_new_vendor, check_lookalike_vendor,
    check_bank_change, check_refund, check_edit,
)


def evaluate(req: ActionRequest, ctx: Context) -> tuple[Verdict, int, tuple[Finding, ...]]:
    findings: list[Finding] = []
    for check in CHECKS:
        try:
            findings.extend(check(req, ctx))
        except Exception as exc:  # fail closed
            findings.append(Finding("checkpoint_error", B, f"{check.__name__} failed ({type(exc).__name__}); "
                                                           "blocked until it can be checked", 1.0))
    verdict = max((f.verdict for f in findings), key=RANK.__getitem__, default=Verdict.GO)
    keep = 1.0
    for f in findings:
        keep *= 1 - ctx.weights.get(f.check, 1.0) * f.weight
    return verdict, round(100 * (1 - keep)), tuple(findings)


def learned_weights(closed_tickets: list[dict]) -> dict[str, float]:
    """Per-check multiplier from approvers' decisions: (rejected + 5) / (decided + 5), floor 0.05.

    A check whose pauses are always approved fades in the queue ranking; one whose pauses are
    rejected keeps full weight. The +5 is a prior so a couple of decisions can't swing it.
    """
    seen: dict[str, list[int]] = {}
    for t in closed_tickets:
        if t["status"] not in ("approved", "rejected"):
            continue
        for check in {f["check"] for f in t["findings"]}:
            approved, rejected = seen.setdefault(check, [0, 0])
            seen[check] = [approved + (t["status"] == "approved"), rejected + (t["status"] == "rejected")]
    return {c: max(0.05, (r + 5) / (a + r + 5)) for c, (a, r) in seen.items()}

