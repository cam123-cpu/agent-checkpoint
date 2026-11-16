"""What crosses the checkpoint: an agent's request, and the decision it gets back.

Design rules enforced here, at the boundary:

- **Agents never choose where money goes.** A payment is made to the bank account in the
  company's vendor master. The agent may report the account *printed on the invoice*
  (`bank_account_on_invoice`) as evidence, and a mismatch is a red flag, but it can't direct
  funds there.
- **Agents don't set the date or their own identity.** Both come from the checkpoint (its clock,
  and the key the agent authenticated with), so an agent can't backdate an action out of the
  "bank changed recently" window or pose as another agent.
- **Money is integer cents.** Amounts from language models arrive as decimal strings and are
  parsed exactly, never through floats.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation
from enum import Enum


class Verdict(str, Enum):
    GO = "go"
    PAUSE = "pause"
    BLOCK = "block"


RANK = {Verdict.GO: 0, Verdict.PAUSE: 1, Verdict.BLOCK: 2}

ACTIONS = ("pay", "change_bank", "refund", "edit_record")
EVIDENCE_KINDS = ("invoice", "purchase_order", "email", "ticket", "contract", "receipt", "other")
INSTRUCTION_SOURCES = ("human", "email", "schedule", "agent", "system")
MAX_CENTS = 10**13
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")


def money(cents: int, currency: str = "USD") -> str:
    sign = "-" if cents < 0 else ""
    symbol = {"USD": "$", "EUR": "€", "GBP": "£"}.get(currency, currency + " ")
    return f"{sign}{symbol}{abs(cents) / 100:,.2f}"


def parse_amount(value) -> int:
    """'4800', '4,800.00', 4800.5 → cents. Rejects anything ambiguous instead of guessing."""
    if isinstance(value, bool):
        raise ValueError("amount must be a number")
    if isinstance(value, int):
        d = Decimal(value)
    elif isinstance(value, float):
        d = Decimal(repr(value))
    elif isinstance(value, str):
        s = value.strip().replace("$", "").replace("USD", "").replace(",", "").strip()
        if not re.fullmatch(r"\d+(\.\d{1,2})?", s):
            raise ValueError(f"amount {value!r} must look like 4800 or 4800.00")
        d = Decimal(s)
    else:
        raise ValueError("amount must be a number or a decimal string")
    try:
        cents = d * 100
    except InvalidOperation as exc:  # pragma: no cover
        raise ValueError("bad amount") from exc
    if cents != cents.to_integral_value():
        raise ValueError("amount has more than two decimal places")
    cents = int(cents)
    if cents <= 0 or cents > MAX_CENTS:
        raise ValueError("amount must be positive and realistic")
    return cents


@dataclass(frozen=True)
class Evidence:
    """Something that justifies the action. `sha256` lets an auditor match the exact file."""

    kind: str
    ref: str
    sender: str = ""
    sha256: str = ""
    excerpt: str = ""  # short text the agent relied on; stored, never interpreted


@dataclass(frozen=True)
class Instruction:
    """Who told the agent to do this. An email is a stranger until proven otherwise."""

    source: str
    identity: str


@dataclass(frozen=True)
class ActionRequest:
    request_id: str
    agent_id: str
    action: str
    vendor_id: str
    on: date
    amount_cents: int = 0
    currency: str = "USD"
    invoice_number: str = ""
    po_number: str = ""
    bank_account: str = ""             # change_bank: the new account; refund: where the agent says it goes
    bank_account_on_invoice: str = ""  # pay: what the invoice printed (evidence only)
    memo: str = ""
    evidence: tuple[Evidence, ...] = ()
    instructed_by: Instruction | None = None

    FIELDS = frozenset({
        "request_id", "action", "vendor_id", "amount", "amount_cents", "currency", "invoice_number",
        "po_number", "bank_account", "bank_account_on_invoice", "memo", "evidence", "instructed_by",
    })

    @classmethod
    def from_dict(cls, d: dict, *, agent_id: str, on: date) -> ActionRequest:
        if not isinstance(d, dict):
            raise ValueError("request must be a JSON object")
        extra = set(d) - cls.FIELDS
        if extra:
            raise ValueError(f"unknown fields: {sorted(extra)} (agent_id and date are set by the checkpoint)")
        for key in ("request_id", "action", "vendor_id"):
            if not isinstance(d.get(key), str) or not d[key].strip():
                raise ValueError(f"{key} is required")
        if not _ID.match(d["request_id"].strip()):
            raise ValueError("request_id may use letters, digits and ._:- (max 128)")
        action = d["action"]
        if action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")

        if "amount" in d and "amount_cents" in d:
            raise ValueError("give amount or amount_cents, not both")
        amount = 0
        if "amount_cents" in d:
            amount = d["amount_cents"]
            if not isinstance(amount, int) or isinstance(amount, bool) or not 0 < amount <= MAX_CENTS:
                raise ValueError("amount_cents must be a positive integer")
        elif "amount" in d:
            amount = parse_amount(d["amount"])
        if action in ("pay", "refund") and amount == 0:
            raise ValueError(f"{action} needs an amount")
        if action in ("change_bank", "edit_record") and amount:
            raise ValueError(f"{action} takes no amount")

        bank = str(d.get("bank_account", "") or "")
        if action == "pay" and bank:
            raise ValueError("payments go to the account on file; report the invoice's account in "
                             "bank_account_on_invoice instead")
        if action == "change_bank" and not bank:
            raise ValueError("change_bank needs bank_account")
        if action != "pay" and d.get("bank_account_on_invoice"):
            raise ValueError("bank_account_on_invoice is only for payments")
        if action in ("pay", "refund", "edit_record") and not str(d.get("invoice_number", "")).strip():
            raise ValueError(f"{action} needs invoice_number")

        evidence = []
        raw_ev = d.get("evidence", []) or []
        if not isinstance(raw_ev, list) or len(raw_ev) > 20:
            raise ValueError("evidence must be a list of at most 20 items")
        for e in raw_ev:
            if not isinstance(e, dict) or e.get("kind") not in EVIDENCE_KINDS or not str(e.get("ref", "")).strip():
                raise ValueError(f"each evidence item needs kind in {EVIDENCE_KINDS} and ref")
            unknown = set(e) - {"kind", "ref", "sender", "sha256", "excerpt"}
            if unknown:
                raise ValueError(f"unknown evidence fields: {sorted(unknown)}")
            sha = str(e.get("sha256", "")).lower()
            if sha and not re.fullmatch(r"[0-9a-f]{64}", sha):
                raise ValueError("evidence sha256 must be 64 hex characters")
            evidence.append(Evidence(e["kind"], str(e["ref"])[:300], str(e.get("sender", ""))[:200], sha,
                                     str(e.get("excerpt", ""))[:1000]))
        instr = d.get("instructed_by")
        instruction = None
        if instr is not None:
            if (not isinstance(instr, dict) or instr.get("source") not in INSTRUCTION_SOURCES
                    or not str(instr.get("identity", "")).strip() or set(instr) - {"source", "identity"}):
                raise ValueError(f"instructed_by needs source in {INSTRUCTION_SOURCES} and identity")
            instruction = Instruction(instr["source"], str(instr["identity"])[:200])
        currency = str(d.get("currency", "USD")).upper()
        if not re.fullmatch(r"[A-Z]{3}", currency):
            raise ValueError("currency must be a 3-letter code")
        return cls(
            request_id=d["request_id"].strip(), agent_id=agent_id, action=action,
            vendor_id=d["vendor_id"].strip()[:64], on=on, amount_cents=amount, currency=currency,
            invoice_number=str(d.get("invoice_number", "")).strip()[:64],
            po_number=str(d.get("po_number", "")).strip()[:64], bank_account=bank.strip()[:64],
            bank_account_on_invoice=str(d.get("bank_account_on_invoice", "") or "").strip()[:64],
            memo=str(d.get("memo", ""))[:500], evidence=tuple(evidence), instructed_by=instruction,
        )

    def to_dict(self) -> dict:
        out = asdict(self)
        out["on"] = self.on.isoformat()
        out["evidence"] = [asdict(e) for e in self.evidence]
        return out

    @classmethod
    def from_stored(cls, d: dict) -> ActionRequest:
        d = dict(d)
        d["on"] = date.fromisoformat(d["on"])
        d["evidence"] = tuple(Evidence(**e) for e in d["evidence"])
        d["instructed_by"] = Instruction(**d["instructed_by"]) if d["instructed_by"] else None
        return cls(**d)

    def fingerprint(self) -> dict:
        """What must match for a retry to count as the same request (date excluded)."""
        d = self.to_dict()
        d.pop("on")
        return d


@dataclass(frozen=True)
class Finding:
    check: str
    verdict: Verdict
    message: str
    weight: float


@dataclass
class Decision:
    request_id: str
    verdict: Verdict          # what the checkpoint concluded
    returned: Verdict         # what the agent was told (GO in shadow mode)
    mode: str
    risk: int
    findings: tuple[Finding, ...] = ()
    ticket_id: str | None = None
    transfer_id: str | None = None
    status: str = ""          # executed | observed | awaiting_approval | blocked | rejected | expired
    elapsed_ms: float = 0.0
    replayed: bool = field(default=False, compare=False)

    def next_step(self) -> str:
        if self.returned is Verdict.BLOCK:
            return ("Blocked. Do not retry this action or try to achieve it another way. "
                    "Tell the person who asked what the checkpoint found.")
        if self.returned is Verdict.PAUSE:
            return (f"Waiting for human approval (ticket {self.ticket_id}). Do not resubmit. "
                    "Check back later with the request id.")
        if self.status == "observed":
            return "Allowed (shadow mode: recorded only)."
        return "Done. The checkpoint executed it."

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id, "verdict": self.verdict.value, "returned": self.returned.value,
            "mode": self.mode, "risk": self.risk, "status": self.status, "ticket_id": self.ticket_id,
            "transfer_id": self.transfer_id, "elapsed_ms": round(self.elapsed_ms, 2),
            "findings": [{"check": f.check, "verdict": f.verdict.value, "message": f.message}
                         for f in self.findings],
            "next_step": self.next_step(), "replayed": self.replayed,
        }
