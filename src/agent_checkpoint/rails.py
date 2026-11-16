"""Payment rails: where money actually moves, and the only code that holds bank credentials.

The agent has no rail. It asks the checkpoint; the checkpoint signs a receipt; the rail checks
the receipt and moves the money. A real deployment implements `Rail` for a bank API (ACH, wire,
SEPA) or for the ERP's bill-payment API, and keeps those credentials inside the checkpoint's
deployment, never in the agent's.

`SandboxRail` is the reference implementation: it does every check a real rail must do
(signature, expiry, single use, contents match) and records transfers instead of sending them.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from .receipts import ReceiptError, Verifier
from .store import Store, norm_account


class Rail(Protocol):
    def execute(self, receipt: dict, *, payee_account: str, amount_cents: int, now: datetime) -> str:
        """Move the money. Return a transfer id. Raise ReceiptError if anything doesn't match."""


class SandboxRail:
    def __init__(self, store: Store, verifier: Verifier):
        self.store = store
        self.verifier = verifier

    def execute(self, receipt: dict, *, payee_account: str, amount_cents: int, now: datetime) -> str:
        body = self.verifier.verify(receipt, now)
        if body["action"] not in ("pay", "refund"):
            raise ReceiptError("receipt is not for a money movement")
        if norm_account(body["payee_account"]) != norm_account(payee_account):
            raise ReceiptError("payee account does not match the receipt")
        if body["amount_cents"] != amount_cents:
            raise ReceiptError("amount does not match the receipt")
        if not self.store.record_transfer(body["receipt_id"], body["request_id"], receipt, now):
            raise ReceiptError("receipt (or request) was already used")
        return body["receipt_id"]
