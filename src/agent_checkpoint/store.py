"""One company's records, in one SQLite file: vendors, POs, payments, tickets, transfers.

Each company gets its own database file (the strongest kind of tenant isolation: there is no
query that can cross companies, because there is no shared table to cross).

In production the vendor master and POs are synced read-only from QuickBooks, Xero or NetSuite
(`importers.py` loads CSV exports today). Payments made *through* the checkpoint are its own
record; the ERP learns about them from the rail.

Bank account numbers, stored requests, tickets and receipts are encrypted at rest
(`crypto.py`); everything that reads them goes through this class.

`tx()` takes SQLite's write lock (`BEGIN IMMEDIATE`) for the whole check-then-execute step, so
two copies of one invoice arriving at the same moment, even from two processes, are checked
one after the other and the second sees the first.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime

from .crypto import Crypto

SCHEMA = """
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS vendors (
    vendor_id TEXT PRIMARY KEY, name TEXT NOT NULL, bank_account TEXT NOT NULL,
    email_domains TEXT NOT NULL DEFAULT '[]', created_on TEXT NOT NULL,
    bank_changed_on TEXT, phone TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS pos (
    number TEXT PRIMARY KEY, vendor_id TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    billed_cents INTEGER NOT NULL DEFAULT 0
);
-- payments: see PAYMENTS_DDL (kept separate so older databases can be upgraded)
CREATE TABLE IF NOT EXISTS tickets (
    ticket_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, request TEXT NOT NULL,
    findings TEXT NOT NULL, status TEXT NOT NULL, needed INTEGER NOT NULL,
    approvals TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    closed_by TEXT, note TEXT NOT NULL DEFAULT '', fraud INTEGER NOT NULL DEFAULT 0, payee_fp TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS transfers (
    receipt_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, receipt TEXT NOT NULL, executed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (agent_id TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS requests (request_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS activity_agent ON activity (agent_id, at);
"""


PAYMENTS_DDL = """
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, agent_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL, invoice_key TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    bank_account TEXT NOT NULL, on_date TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('pay', 'refund')),
    via TEXT NOT NULL CHECK (via IN ('rail', 'observed', 'imported'))
);
CREATE INDEX IF NOT EXISTS payments_vendor ON payments (vendor_id, kind);
"""


def norm_account(acct: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", acct or "").upper()


def _fold(text: str) -> str:
    """Full-width letters, other scripts' digits, invisible characters: fold to plain ASCII where they mean the same."""
    s = unicodedata.normalize("NFKC", text or "")
    return "".join(str(unicodedata.decimal(ch)) if ch.isdecimal() else ch for ch in s)


def norm_invoice(number: str) -> str:
    """INV-0042, inv 42, Invoice #42, ＩＮＶ－４２ → 42. The same invoice arriving twice must match."""
    s = re.sub(r"[^0-9A-Za-z]", "", _fold(number)).upper()
    s = re.sub(r"^(INVOICE|INV|NO|NR)+", "", s)
    return s.lstrip("0") or s


def last4(acct: str) -> str:
    return "..." + norm_account(acct)[-4:]


@dataclass
class Vendor:
    vendor_id: str
    name: str
    bank_account: str
    email_domains: tuple[str, ...]
    created_on: date
    bank_changed_on: date | None = None
    phone: str = ""


@dataclass
class PurchaseOrder:
    number: str
    vendor_id: str
    amount_cents: int
    billed_cents: int = 0

    @property
    def remaining_cents(self) -> int:
        return self.amount_cents - self.billed_cents


@dataclass(frozen=True)
class Payment:
    request_id: str
    agent_id: str
    vendor_id: str
    invoice_key: str
    amount_cents: int
    bank_account: str
    on: date
    kind: str
    via: str




_PAY_COLS = "request_id, agent_id, vendor_id, invoice_key, amount_cents, bank_account, on_date, kind, via"


class Store:
    def __init__(self, path: str, key: bytes):
        self.crypto = Crypto(key)
        self._lock = threading.RLock()
        self._depth = 0
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.executescript(SCHEMA)
        old = self.db.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'payments'").fetchone()
        if old and "'imported'" not in old[0]:  # upgrade: payments imported from history are a new kind of row
            self.db.executescript(
                "BEGIN; DROP INDEX IF EXISTS payments_vendor; ALTER TABLE payments RENAME TO payments_v1;" + PAYMENTS_DDL
                + "INSERT INTO payments SELECT * FROM payments_v1; DROP TABLE payments_v1; COMMIT;")
        self.db.executescript(PAYMENTS_DDL)
        if "payee_fp" not in {r[1] for r in self.db.execute("PRAGMA table_info(tickets)")}:
            self.db.execute("ALTER TABLE tickets ADD COLUMN payee_fp TEXT NOT NULL DEFAULT ''")

    @contextmanager
    def tx(self):
        with self._lock:
            outer = self._depth == 0
            if outer:
                self.db.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self
                self._depth -= 1
                if outer:
                    self.db.execute("COMMIT")
            except BaseException:
                self._depth -= 1
                if outer:
                    self.db.execute("ROLLBACK")
                raise

    @contextmanager
    def scratch(self):
        """A transaction that is always rolled back: for 'what would happen if' checks, like a payment run."""
        with self._lock:
            if self._depth:
                raise RuntimeError("scratch() can't run inside another transaction")
            self.db.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self
            finally:
                self._depth -= 1
                self.db.execute("ROLLBACK")

    def q(self, sql: str, params=()) -> list[tuple]:
        with self._lock:
            return self.db.execute(sql, params).fetchall()

    def _vendor(self, r) -> Vendor:
        return Vendor(r[0], r[1], self.crypto.decrypt(r[2], f"vendors.bank:{r[0]}"), tuple(json.loads(r[3])),
                      date.fromisoformat(r[4]), date.fromisoformat(r[5]) if r[5] else None, r[6])

    def _payment(self, r) -> Payment:
        return Payment(r[0], r[1], r[2], r[3], r[4], self.crypto.decrypt(r[5], f"payments.bank:{r[0]}"),
                       date.fromisoformat(r[6]), r[7], r[8])

    # --- vendor master and POs -----------------------------------------------------------

    def upsert_vendor(self, v: Vendor) -> None:
        self.q("INSERT INTO vendors VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (vendor_id) DO UPDATE SET "
               "name = excluded.name, bank_account = excluded.bank_account, email_domains = excluded.email_domains, "
               "bank_changed_on = excluded.bank_changed_on, phone = excluded.phone",
               (v.vendor_id, v.name, self.crypto.encrypt(v.bank_account, f"vendors.bank:{v.vendor_id}"),
                json.dumps([d.lower() for d in v.email_domains]),
                v.created_on.isoformat(), v.bank_changed_on.isoformat() if v.bank_changed_on else None, v.phone))

    def vendor(self, vendor_id: str) -> Vendor | None:
        rows = self.q("SELECT * FROM vendors WHERE vendor_id = ?", (vendor_id,))
        return self._vendor(rows[0]) if rows else None

    def vendors(self) -> list[Vendor]:
        return [self._vendor(r) for r in self.q("SELECT * FROM vendors ORDER BY vendor_id")]

    def vendor_using_account(self, account: str, other_than: str) -> Vendor | None:
        key = norm_account(account)
        return next((v for v in self.vendors() if v.vendor_id != other_than and norm_account(v.bank_account) == key),
                    None)

    def set_bank(self, vendor_id: str, account: str, on: date) -> None:
        self.q("UPDATE vendors SET bank_account = ?, bank_changed_on = ? WHERE vendor_id = ?",
               (self.crypto.encrypt(account, f"vendors.bank:{vendor_id}"), on.isoformat(), vendor_id))

    def upsert_po(self, po: PurchaseOrder) -> None:
        self.q("INSERT INTO pos VALUES (?, ?, ?, ?) ON CONFLICT (number) DO UPDATE SET "
               "vendor_id = excluded.vendor_id, amount_cents = excluded.amount_cents",
               (po.number, po.vendor_id, po.amount_cents, po.billed_cents))

    def po(self, number: str) -> PurchaseOrder | None:
        rows = self.q("SELECT number, vendor_id, amount_cents, billed_cents FROM pos WHERE number = ?", (number,))
        return PurchaseOrder(*rows[0]) if rows else None

    # --- payments ---------------------------------------------------------------------

    def record_payment(self, p: Payment, po_number: str = "", ignore_existing: bool = False) -> bool:
        verb = "INSERT OR IGNORE" if ignore_existing else "INSERT"
        before = self.db.total_changes
        self.q(f"{verb} INTO payments ({_PAY_COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
               (p.request_id, p.agent_id, p.vendor_id, p.invoice_key, p.amount_cents,
                self.crypto.encrypt(p.bank_account, f"payments.bank:{p.request_id}"),
                p.on.isoformat(), p.kind, p.via))
        inserted = self.db.total_changes > before
        if inserted and p.kind == "pay" and po_number:
            self.q("UPDATE pos SET billed_cents = billed_cents + ? WHERE number = ?", (p.amount_cents, po_number))
        return inserted

    def payments(self, vendor_id: str | None = None, kind: str | None = None) -> list[Payment]:
        sql, params = f"SELECT {_PAY_COLS} FROM payments WHERE 1 = 1", []
        if vendor_id:
            sql, params = sql + " AND vendor_id = ?", params + [vendor_id]
        if kind:
            sql, params = sql + " AND kind = ?", params + [kind]
        return [self._payment(r) for r in self.q(sql + " ORDER BY id", params)]

    def spent_on(self, agent_id: str, on: date) -> int:
        return self.q("SELECT COALESCE(SUM(amount_cents), 0) FROM payments WHERE agent_id = ? AND on_date = ?",
                      (agent_id, on.isoformat()))[0][0]

    def counts(self) -> dict:
        return {
            "vendors": self.q("SELECT COUNT(*) FROM vendors")[0][0],
            "pos": self.q("SELECT COUNT(*) FROM pos")[0][0],
            "history": self.q("SELECT COUNT(*) FROM payments WHERE via = 'imported'")[0][0],
            "payments": self.q("SELECT COUNT(*) FROM payments WHERE kind = 'pay'")[0][0],
            "vendors_with_history": self.q("SELECT COUNT(*) FROM (SELECT vendor_id FROM payments WHERE kind = 'pay' "
                                           "GROUP BY vendor_id HAVING COUNT(*) >= 8)")[0][0],
        }

    def all_pay_amounts(self) -> list[int]:
        return [r[0] for r in self.q("SELECT amount_cents FROM payments WHERE kind = 'pay'")]

    # --- tickets ----------------------------------------------------------------------

    def add_ticket(self, ticket_id: str, request: dict, findings: list[dict], needed: int,
                   created_at: datetime, expires_at: datetime, payee_fp: str = "") -> None:
        self.q("INSERT INTO tickets (ticket_id, request_id, request, findings, status, needed, created_at, expires_at, "
               "payee_fp) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)",
               (ticket_id, request["request_id"], self.crypto.encrypt(json.dumps(request), f"tickets:{ticket_id}"),
                json.dumps(findings), needed,
                created_at.isoformat(), expires_at.isoformat(), payee_fp))

    def ticket(self, ticket_id: str) -> dict | None:
        rows = self.q("SELECT ticket_id, request_id, request, findings, status, needed, approvals, created_at, "
                      "expires_at, closed_by, note, fraud, payee_fp FROM tickets WHERE ticket_id = ?", (ticket_id,))
        if not rows:
            return None
        r = rows[0]
        return {"ticket_id": r[0], "request_id": r[1], "request": json.loads(self.crypto.decrypt(r[2], f"tickets:{r[0]}")),
                "findings": json.loads(r[3]),
                "status": r[4], "needed": r[5], "approvals": json.loads(r[6]), "created_at": r[7],
                "expires_at": r[8], "closed_by": r[9], "note": r[10], "fraud": bool(r[11]), "payee_fp": r[12]}

    def ticket_for(self, request_id: str) -> dict | None:
        rows = self.q("SELECT ticket_id FROM tickets WHERE request_id = ?", (request_id,))
        return self.ticket(rows[0][0]) if rows else None

    def tickets(self, status: str | None = None) -> list[dict]:
        rows = self.q("SELECT ticket_id FROM tickets" + (" WHERE status = ?" if status else "") +
                      " ORDER BY created_at", (status,) if status else ())
        return [self.ticket(r[0]) for r in rows]

    def update_ticket(self, ticket_id: str, *, status: str, approvals: list, closed_by=None, note="",
                      fraud=False) -> None:
        self.q("UPDATE tickets SET status = ?, approvals = ?, closed_by = ?, note = ?, fraud = ? WHERE ticket_id = ?",
               (status, json.dumps(approvals), closed_by, note, int(fraud), ticket_id))

    def set_ticket_findings(self, ticket_id: str, findings: list[dict]) -> None:
        self.q("UPDATE tickets SET findings = ? WHERE ticket_id = ?", (json.dumps(findings), ticket_id))

    def open_ticket_for_invoice(self, vendor_id: str, invoice_key: str) -> dict | None:
        for t in self.tickets("open"):
            r = t["request"]
            if r["action"] == "pay" and r["vendor_id"] == vendor_id and norm_invoice(r["invoice_number"]) == invoice_key:
                return t
        return None

    # --- transfers and activity -------------------------------------------------------

    def record_transfer(self, receipt_id: str, request_id: str, receipt: dict, at: datetime) -> bool:
        try:
            self.q("INSERT INTO transfers VALUES (?, ?, ?, ?)",
                   (receipt_id, request_id, self.crypto.encrypt(json.dumps(receipt), f"transfers:{receipt_id}"),
                    at.isoformat()))
            return True
        except sqlite3.IntegrityError:
            return False

    def transfer_for(self, request_id: str) -> str | None:
        rows = self.q("SELECT receipt_id FROM transfers WHERE request_id = ?", (request_id,))
        return rows[0][0] if rows else None

    def save_request(self, request: dict) -> None:
        rid = request["request_id"]
        self.q("INSERT INTO requests VALUES (?, ?, ?)",
               (rid, request["agent_id"], self.crypto.encrypt(json.dumps(request), f"requests:{rid}")))

    def get_request(self, request_id: str) -> dict | None:
        rows = self.q("SELECT body FROM requests WHERE request_id = ?", (request_id,))
        return json.loads(self.crypto.decrypt(rows[0][0], f"requests:{request_id}")) if rows else None

    def note_activity(self, agent_id: str, at: datetime) -> None:
        self.q("INSERT INTO activity VALUES (?, ?)", (agent_id, at.isoformat()))

    def activity_since(self, agent_id: str, since: datetime) -> int:
        return self.q("SELECT COUNT(*) FROM activity WHERE agent_id = ? AND at >= ?",
                      (agent_id, since.isoformat()))[0][0]
