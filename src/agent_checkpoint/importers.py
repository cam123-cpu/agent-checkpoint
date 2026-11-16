"""Bring a company's own records in: vendors, purchase orders, payment history, and payment runs to check.

Every accounting system exports with its own column names, so columns are matched by meaning:
"Supplier", "Vendor name" and "Payee" all mean the vendor; "Invoice #", "Bill no" and "Reference"
mean the invoice number. In Excel, save the sheet as "CSV UTF-8" and upload it.

Rules that keep imports from becoming a way around the checkpoint:
- An import never changes an existing vendor's bank account. That only happens through a bank-change
  request that a person approves after a phone call (pen test PT-16).
- Bad rows are reported by line number and skipped; good rows go in together, in one transaction.
- Dates like 03/04/2026 are ambiguous. The person picks month-first or day-first; anything that
  doesn't parse is reported, never guessed.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from datetime import date, datetime

from .models import parse_amount
from .store import Payment, PurchaseOrder, Store, Vendor, norm_account, norm_invoice

MAX_ROWS = 5000

FIELDS = {
    "vendor_id": ["vendor id", "vendor_id", "supplier id", "vendor no", "vendor number", "vendor code", "supplier code",
                  "payee id", "id"],
    "name": ["name", "vendor name", "supplier name", "vendor", "supplier", "payee", "company"],
    "bank_account": ["bank account", "bank_account", "account number", "iban", "account no", "bank account number",
                     "account", "bank"],
    "email_domains": ["email domains", "email_domains", "email domain", "domain", "domains", "email", "remittance email",
                      "contact email"],
    "created_on": ["created on", "created_on", "created", "date added", "vendor since", "added"],
    "phone": ["phone", "phone number", "telephone", "tel", "contact phone"],
    "number": ["po number", "po", "purchase order", "purchase order number", "order number", "number", "po no"],
    "amount": ["amount", "total", "payment amount", "amount paid", "paid", "value", "po amount", "invoice amount",
               "amount due", "net amount"],
    "billed": ["billed", "invoiced", "billed amount", "amount billed"],
    "invoice_number": ["invoice number", "invoice_number", "invoice", "invoice #", "invoice no", "inv", "bill number",
                       "bill no", "reference", "ref", "document number"],
    "paid_on": ["paid on", "paid_on", "payment date", "date paid", "paid date", "date", "value date"],
    "po_number": ["po number", "po_number", "po", "purchase order"],
}


def _key(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def map_headers(headers: list[str], wanted: list[str]) -> dict[str, int]:
    """Match each wanted field to a column: exact names first, then 'contains', longest names first."""
    keys = [_key(h) for h in headers]
    found: dict[str, int] = {}
    used: set[int] = set()
    for pass_ in ("exact", "contains"):
        for field in wanted:
            if field in found:
                continue
            for syn in sorted(FIELDS[field], key=len, reverse=True):
                k = _key(syn)
                hit = next((i for i, h in enumerate(keys) if i not in used and
                            (h == k if pass_ == "exact" else (len(k) >= 4 and k in h))), None)
                if hit is not None:
                    found[field] = hit
                    used.add(hit)
                    break
    return found


def read_table(text: str) -> tuple[list[str], list[tuple[int, list[str]]]]:
    text = text.lstrip("﻿")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    if not rows:
        raise ValueError("The file is empty.")
    if len(rows) > MAX_ROWS + 1:
        raise ValueError(f"The file has more than {MAX_ROWS} rows. Split it into smaller files.")
    header, body = rows[0], rows[1:]
    out = [(n, [c.strip() for c in r]) for n, r in enumerate(body, start=2) if any(c.strip() for c in r)]
    return [h.strip() for h in header], out


def _records(text: str, required: list[str], optional: list[str]):
    headers, rows = read_table(text)
    cols = map_headers(headers, required + optional)
    missing = [f for f in required if f not in cols]
    if missing:
        raise ValueError(f"Couldn't find a column for: {', '.join(m.replace('_', ' ') for m in missing)}. "
                         f"Columns found: {', '.join(headers) or 'none'}.")
    return [(n, {f: (r[i] if i < len(r) else "") for f, i in cols.items()}) for n, r in rows]


def parse_date(s: str, order: str = "mdy") -> date:
    s = (s or "").strip()
    if not s:
        raise ValueError("date is missing")
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d %b %Y", "%d %B %Y", "%b %d %Y", "%B %d %Y", "%b %d, %Y", "%B %d, %Y",
                "%d-%b-%Y", "%d-%b-%y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            pass
    m = re.fullmatch(r"(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{2,4})", s)
    if m:
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        y += 2000 if y < 100 else 0
        month, day = (a, b) if order == "mdy" else (b, a)
        return date(y, month, day)
    raise ValueError(f"can't read the date {s!r}")


def _vendor_lookup(store: Store):
    vendors = store.vendors()
    by_id = {v.vendor_id: v for v in vendors}
    by_name = {v.name.strip().lower(): v for v in vendors}

    def find(rec: dict) -> Vendor:
        key = rec.get("vendor_id", "").strip()
        v = by_id.get(key) or by_name.get(rec.get("name", "").strip().lower()) or by_name.get(key.lower())
        if not v:
            raise ValueError(f"unknown vendor {key or rec.get('name', '')!r}: import your vendor list first")
        return v
    return find


def _domains(raw: str) -> tuple[str, ...]:
    out = []
    for part in re.split(r"[;,\s]+", raw or ""):
        part = part.strip().lower().strip("<>")
        if "@" in part:
            part = part.rsplit("@", 1)[1]
        if part and re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", part) and part not in out:
            out.append(part)
    return tuple(out)


# --- vendors and purchase orders -----------------------------------------------------------

def import_vendors(store: Store, text: str) -> tuple[int, list[str]]:
    errors, vendors = [], []
    for n, r in _records(text, ["name", "bank_account"], ["vendor_id", "email_domains", "created_on", "phone"]):
        try:
            vid = (r.get("vendor_id") or "V-" + re.sub(r"[^A-Z0-9]", "", r["name"].upper())[:20])[:64]
            if not r["name"] or not r["bank_account"]:
                raise ValueError("name and bank account are required")
            created = parse_date(r["created_on"]) if r.get("created_on") else date(2000, 1, 1)
            existing = store.vendor(vid)
            if existing and norm_account(existing.bank_account) != norm_account(r["bank_account"]):
                raise ValueError(f"{vid}: the bank account differs from the one on file. Bank details "
                                 "only change through a bank-change request that a person approves after a phone call")
            vendors.append(Vendor(vid, r["name"][:200], r["bank_account"][:64], _domains(r.get("email_domains", "")),
                                  existing.created_on if existing else created,
                                  existing.bank_changed_on if existing else None, r.get("phone", "")[:40]))
        except ValueError as exc:
            errors.append(f"line {n}: {exc}")
    with store.tx():
        for v in vendors:
            store.upsert_vendor(v)
    return len(vendors), errors


def import_pos(store: Store, text: str) -> tuple[int, list[str]]:
    errors, pos = [], []
    find = _vendor_lookup(store)
    for n, r in _records(text, ["number", "amount"], ["vendor_id", "name", "billed"]):
        try:
            v = find(r)
            billed = parse_amount(r["billed"]) if r.get("billed") not in (None, "", "0", "0.00") else 0
            pos.append(PurchaseOrder(r["number"][:64], v.vendor_id, parse_amount(r["amount"]), billed))
        except ValueError as exc:
            errors.append(f"line {n}: {exc}")
    with store.tx():
        for po in pos:
            store.upsert_po(po)
    return len(pos), errors


# --- payment history --------------------------------------------------------------------

def import_history(store: Store, text: str, date_order: str = "mdy") -> tuple[int, int, list[str]]:
    """Past payments: so duplicate checks know what's already paid and the 'unusual amount' check has a baseline
    from day one. Re-importing the same file adds nothing twice. Returns (added, already there, errors)."""
    errors, rows = [], []
    find = _vendor_lookup(store)
    for n, r in _records(text, ["invoice_number", "amount", "paid_on"], ["vendor_id", "name", "bank_account"]):
        try:
            v = find(r)
            paid = parse_date(r["paid_on"], date_order)
            if paid > date.today():
                raise ValueError("payment date is in the future")
            cents = parse_amount(r["amount"])
            acct = r.get("bank_account") or v.bank_account
            ident = hashlib.sha256(f"{v.vendor_id}|{norm_invoice(r['invoice_number'])}|{paid}|{cents}".encode()).hexdigest()
            rows.append(Payment(f"hist-{ident[:24]}", "history", v.vendor_id, norm_invoice(r["invoice_number"]), cents,
                                norm_account(acct), paid, "pay", "imported"))
        except ValueError as exc:
            errors.append(f"line {n}: {exc}")
    added = 0
    with store.tx():
        for p in rows:
            added += store.record_payment(p, ignore_existing=True)
    return added, len(rows) - added, errors


# --- payment runs -------------------------------------------------------------------------

def read_payment_run(store: Store, text: str) -> tuple[list[dict], list[str]]:
    """The bills about to be paid, as rows the checkpoint can check. Unknown vendors are kept (they're a finding)."""
    rows, errors = [], []
    vendors = store.vendors()
    by_id = {v.vendor_id: v for v in vendors}
    by_name = {v.name.strip().lower(): v for v in vendors}
    for n, r in _records(text, ["amount"], ["vendor_id", "name", "invoice_number", "bank_account", "po_number"]):
        try:
            key = (r.get("vendor_id") or r.get("name") or "").strip()
            if not key:
                raise ValueError("no vendor")
            v = by_id.get(key) or by_name.get(key.lower()) or by_name.get((r.get("name") or "").strip().lower())
            rows.append({"line": n, "vendor_id": v.vendor_id if v else key[:64], "vendor_name": v.name if v else key[:200],
                         "invoice_number": (r.get("invoice_number") or "").strip()[:64] or f"line {n}",
                         "amount_cents": parse_amount(r["amount"]), "bank_account": (r.get("bank_account") or "")[:64],
                         "po_number": (r.get("po_number") or "")[:64]})
        except ValueError as exc:
            errors.append(f"line {n}: {exc}")
    return rows, errors
