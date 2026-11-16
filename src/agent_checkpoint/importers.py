"""Load a company's vendor master and open POs from CSV exports, for pilots before live connectors.

vendors.csv:  vendor_id, name, bank_account, email_domains (separated by ;), created_on (yyyy-mm-dd), phone
pos.csv:      number, vendor_id, amount (e.g. 4800.00), billed (optional)

Bad rows are reported with their line number and skipped; good rows are loaded in one
transaction. Re-importing updates vendors and POs but never touches payments or bank-change
history recorded by the checkpoint.
"""

from __future__ import annotations

import csv
import io
from datetime import date

from .models import parse_amount
from .store import PurchaseOrder, Store, Vendor


def _rows(text: str):
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    reader.fieldnames = [(f or "").strip().lower() for f in reader.fieldnames or []]
    for n, row in enumerate(reader, start=2):
        yield n, {k: (v or "").strip() for k, v in row.items() if k}


def import_vendors(store: Store, text: str) -> tuple[int, list[str]]:
    ok, errors, vendors = 0, [], []
    for n, r in _rows(text):
        try:
            if not r.get("vendor_id") or not r.get("name") or not r.get("bank_account"):
                raise ValueError("vendor_id, name and bank_account are required")
            created = date.fromisoformat(r["created_on"]) if r.get("created_on") else date(2000, 1, 1)
            domains = tuple(d.strip().lower() for d in r.get("email_domains", "").split(";") if d.strip())
            existing = store.vendor(r["vendor_id"])
            vendors.append(Vendor(r["vendor_id"], r["name"], r["bank_account"], domains, created,
                                  existing.bank_changed_on if existing else None, r.get("phone", "")))
        except ValueError as exc:
            errors.append(f"line {n}: {exc}")
    with store.tx():
        for v in vendors:
            store.upsert_vendor(v)
            ok += 1
    return ok, errors


def import_pos(store: Store, text: str) -> tuple[int, list[str]]:
    errors, pos = [], []
    for n, r in _rows(text):
        try:
            if not r.get("number") or not r.get("vendor_id"):
                raise ValueError("number and vendor_id are required")
            if store.vendor(r["vendor_id"]) is None:
                raise ValueError(f"unknown vendor {r['vendor_id']}")
            billed = parse_amount(r["billed"]) if r.get("billed") not in (None, "", "0", "0.00") else 0
            pos.append(PurchaseOrder(r["number"], r["vendor_id"], parse_amount(r.get("amount", "")), billed))
        except ValueError as exc:
            errors.append(f"line {n}: {exc}")
    with store.tx():
        for po in pos:
            store.upsert_po(po)
    return len(pos), errors
