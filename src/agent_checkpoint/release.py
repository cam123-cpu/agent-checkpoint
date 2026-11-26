"""Signed records that something which moves money can check without trusting this software.

Two documents, both signed with the company's Ed25519 key (the same key as execution receipts, with a
different signing context so one can never be passed off as the other):

* **Release** (`release`): issued after a payment file was checked. It names the file (SHA-256), the
  lines that may be released, the lines that must be held, and where each released line may go. A bank,
  Bill.com, Ramp or an ERP can refuse a file with no valid release, or release only the listed lines.

* **Allowed accounts** (`allowed_accounts`): the company's list of vendor accounts currently on file.
  `confirmed_by_call` is true only when that account was set by a bank change a second person approved
  after the number on file was recorded. An import or a newly added vendor is on the list with that flag
  false. A payment system can refuse any payment to an account that isn't on the latest list.

Neither document is enforcement by itself. It becomes a control only when the system that releases the
money is configured to check it. Until a partner does that, this is evidence, not a gate, and nothing in
this package should claim otherwise.

Accounts appear as salted SHA-256 tags, not numbers, so the documents can sit in email threads and
ticket systems without spreading bank details. Account numbers are short, so a tag is not secret from
someone determined to guess: share these documents only with the partner that checks them.

The functions under "verifying" need only the public key and the standard library plus `cryptography`.
A partner can run `agent-checkpoint verify-release` without a data folder.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .store import norm_account

CONTEXT = {
    "release": b"agent-checkpoint release v1\n",
    "allowed_accounts": b"agent-checkpoint allowed-accounts v1\n",
}


class ReleaseError(Exception):
    pass


def canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def account_tag(salt: str, account: str) -> str:
    return hashlib.sha256(f"{salt}:{norm_account(account)}".encode()).hexdigest()


def sign(signer, kind: str, body: dict) -> dict:
    sig = signer.sign_bytes(CONTEXT[kind] + canonical(body))
    return {"kind": kind, "body": body, "sig": base64.b64encode(sig).decode(),
            "sha256": hashlib.sha256(canonical(body)).hexdigest()}


# --- verifying (partner side) -----------------------------------------------------------

def verify(public_pem: str, doc: dict, kind: str, now: datetime) -> dict:
    """The body, if the signature is good, the kind is right and it hasn't expired. Otherwise ReleaseError."""
    try:
        key = serialization.load_pem_public_key(public_pem.encode())
    except ValueError as exc:
        raise ReleaseError("that public key can't be read") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ReleaseError("public key must be Ed25519")
    if not isinstance(doc, dict) or doc.get("kind") != kind:
        raise ReleaseError(f"this is not a {kind.replace('_', ' ')} document")
    try:
        body = doc["body"]
        key.verify(base64.b64decode(doc["sig"], validate=True), CONTEXT[kind] + canonical(body))
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise ReleaseError("signature is not valid: the document was changed or signed by someone else") from exc
    try:
        expires = datetime.fromisoformat(body["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseError("document has no expiry") from exc
    if now > expires:
        raise ReleaseError(f"document expired at {body['expires_at']}")
    return body


def instructions_from_csv(text: str) -> list[dict]:
    """A partner's view of a payment file: amount and account per line (headers: amount, account; optional
    vendor_id, invoice_number). This is what the bank is about to send, in its own words."""
    out = []
    reader = csv.DictReader(io.StringIO(text))
    names = {h: (h or "").strip().lower() for h in reader.fieldnames or []}
    for n, row in enumerate(reader, start=2):
        r = {names[k]: (v or "").strip() for k, v in row.items() if k in names}
        amount = r.get("amount_cents") or ""
        if not amount and r.get("amount"):
            from .models import parse_amount
            amount = str(parse_amount(r["amount"]))
        out.append({"line": n, "amount_cents": int(amount or 0),
                    "account": r.get("account") or r.get("bank_account") or r.get("iban") or "",
                    "vendor_id": r.get("vendor_id", ""), "invoice_number": r.get("invoice_number", "")})
    return out


def check_release(body: dict, file_bytes: bytes | None = None, instructions: list[dict] | None = None,
                  used_release_ids: set[str] | frozenset[str] = frozenset()) -> dict:
    """What a partner may release under a verified release body.

    With the file: its SHA-256 must be the one that was checked, and the result lists the lines to release
    and to hold. With instructions (what the bank will actually send): each must match one released line by
    amount and account, once. Anything else is held. A release id seen before is refused (single use).
    """
    if body.get("release_id") in used_release_ids:
        raise ReleaseError("this release was already used")
    if file_bytes is not None and hashlib.sha256(file_bytes).hexdigest() != body["file_sha256"]:
        raise ReleaseError("this file is not the file that was checked (its SHA-256 differs)")
    result = {"release_id": body["release_id"], "release_lines": [r["line"] for r in body["release"]],
              "hold_lines": list(body["hold"]), "unmatched": []}
    if instructions is not None:
        pool = list(body["release"])
        ok = []
        for ins in instructions:
            if not norm_account(ins.get("account", "")):
                result["unmatched"].append(ins["line"])  # no account: nothing can be checked
                continue
            tag = account_tag(body["salt"], ins.get("account", ""))
            hit = next((r for r in pool if r["amount_cents"] == ins["amount_cents"] and r["account_tag"] == tag
                        and (not ins.get("vendor_id") or ins["vendor_id"] == r["vendor_id"])), None)
            if hit:
                pool.remove(hit)
                ok.append(ins["line"])
            else:
                result["unmatched"].append(ins["line"])
        result["release_lines"] = ok
    result["ok"] = not result["unmatched"]
    return result


def check_allowed(body: dict, instructions: list[dict], min_version: int = 0) -> dict:
    """Each payment's account must be on the company's allowed list (and, if given, for that vendor)."""
    if int(body.get("version", 0)) < min_version:
        raise ReleaseError(f"this list is version {body.get('version')}; you have already seen version {min_version}")
    by_tag: dict[str, set[str]] = {}
    for a in body["accounts"]:
        by_tag.setdefault(a["account_tag"], set()).add(a["vendor_id"])
    allowed, refused = [], []
    for ins in instructions:
        vendors = by_tag.get(account_tag(body["salt"], ins.get("account", ""))) if norm_account(
            ins.get("account", "")) else None
        good = bool(vendors) and (not ins.get("vendor_id") or ins["vendor_id"] in vendors)
        (allowed if good else refused).append(ins["line"])
    return {"list_id": body["list_id"], "version": body["version"], "allowed_lines": allowed,
            "refused_lines": refused, "ok": not refused}
