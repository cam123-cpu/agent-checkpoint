"""Signed execution receipts.

When an action is allowed (straight away, or after approval), the checkpoint signs a receipt
with its Ed25519 private key: exactly what may happen (payee account from the vendor master,
amount, invoice), when it expires, and who approved it. The sandbox rail executes only with a
valid, unexpired, unused receipt whose contents match the transfer.

Verification needs only the *public* key, so a bank or ERP partner could check receipts
themselves. That only binds money that partner releases, and only once it is configured to
refuse transfers without one. Until then a receipt is evidence, not a gate.
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


class ReceiptError(Exception):
    pass


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey, org_id: str):
        self._key = private_key
        self.org_id = org_id

    @classmethod
    def generate(cls, org_id: str) -> Signer:
        return cls(Ed25519PrivateKey.generate(), org_id)

    @classmethod
    def load(cls, path: str, org_id: str) -> Signer:
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("signing key must be Ed25519")
        return cls(key, org_id)

    def save(self, path: str) -> None:
        pem = self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)

    def sign_bytes(self, data: bytes) -> bytes:
        """For signed documents (release.py) that carry their own signing context."""
        return self._key.sign(data)

    def public_pem(self) -> str:
        return self._key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def issue(self, *, request_id: str, action: str, vendor_id: str, amount_cents: int, payee_account: str,
              invoice_key: str, approved_by: list[str], now: datetime, ttl_minutes: int = 10) -> dict:
        body = {
            "receipt_id": "RC-" + uuid.uuid4().hex, "org_id": self.org_id, "request_id": request_id,
            "action": action, "vendor_id": vendor_id, "amount_cents": amount_cents,
            "payee_account": payee_account, "invoice_key": invoice_key, "approved_by": approved_by,
            "issued_at": now.isoformat(), "expires_at": (now + timedelta(minutes=ttl_minutes)).isoformat(),
        }
        sig = base64.b64encode(self._key.sign(_canonical(body))).decode()
        return {"body": body, "sig": sig}


class Verifier:
    def __init__(self, public_pem: str):
        key = serialization.load_pem_public_key(public_pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("public key must be Ed25519")
        self._key = key

    def verify(self, receipt: dict, now: datetime) -> dict:
        try:
            body, sig = receipt["body"], base64.b64decode(receipt["sig"], validate=True)
            self._key.verify(sig, _canonical(body))
        except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
            raise ReceiptError("receipt signature is invalid") from exc
        if now > datetime.fromisoformat(body["expires_at"]):
            raise ReceiptError("receipt has expired")
        return body
