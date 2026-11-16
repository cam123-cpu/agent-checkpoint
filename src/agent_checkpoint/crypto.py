"""Encryption at rest for bank details and stored requests.

AES-256-GCM, with a fresh 12-byte nonce per value and *associated data* that names where the
value lives (`vendors.bank:V-NORTH`). Copying a ciphertext into another row, table or company
makes decryption fail, so a database attacker can't shuffle accounts between vendors.

Each company has its own data key (`orgs/<id>/data.key`). Account numbers that must be compared
without decrypting (for the audit log) get a keyed fingerprint (HMAC), which reveals only
whether two accounts are equal.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "v1:"


class Crypto:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("data key must be 32 bytes")
        self._enc = hmac.new(key, b"encrypt", hashlib.sha256).digest()
        self._idx = hmac.new(key, b"fingerprint", hashlib.sha256).digest()

    def encrypt(self, plaintext: str, where: str) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self._enc).encrypt(nonce, plaintext.encode(), where.encode())
        return PREFIX + base64.b64encode(nonce + ct).decode()

    def decrypt(self, token: str, where: str) -> str:
        if not token.startswith(PREFIX):
            raise ValueError("not an encrypted value")
        raw = base64.b64decode(token[len(PREFIX):])
        return AESGCM(self._enc).decrypt(raw[:12], raw[12:], where.encode()).decode()

    def fingerprint(self, value: str) -> str:
        return hmac.new(self._idx, value.encode(), hashlib.sha256).hexdigest()[:16]
