"""Two-step sign-in codes: TOTP (RFC 6238), the algorithm in every authenticator app.

Both sides share a random 160-bit secret. Every 30 seconds each computes HMAC-SHA1(secret,
time step), takes 4 bytes chosen by the last byte (dynamic truncation) and keeps 6 digits.
The server accepts the step before and after (phone clocks drift) and remembers the last step
used, so a code can't be replayed even within its 30 seconds.

Recovery codes: ten random one-time codes shown once. Only a keyed hash is stored.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret_b32: str) -> bytes:
    s = secret_b32.upper().replace(" ", "")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret_b32: str, step: int, digits: int = DIGITS) -> str:
    digest = hmac.new(_key(secret_b32), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def verify(secret_b32: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Return the matched time step (to store as last used), or None."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != DIGITS:
        return None
    current = int((time.time() if now is None else now) // STEP)
    for step in (current - 1, current, current + 1):
        if last_step is not None and step <= last_step:
            continue  # already used: replay
        if hmac.compare_digest(code_at(secret_b32, step), code):
            return step
    return None


def otpauth_uri(secret_b32: str, account: str, issuer: str = "Checkpoint") -> str:
    label = quote(f"{issuer}:{account}", safe="")
    # SHA1, 6 digits and 30 seconds are the defaults every app assumes; leaving them out keeps the QR code small.
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}"


def new_recovery_codes(n: int = 10) -> list[str]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i
    return ["-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(2)) for _ in range(n)]


def normalize_recovery(code: str) -> str:
    return "".join(ch for ch in (code or "").lower() if ch.isalnum())
