"""People who use the web app: accounts, passwords, sessions and sign-in limits.

- **Passwords** are hashed with scrypt (N=2^14, r=8, p=1, 16-byte salt), never stored, and
  checked in constant time. An unknown email still runs a full hash against a dummy, so "no such
  user" and "wrong password" take the same time and get the same message (no user enumeration).
- **Sessions** are random 256-bit tokens. Only their SHA-256 is stored, so a stolen database
  can't be replayed as a login. They end after 30 minutes idle or 12 hours, at sign-out, or when
  the account is disabled or its password changes.
- **Sign-in limits**: 5 failures per address and email in 15 minutes locks that pair, and 30
  per address locks the address. Stored in SQLite, so every server thread and process shares them.
- **Roles**: `admin` (settings, imports, approves), `approver` (approves), `auditor` (reads, exports).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

ROLES = ("admin", "approver", "auditor")
IDLE = timedelta(minutes=30)
ABSOLUTE = timedelta(hours=12)
WINDOW = timedelta(minutes=15)
PAIR_LIMIT, IP_LIMIT = 5, 30
N, R, P = 2**14, 8, 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY, org_id TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin', 'approver', 'auditor')),
    password_hash TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
    password_changed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, created_at TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_failures (key TEXT NOT NULL, at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS login_failures_key ON login_failures (key, at);
"""

COMMON = {"password", "password123", "123456789012", "qwertyuiop12", "letmein12345", "welcome12345",
          "changeme1234", "administrator", "passwordpassword", "iloveyou1234"}


def _now() -> datetime:
    return datetime.now(UTC)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=N, r=R, p=P, dklen=32)
    return f"scrypt${N}${R}${P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got.hex(), digest)


DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problem(password: str, email: str) -> str | None:
    if len(password) < 12:
        return "Use at least 12 characters."
    if len(password) > 256:
        return "Use at most 256 characters."
    lowered = password.lower()
    if lowered in COMMON or len(set(lowered)) < 5:
        return "That password is too easy to guess."
    local = email.split("@")[0].lower()
    if len(local) >= 4 and local in lowered:
        return "Don't use your email address in your password."
    return None


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class User:
    email: str
    org_id: str
    role: str


class Accounts:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self.db.executescript(SCHEMA)
        if path != ":memory:":
            os.chmod(path, 0o600)

    def _q(self, sql, params=()):
        with self._lock:
            return self.db.execute(sql, params).fetchall()

    # --- accounts -------------------------------------------------------------------

    def create_user(self, email: str, org_id: str, role: str, password: str) -> User:
        email = email.strip().lower()
        if role not in ROLES:
            raise AuthError(422, f"role must be one of {ROLES}")
        if "@" not in email or len(email) > 254:
            raise AuthError(422, "Enter a valid email address.")
        problem = password_problem(password, email)
        if problem:
            raise AuthError(422, problem)
        now = _now().isoformat()
        try:
            self._q("INSERT INTO users VALUES (?, ?, ?, ?, 0, ?, ?)", (email, org_id, role, hash_password(password), now, now))
        except sqlite3.IntegrityError as exc:
            raise AuthError(409, "That email already has an account.") from exc
        return User(email, org_id, role)

    def set_password(self, email: str, password: str) -> None:
        problem = password_problem(password, email)
        if problem:
            raise AuthError(422, problem)
        self._q("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE email = ?",
                (hash_password(password), _now().isoformat(), email.lower()))
        self._q("DELETE FROM sessions WHERE email = ?", (email.lower(),))

    def set_disabled(self, email: str, disabled: bool) -> None:
        self._q("UPDATE users SET disabled = ? WHERE email = ?", (int(disabled), email.lower()))
        if disabled:
            self._q("DELETE FROM sessions WHERE email = ?", (email.lower(),))

    def users(self, org_id: str) -> list[dict]:
        return [{"email": r[0], "role": r[1], "disabled": bool(r[2])}
                for r in self._q("SELECT email, role, disabled FROM users WHERE org_id = ? ORDER BY email", (org_id,))]

    # --- sign-in --------------------------------------------------------------------

    def _failures(self, key: str, now: datetime) -> int:
        return self._q("SELECT COUNT(*) FROM login_failures WHERE key = ? AND at >= ?",
                       (key, (now - WINDOW).isoformat()))[0][0]

    def login(self, email: str, password: str, ip: str) -> tuple[str, User]:
        email = (email or "").strip().lower()[:254]
        now = _now()
        pair, addr = f"{ip}|{email}", f"{ip}|*"
        if self._failures(pair, now) >= PAIR_LIMIT or self._failures(addr, now) >= IP_LIMIT:
            raise AuthError(429, "Too many attempts. Wait 15 minutes, then try again.")
        rows = self._q("SELECT org_id, role, password_hash, disabled FROM users WHERE email = ?", (email,))
        stored = rows[0][2] if rows else DUMMY_HASH
        ok = verify_password(password or "", stored) and bool(rows) and not rows[0][3]
        if not ok:
            self._q("INSERT INTO login_failures VALUES (?, ?), (?, ?)", (pair, now.isoformat(), addr, now.isoformat()))
            self._q("DELETE FROM login_failures WHERE at < ?", ((now - WINDOW * 4).isoformat(),))
            raise AuthError(401, "Email or password is incorrect.")
        self._q("DELETE FROM login_failures WHERE key = ?", (pair,))
        token = secrets.token_urlsafe(32)
        self._q("INSERT INTO sessions VALUES (?, ?, ?, ?)", (self._h(token), email, now.isoformat(), now.isoformat()))
        return token, User(email, rows[0][0], rows[0][1])

    @staticmethod
    def _h(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def session(self, token: str) -> User | None:
        if not token or len(token) > 100:
            return None
        rows = self._q("SELECT s.email, s.created_at, s.last_seen, u.org_id, u.role, u.disabled, u.password_changed_at "
                       "FROM sessions s JOIN users u ON u.email = s.email WHERE s.token_hash = ?", (self._h(token),))
        if not rows:
            return None
        email, created, seen, org, role, disabled, changed = rows[0]
        now = _now()
        if (disabled or now - datetime.fromisoformat(seen) > IDLE or now - datetime.fromisoformat(created) > ABSOLUTE
                or changed > created):
            self._q("DELETE FROM sessions WHERE token_hash = ?", (self._h(token),))
            return None
        self._q("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now.isoformat(), self._h(token)))
        return User(email, org, role)

    def logout(self, token: str) -> None:
        self._q("DELETE FROM sessions WHERE token_hash = ?", (self._h(token or ""),))
