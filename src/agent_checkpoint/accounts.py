"""People who use the web app: accounts, passwords, two-step sign-in, sessions and sign-in limits.

- **Passwords** are hashed with scrypt (N=2^14, r=8, p=1, 16-byte salt), never stored, and
  checked in constant time. An unknown email still runs a full hash against a dummy, so "no such
  user" and "wrong password" take the same time and get the same message (no user enumeration).
- **Two-step sign-in** (TOTP, `totp.py`): the secret is encrypted at rest; a used code can't be
  replayed; ten one-time recovery codes are stored only as keyed hashes. After a correct
  password, the person gets a 5-minute single-use "pending" token that is only good for entering
  a code (5 tries). A company can require two-step sign-in: people without it get a *limited*
  session that can do nothing except set it up.
- **Sessions** are random 256-bit tokens. Only their SHA-256 is stored. They end after 30 minutes
  idle or 12 hours, at sign-out, or when the account is disabled or its password changes.
- **Sign-in limits**: 5 failures (password or code) per address and email in 15 minutes locks
  that pair, and 30 per address locks the address. Stored in SQLite, shared by every thread and
  process.
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
from json import dumps as json_dumps
from json import loads as json_loads

from . import totp
from .crypto import Crypto

ROLES = ("admin", "approver", "auditor")
IDLE = timedelta(minutes=30)
ABSOLUTE = timedelta(hours=12)
WINDOW = timedelta(minutes=15)
PENDING = timedelta(minutes=5)
PAIR_LIMIT, IP_LIMIT, CODE_TRIES = 5, 30, 5
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
CREATE TABLE IF NOT EXISTS recovery_codes (email TEXT NOT NULL, code_hash TEXT NOT NULL, PRIMARY KEY (email, code_hash));
CREATE TABLE IF NOT EXISTS sso_pending (
    state_hash TEXT PRIMARY KEY, org_id TEXT NOT NULL, secrets_enc TEXT NOT NULL, binding_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_logins (
    token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, expires_at TEXT NOT NULL, tries INTEGER NOT NULL DEFAULT 0
);
"""
# Columns added after the first release: (table, column, definition). Added on start-up if missing.
ADDED = [
    ("users", "totp_enc", "TEXT"), ("users", "totp_pending_enc", "TEXT"), ("users", "totp_last_step", "INTEGER"),
    ("sessions", "limited", "INTEGER NOT NULL DEFAULT 0"), ("sessions", "via", "TEXT NOT NULL DEFAULT 'password'"),
]

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
    limited: bool = False   # signed in, but must set up two-step sign-in before anything else
    two_step: bool = False


@dataclass(frozen=True)
class LoginResult:
    kind: str               # "session" or "two_step"
    token: str              # session token, or the pending token for the code step
    user: User | None = None


class Accounts:
    def __init__(self, path: str, key: bytes):
        self._lock = threading.Lock()
        self.crypto = Crypto(key)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self.db.executescript(SCHEMA)
        for table, column, ddl in ADDED:
            if column not in {r[1] for r in self.db.execute(f"PRAGMA table_info({table})")}:
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        if path != ":memory:":
            os.chmod(path, 0o600)

    def _q(self, sql, params=()):
        with self._lock:
            return self.db.execute(sql, params).fetchall()

    @staticmethod
    def _h(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

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
            self._q("INSERT INTO users (email, org_id, role, password_hash, disabled, created_at, password_changed_at) "
                    "VALUES (?, ?, ?, ?, 0, ?, ?)", (email, org_id, role, hash_password(password), now, now))
        except sqlite3.IntegrityError as exc:
            raise AuthError(409, "That email already has an account.") from exc
        return User(email, org_id, role)

    def user(self, email: str) -> User | None:
        rows = self._q("SELECT email, org_id, role, totp_enc FROM users WHERE email = ? AND disabled = 0",
                       (email.strip().lower(),))
        return User(rows[0][0], rows[0][1], rows[0][2], two_step=bool(rows[0][3])) if rows else None

    def set_password(self, email: str, password: str) -> None:
        problem = password_problem(password, email)
        if problem:
            raise AuthError(422, problem)
        self._q("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE email = ?",
                (hash_password(password), _now().isoformat(), email.lower()))
        self._q("DELETE FROM sessions WHERE email = ?", (email.lower(),))

    def change_password(self, email: str, current: str, new: str) -> None:
        rows = self._q("SELECT password_hash FROM users WHERE email = ?", (email,))
        if not rows or not verify_password(current or "", rows[0][0]):
            raise AuthError(403, "Your current password is incorrect.")
        if current == new:
            raise AuthError(422, "Choose a password you haven't used here.")
        self.set_password(email, new)

    def set_disabled(self, email: str, disabled: bool) -> None:
        self._q("UPDATE users SET disabled = ? WHERE email = ?", (int(disabled), email.lower()))
        if disabled:
            self._q("DELETE FROM sessions WHERE email = ?", (email.lower(),))

    def users(self, org_id: str) -> list[dict]:
        return [{"email": r[0], "role": r[1], "disabled": bool(r[2]), "two_step": bool(r[3])}
                for r in self._q("SELECT email, role, disabled, totp_enc FROM users WHERE org_id = ? ORDER BY email",
                                 (org_id,))]

    # --- sign-in --------------------------------------------------------------------

    def _failures(self, key: str, now: datetime) -> int:
        return self._q("SELECT COUNT(*) FROM login_failures WHERE key = ? AND at >= ?",
                       (key, (now - WINDOW).isoformat()))[0][0]

    def _check_limits(self, ip: str, email: str, now: datetime) -> None:
        if self._failures(f"{ip}|{email}", now) >= PAIR_LIMIT or self._failures(f"{ip}|*", now) >= IP_LIMIT:
            raise AuthError(429, "Too many attempts. Wait 15 minutes, then try again.")

    def _fail(self, ip: str, email: str, now: datetime) -> None:
        self._q("INSERT INTO login_failures VALUES (?, ?), (?, ?)",
                (f"{ip}|{email}", now.isoformat(), f"{ip}|*", now.isoformat()))
        self._q("DELETE FROM login_failures WHERE at < ?", ((now - WINDOW * 4).isoformat(),))

    def _new_session(self, email: str, limited: bool = False, via: str = "password") -> str:
        token = secrets.token_urlsafe(32)
        now = _now().isoformat()
        self._q("INSERT INTO sessions (token_hash, email, created_at, last_seen, limited, via) VALUES (?, ?, ?, ?, ?, ?)",
                (self._h(token), email, now, now, int(limited), via))
        return token

    def login(self, email: str, password: str, ip: str, *, require_two_step=False) -> LoginResult:
        """`require_two_step`: a bool, or a function of the person's company id returning one."""
        email = (email or "").strip().lower()[:254]
        now = _now()
        self._check_limits(ip, email, now)
        rows = self._q("SELECT org_id, role, password_hash, disabled, totp_enc FROM users WHERE email = ?", (email,))
        stored = rows[0][2] if rows else DUMMY_HASH
        ok = verify_password(password or "", stored) and bool(rows) and not rows[0][3]
        if not ok:
            self._fail(ip, email, now)
            raise AuthError(401, "Email or password is incorrect.")
        org, role, _, _, totp_enc = rows[0]
        if totp_enc:
            pending = secrets.token_urlsafe(32)
            self._q("INSERT INTO pending_logins VALUES (?, ?, ?, 0)", (self._h(pending), email, (now + PENDING).isoformat()))
            return LoginResult("two_step", pending)
        self._q("DELETE FROM login_failures WHERE key = ?", (f"{ip}|{email}",))
        limited = bool(require_two_step(org) if callable(require_two_step) else require_two_step)
        return LoginResult("session", self._new_session(email, limited), User(email, org, role, limited=limited))

    def login_second_step(self, pending: str, code: str, ip: str) -> LoginResult:
        now = _now()
        rows = self._q("SELECT email, expires_at, tries FROM pending_logins WHERE token_hash = ?", (self._h(pending or ""),))
        if not rows or now > datetime.fromisoformat(rows[0][1]) or rows[0][2] >= CODE_TRIES:
            raise AuthError(401, "That sign-in has expired. Enter your email and password again.")
        email = rows[0][0]
        self._check_limits(ip, email, now)
        if not self._check_code(email, code):
            self._q("UPDATE pending_logins SET tries = tries + 1 WHERE token_hash = ?", (self._h(pending),))
            self._fail(ip, email, now)
            raise AuthError(401, "That code didn't work. Check your authenticator app and try again.")
        self._q("DELETE FROM pending_logins WHERE token_hash = ? OR expires_at < ?", (self._h(pending), now.isoformat()))
        self._q("DELETE FROM login_failures WHERE key = ?", (f"{ip}|{email}",))
        user = self.user(email)
        if user is None:
            raise AuthError(401, "That sign-in has expired. Enter your email and password again.")
        return LoginResult("session", self._new_session(email), user)

    def sso_session(self, email: str) -> tuple[str, User]:
        """The identity provider verified the person (and its own second factor)."""
        user = self.user(email)
        if user is None:
            raise AuthError(403, "No account here for that email. Ask an admin to add you.")
        return self._new_session(user.email, via="sso"), user

    # --- single sign-on flows in progress ------------------------------------------------

    def sso_begin(self, org_id: str, state: str, nonce: str, verifier: str, binding: str) -> None:
        now = _now()
        self._q("DELETE FROM sso_pending WHERE expires_at < ?", (now.isoformat(),))
        enc = self.crypto.encrypt(json_dumps({"nonce": nonce, "verifier": verifier}), f"sso:{self._h(state)}")
        self._q("INSERT INTO sso_pending VALUES (?, ?, ?, ?, ?)",
                (self._h(state), org_id, enc, self._h(binding), (now + timedelta(minutes=10)).isoformat()))

    def sso_take(self, state: str, binding: str) -> tuple[str, str, str]:
        """Single use: the row is deleted whether or not the rest of the sign-in succeeds."""
        with self._lock:
            rows = self.db.execute("SELECT org_id, secrets_enc, binding_hash, expires_at FROM sso_pending "
                                   "WHERE state_hash = ?", (self._h(state or ""),)).fetchall()
            self.db.execute("DELETE FROM sso_pending WHERE state_hash = ?", (self._h(state or ""),))
        if (not rows or _now() > datetime.fromisoformat(rows[0][3])
                or not hmac.compare_digest(rows[0][2], self._h(binding or ""))):
            raise AuthError(400, "expired")
        data = json_loads(self.crypto.decrypt(rows[0][1], f"sso:{self._h(state)}"))
        return rows[0][0], data["nonce"], data["verifier"]

    def _check_code(self, email: str, code: str) -> bool:
        rows = self._q("SELECT totp_enc, totp_last_step FROM users WHERE email = ?", (email,))
        if not rows or not rows[0][0]:
            return False
        secret = self.crypto.decrypt(rows[0][0], f"users.totp:{email}")
        digits = "".join(ch for ch in (code or "") if ch.isdigit())
        if len(digits) == totp.DIGITS and len((code or "").strip()) <= 7:
            step = totp.verify(secret, code, rows[0][1])
            if step is None:
                return False
            # Conditional update: two requests racing with the same code can't both win.
            with self._lock:
                cur = self.db.execute("UPDATE users SET totp_last_step = ? WHERE email = ? AND "
                                      "(totp_last_step IS NULL OR totp_last_step < ?)", (step, email, step))
            return cur.rowcount == 1
        h = self._recovery_hash(email, code)
        with self._lock:
            cur = self.db.execute("DELETE FROM recovery_codes WHERE email = ? AND code_hash = ?", (email, h))
        return cur.rowcount == 1

    def _recovery_hash(self, email: str, code: str) -> str:
        return self.crypto.fingerprint(f"recovery|{email}|{totp.normalize_recovery(code)}")

    # --- two-step set-up --------------------------------------------------------------

    def start_two_step(self, email: str) -> str:
        secret = totp.new_secret()
        self._q("UPDATE users SET totp_pending_enc = ? WHERE email = ?",
                (self.crypto.encrypt(secret, f"users.totp_pending:{email}"), email))
        return secret

    def confirm_two_step(self, email: str, code: str) -> list[str]:
        rows = self._q("SELECT totp_pending_enc FROM users WHERE email = ?", (email,))
        if not rows or not rows[0][0]:
            raise AuthError(409, "Start setting up two-step sign-in first.")
        secret = self.crypto.decrypt(rows[0][0], f"users.totp_pending:{email}")
        step = totp.verify(secret, code, None)
        if step is None:
            raise AuthError(422, "That code didn't match. Check the time on your phone and try the newest code.")
        codes = totp.new_recovery_codes()
        self._q("UPDATE users SET totp_enc = ?, totp_pending_enc = NULL, totp_last_step = ? WHERE email = ?",
                (self.crypto.encrypt(secret, f"users.totp:{email}"), step, email))
        self._q("DELETE FROM recovery_codes WHERE email = ?", (email,))
        for c in codes:
            self._q("INSERT INTO recovery_codes VALUES (?, ?)", (email, self._recovery_hash(email, c)))
        self._q("UPDATE sessions SET limited = 0 WHERE email = ?", (email,))
        return codes

    def disable_two_step(self, email: str, password: str, code: str) -> None:
        rows = self._q("SELECT password_hash FROM users WHERE email = ?", (email,))
        if not rows or not verify_password(password or "", rows[0][0]):
            raise AuthError(403, "Your password is incorrect.")
        if not self._check_code(email, code):
            raise AuthError(403, "That code didn't work.")
        self.reset_two_step(email)

    def reset_two_step(self, email: str) -> None:
        """Admin recovery for a lost phone and lost codes (CLI). Ends the person's sessions."""
        self._q("UPDATE users SET totp_enc = NULL, totp_pending_enc = NULL, totp_last_step = NULL WHERE email = ?",
                (email.lower(),))
        self._q("DELETE FROM recovery_codes WHERE email = ?", (email.lower(),))
        self._q("DELETE FROM sessions WHERE email = ?", (email.lower(),))

    def recovery_codes_left(self, email: str) -> int:
        return self._q("SELECT COUNT(*) FROM recovery_codes WHERE email = ?", (email,))[0][0]

    # --- sessions -------------------------------------------------------------------

    def session(self, token: str) -> User | None:
        if not token or len(token) > 100:
            return None
        rows = self._q("SELECT s.email, s.created_at, s.last_seen, u.org_id, u.role, u.disabled, u.password_changed_at, "
                       "s.limited, u.totp_enc FROM sessions s JOIN users u ON u.email = s.email WHERE s.token_hash = ?",
                       (self._h(token),))
        if not rows:
            return None
        email, created, seen, org, role, disabled, changed, limited, totp_enc = rows[0]
        now = _now()
        if (disabled or now - datetime.fromisoformat(seen) > IDLE or now - datetime.fromisoformat(created) > ABSOLUTE
                or changed > created):
            self._q("DELETE FROM sessions WHERE token_hash = ?", (self._h(token),))
            return None
        self._q("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now.isoformat(), self._h(token)))
        return User(email, org, role, limited=bool(limited), two_step=bool(totp_enc))

    def logout(self, token: str) -> None:
        self._q("DELETE FROM sessions WHERE token_hash = ?", (self._h(token or ""),))
