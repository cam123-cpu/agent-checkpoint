"""The shared fraud network: what one company learns protects every company.

When an approver rejects a ticket and marks it as fraud, the bank account and the sender's
email domain go into a shared list. The next time any company's agent on this same installation
is asked to pay or switch to that account, or acts on a request from that domain, the checkpoint
blocks it. The list is one database file (`network/intel.db`). It is not a hosted exchange
between customers who run their own servers.

Privacy: accounts are stored only as a keyed hash (HMAC-SHA256 with the network key, a
"blind index"), so the shared list can answer "has this account been reported?" without
holding anyone's bank details. Reports record which company reported, but other companies
only ever see a count.

This is the part a single-company tool can't copy, and the main reason the product gets
better as it grows.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
from datetime import UTC, datetime

from .store import norm_account

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    kind TEXT NOT NULL CHECK (kind IN ('account', 'domain')), value TEXT NOT NULL,
    org_id TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY (kind, value, org_id)
);
"""


class Intel:
    def __init__(self, path: str, key: bytes):
        if len(key) < 32:
            raise ValueError("intel key must be at least 32 bytes")
        self._key = key
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self.db.executescript(SCHEMA)

    def _blind(self, account: str) -> str:
        return hmac.new(self._key, norm_account(account).encode(), hashlib.sha256).hexdigest()

    def report(self, org_id: str, *, account: str = "", domain: str = "") -> None:
        at = datetime.now(UTC).isoformat()
        with self._lock:
            if account and norm_account(account):
                self.db.execute("INSERT OR IGNORE INTO reports VALUES ('account', ?, ?, ?)",
                                (self._blind(account), org_id, at))
            if domain:
                self.db.execute("INSERT OR IGNORE INTO reports VALUES ('domain', ?, ?, ?)",
                                (domain.lower().strip(), org_id, at))

    def account_reports(self, account: str) -> int:
        if not norm_account(account):
            return 0
        return self.db.execute("SELECT COUNT(*) FROM reports WHERE kind = 'account' AND value = ?",
                               (self._blind(account),)).fetchone()[0]

    def domain_reports(self, domain: str) -> int:
        if not domain:
            return 0
        return self.db.execute("SELECT COUNT(*) FROM reports WHERE kind = 'domain' AND value = ?",
                               (domain.lower().strip(),)).fetchone()[0]
