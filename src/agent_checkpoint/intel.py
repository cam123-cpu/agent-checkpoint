"""The shared fraud network: what one company learns can warn every company.

When an approver rejects a ticket and marks it as fraud, the bank account and the sender's email
domain go into a shared list. The list is one database file (`network/intel.db`) on this
installation. It is not a hosted exchange between customers who run their own servers.

How much one report is allowed to do is deliberately limited, because a list that blocks a real
company on one say-so is a liability, not a moat:

* Your own company's report blocks, for your company. You saw the fraud.
* One report from another company only pauses: a person looks before money moves.
* Reports from two or more other companies block.
* Free-mail and shared domains (gmail.com, outlook.com...) are never listed: one fraudster there
  would put millions of real senders on the list.
* A company can withdraw its own report, and that is in its audit log.

Privacy: accounts and domains are stored only as keyed hashes (HMAC-SHA256 with the network key,
a "blind index"), so the list can answer "has this been reported?" without holding anyone's bank
details or a readable list of names. Other companies only ever see a count. The network key
should live apart from the database (see `AGENT_CHECKPOINT_KEYS`).
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
from datetime import UTC, datetime

from .store import norm_account

# Free-mail and shared hosting: never listed, however many reports. A report names who the money was
# going to or who wrote; "gmail.com" names a billion people.
SHARED_DOMAINS = frozenset("""
gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com ymail.com aol.com icloud.com me.com
mac.com proton.me protonmail.com pm.me gmx.com gmx.net gmx.de web.de mail.com zoho.com yandex.com yandex.ru
mail.ru qq.com 163.com 126.com naver.com hey.com fastmail.com tutanota.com outlook.de hotmail.co.uk yahoo.co.uk
btinternet.com comcast.net verizon.net att.net sbcglobal.net onmicrosoft.com
""".split())

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    kind TEXT NOT NULL CHECK (kind IN ('account', 'domain')), value TEXT NOT NULL,
    org_id TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY (kind, value, org_id)
);
"""


def shared_domain(domain: str) -> bool:
    d = (domain or "").lower().strip().rstrip(".")
    return d in SHARED_DOMAINS or any(d.endswith("." + s) for s in SHARED_DOMAINS)


class Intel:
    def __init__(self, path: str, key: bytes):
        if len(key) < 32:
            raise ValueError("intel key must be at least 32 bytes")
        self._key = key
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(reports)")}
        if "withdrawn_at" not in cols:
            self.db.execute("ALTER TABLE reports ADD COLUMN withdrawn_at TEXT")
        self._migrate_plain_domains()

    def _blind(self, kind: str, value: str) -> str:
        v = norm_account(value) if kind == "account" else value.lower().strip().rstrip(".")
        # The kind is part of the hashed text, so an account and a domain can never collide.
        return hmac.new(self._key, f"{kind}:{v}".encode(), hashlib.sha256).hexdigest()

    def _migrate_plain_domains(self) -> None:
        """Earlier versions kept domains readable and accounts hashed without a kind prefix."""
        with self._lock:
            done = self.db.execute("SELECT name FROM sqlite_master WHERE name = 'intel_meta'").fetchone()
            if done:
                return
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute("CREATE TABLE intel_meta (version INTEGER NOT NULL)")
                rows = self.db.execute("SELECT kind, value, org_id FROM reports").fetchall()
                for kind, value, org_id in rows:
                    if kind == "domain":
                        if shared_domain(value):
                            self.db.execute("DELETE FROM reports WHERE kind = ? AND value = ? AND org_id = ?",
                                            (kind, value, org_id))
                            continue
                        new = self._blind("domain", value)
                    else:
                        # Old account hashes were HMAC(norm_account) with no prefix; they can't be re-derived
                        # without the account, so they keep their value and are matched both ways below.
                        continue
                    self.db.execute("UPDATE OR IGNORE reports SET value = ? WHERE kind = ? AND value = ? AND org_id = ?",
                                    (new, kind, value, org_id))
                self.db.execute("INSERT INTO intel_meta VALUES (2)")
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def _values(self, kind: str, value: str) -> tuple[str, ...]:
        if kind == "account":
            legacy = hmac.new(self._key, norm_account(value).encode(), hashlib.sha256).hexdigest()
            return (self._blind(kind, value), legacy)
        return (self._blind(kind, value),)

    def report(self, org_id: str, *, account: str = "", domain: str = "") -> bool:
        at = datetime.now(UTC).isoformat()
        listed = False
        with self._lock:
            if account and norm_account(account):
                self.db.execute("INSERT INTO reports (kind, value, org_id, at) VALUES ('account', ?, ?, ?) "
                                "ON CONFLICT (kind, value, org_id) DO UPDATE SET withdrawn_at = NULL, at = excluded.at",
                                (self._blind("account", account), org_id, at))
                listed = True
            if domain and not shared_domain(domain):
                self.db.execute("INSERT INTO reports (kind, value, org_id, at) VALUES ('domain', ?, ?, ?) "
                                "ON CONFLICT (kind, value, org_id) DO UPDATE SET withdrawn_at = NULL, at = excluded.at",
                                (self._blind("domain", domain), org_id, at))
                listed = True
        return listed

    def withdraw(self, org_id: str, *, account: str = "", domain: str = "") -> int:
        """A company takes back its own report. Nobody can withdraw another company's."""
        at, n = datetime.now(UTC).isoformat(), 0
        with self._lock:
            for kind, value in (("account", account), ("domain", domain)):
                if not value:
                    continue
                for v in self._values(kind, value):
                    n += self.db.execute("UPDATE reports SET withdrawn_at = ? WHERE kind = ? AND value = ? AND org_id = ? "
                                         "AND withdrawn_at IS NULL", (at, kind, v, org_id)).rowcount
        return n

    def standing(self, kind: str, value: str, org_id: str = "") -> tuple[bool, int]:
        """(reported by this company, number of other companies that reported it), withdrawn reports excluded."""
        if not value or (kind == "account" and not norm_account(value)) or (kind == "domain" and shared_domain(value)):
            return False, 0
        vals = self._values(kind, value)
        current, legacy = vals[0], vals[-1]  # the same value twice for domains
        orgs = {r[0] for r in self.db.execute(
            "SELECT org_id FROM reports WHERE kind = ? AND value IN (?, ?) AND withdrawn_at IS NULL",
            (kind, current, legacy))}
        return org_id in orgs, len(orgs - {org_id})

    def account_reports(self, account: str) -> int:
        own, others = self.standing("account", account)
        return others + own

    def domain_reports(self, domain: str) -> int:
        own, others = self.standing("domain", domain)
        return others + own
