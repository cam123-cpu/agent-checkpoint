"""The permanent record: every action, allowed or not, and every human decision about one.

Two protections, and an honest statement of what each does:

1. **The database refuses edits.** SQLite triggers abort any UPDATE or DELETE on the table.
   This stops mistakes and casual tampering through the application.
2. **Every entry is chained to the one before it** (SHA-256 of the previous hash + this entry)
   and signed with a server key (HMAC). Anyone with write access to the *file* could still
   drop the triggers and rewrite rows, but then `verify()` fails: changing one entry breaks
   every hash after it, and forging new hashes needs the key.

What a chain can't catch on its own is someone deleting the *newest* entries. That is what
`head()` is for: publish the latest hash somewhere the operator doesn't control (the
customer's own email, their auditor, a timestamping service) and truncation becomes visible.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from datetime import UTC, datetime

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
    seq        INTEGER PRIMARY KEY,
    at         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    request_id TEXT NOT NULL,
    body       TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL UNIQUE,
    sig        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ledger_request ON ledger (request_id);
CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger
    BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger
    BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
-- Which outbox entries are already in the log, so a flush interrupted by a crash never adds one twice.
CREATE TABLE IF NOT EXISTS ledger_uids (uid TEXT PRIMARY KEY, hash TEXT NOT NULL);
"""


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class Ledger:
    def __init__(self, path: str, key: bytes):
        if len(key) < 32:
            raise ValueError("ledger key must be at least 32 bytes")
        self._key = key
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        self._db.executescript(SCHEMA)

    def _hash(self, prev: str, at: str, kind: str, request_id: str, body: str) -> tuple[str, str]:
        material = _canonical([prev, at, kind, request_id, body]).encode()
        digest = hashlib.sha256(material).hexdigest()
        sig = hmac.new(self._key, digest.encode(), hashlib.sha256).hexdigest()
        return digest, sig

    def append(self, kind: str, request_id: str, body: dict, *, uid: str = "") -> str:
        """Add an entry. With `uid` (from the books' outbox), appending the same entry twice adds it once."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                if uid:
                    seen = self._db.execute("SELECT hash FROM ledger_uids WHERE uid = ?", (uid,)).fetchone()
                    if seen:
                        self._db.execute("COMMIT")
                        return seen[0]
                row = self._db.execute("SELECT hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
                prev = row[0] if row else GENESIS
                at = datetime.now(UTC).isoformat(timespec="microseconds")
                text = _canonical(body)
                digest, sig = self._hash(prev, at, kind, request_id, text)
                self._db.execute(
                    "INSERT INTO ledger (at, kind, request_id, body, prev_hash, hash, sig) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)", (at, kind, request_id, text, prev, digest, sig))
                if uid:
                    self._db.execute("INSERT INTO ledger_uids (uid, hash) VALUES (?, ?)", (uid, digest))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return digest

    def entries(self, kind: str | None = None) -> list[dict]:
        sql = "SELECT seq, at, kind, request_id, body, hash FROM ledger"
        rows = self._db.execute(sql + (" WHERE kind = ?" if kind else "") + " ORDER BY seq",
                                (kind,) if kind else ()).fetchall()
        return [{"seq": r[0], "at": r[1], "kind": r[2], "request_id": r[3], "body": json.loads(r[4]),
                 "hash": r[5]} for r in rows]

    def find(self, request_id: str, kind: str) -> dict | None:
        r = self._db.execute("SELECT body FROM ledger WHERE request_id = ? AND kind = ? ORDER BY seq LIMIT 1",
                             (request_id, kind)).fetchone()
        return json.loads(r[0]) if r else None

    def head(self) -> dict:
        r = self._db.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return {"seq": r[0], "hash": r[1]} if r else {"seq": 0, "hash": GENESIS}

    def verify(self, expected_head: dict | None = None) -> tuple[bool, str]:
        """Recompute the whole chain. Returns (ok, explanation)."""
        prev, last_seq = GENESIS, 0
        for seq, at, kind, rid, body, prev_hash, digest, sig in self._db.execute(
                "SELECT seq, at, kind, request_id, body, prev_hash, hash, sig FROM ledger ORDER BY seq"):
            if seq != last_seq + 1:
                return False, f"entry {last_seq + 1} is missing"
            if prev_hash != prev:
                return False, f"entry {seq} does not follow entry {seq - 1}"
            want, want_sig = self._hash(prev, at, kind, rid, body)
            if digest != want:
                return False, f"entry {seq} was altered"
            if not hmac.compare_digest(sig, want_sig):
                return False, f"entry {seq} is not signed by this checkpoint"
            prev, last_seq = digest, seq
        if expected_head and (expected_head["seq"] > last_seq or
                              (expected_head["seq"] == last_seq and expected_head["hash"] != prev)):
            return False, f"ledger ends at entry {last_seq}, but entry {expected_head['seq']} was published"
        if expected_head and expected_head["seq"] < last_seq:
            # The published head must still be in the chain at its position.
            r = self._db.execute("SELECT hash FROM ledger WHERE seq = ?", (expected_head["seq"],)).fetchone()
            if not r or r[0] != expected_head["hash"]:
                return False, f"entry {expected_head['seq']} no longer matches the published hash"
        return True, f"{last_seq} entries, chain intact"
