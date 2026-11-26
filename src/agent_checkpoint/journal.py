"""The audit log, written in step with the books.

The books (`books.db`) and the tamper-evident log (`ledger.db`) are separate databases, so one commit
can't cover both. Writing to the log in the middle of a books transaction would leave a decision in
the log that the books never got if anything failed before the commit, and the log is what replays
and idempotency read.

So inside a books transaction, log entries go into an `outbox` table in the books database and
commit (or roll back) with everything else. Right after the commit, still holding the books lock,
they are copied to the log in order and removed from the outbox. If the process dies in between,
the next start copies what is left. Each entry has a unique id that the log remembers, so an entry
is never added twice.
"""

from __future__ import annotations

import json
import uuid

from .ledger import Ledger
from .store import Store


class Journal:
    def __init__(self, ledger: Ledger, store: Store):
        self.ledger, self.store = ledger, store
        store._on_commit.append(self.flush)
        self.flush()  # anything a crash left in the outbox

    def append(self, kind: str, request_id: str, body: dict) -> str:
        if self.store.queues_log:
            self.store.outbox_add(uuid.uuid4().hex, kind, request_id, json.dumps(body, sort_keys=True))
            return ""
        return self.ledger.append(kind, request_id, body)

    def flush(self) -> int:
        n = 0
        for uid, kind, request_id, body in self.store.outbox():
            self.ledger.append(kind, request_id, json.loads(body), uid=uid)
            self.store.outbox_done(uid)
            n += 1
        return n

    def find(self, request_id: str, kind: str) -> dict | None:
        """Entries already in the log first; then ones this transaction queued and hasn't committed yet."""
        hit = self.ledger.find(request_id, kind)
        if hit is None and self.store.queues_log:
            for _uid, k, rid, body in self.store.outbox():
                if k == kind and rid == request_id:
                    return json.loads(body)
        return hit

    def pending(self) -> int:
        return len(self.store.outbox())

    def __getattr__(self, name):
        return getattr(self.ledger, name)
