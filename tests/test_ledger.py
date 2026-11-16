"""The log: refuses edits, detects rewrites even with the database protections removed, and truncation."""

import hashlib
import json
import sqlite3

import pytest

from agent_checkpoint.ledger import Ledger


def fill(path, n=5):
    led = Ledger(path, b"k" * 32)
    for i in range(n):
        led.append("decision", f"R{i}", {"verdict": "block", "amount": 48_000_00, "i": i})
    return led


def test_refuses_update_and_delete(tmp_path):
    fill(str(tmp_path / "l.db"))
    raw = sqlite3.connect(str(tmp_path / "l.db"))
    for sql in ("UPDATE ledger SET body = '{}'", "DELETE FROM ledger"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            raw.execute(sql)


def test_detects_rewrite_with_triggers_dropped(tmp_path):
    path = str(tmp_path / "l.db")
    led = fill(path)
    assert led.verify()[0]
    raw = sqlite3.connect(path, isolation_level=None)
    raw.execute("DROP TRIGGER ledger_no_update")
    raw.execute("""UPDATE ledger SET body = '{"amount":4800000,"i":2,"verdict":"go"}' WHERE seq = 3""")
    ok, why = led.verify()
    assert not ok and "entry 3" in why


def test_detects_rehash_without_the_key(tmp_path):
    path = str(tmp_path / "l.db")
    led = fill(path, 1)
    raw = sqlite3.connect(path, isolation_level=None)
    raw.execute("DROP TRIGGER ledger_no_update")
    seq, at, kind, rid, prev = raw.execute("SELECT seq, at, kind, request_id, prev_hash FROM ledger").fetchone()
    body = '{"verdict":"go"}'
    digest = hashlib.sha256(json.dumps([prev, at, kind, rid, body], sort_keys=True,
                                       separators=(",", ":")).encode()).hexdigest()
    raw.execute("UPDATE ledger SET body = ?, hash = ? WHERE seq = 1", (body, digest))
    ok, why = led.verify()
    assert not ok and "not signed" in why


def test_published_head_catches_truncation(tmp_path):
    path = str(tmp_path / "l.db")
    led = fill(path, 4)
    published = led.head()
    raw = sqlite3.connect(path, isolation_level=None)
    raw.execute("DROP TRIGGER ledger_no_delete")
    raw.execute("DELETE FROM ledger WHERE seq = 4")
    assert led.verify()[0]                       # a chain alone can't see a missing tail...
    ok, why = led.verify(expected_head=published)
    assert not ok and "published" in why         # ...a published head can


def test_old_published_head_still_matches_after_growth(tmp_path):
    led = fill(str(tmp_path / "l.db"), 3)
    head = led.head()
    led.append("decision", "R9", {})
    assert led.verify(expected_head=head)[0]


def test_gateway_writes_every_step(gw):
    from conftest import pay
    d = gw.submit(pay(amount=12_000_00, po="PO-BIG"), agent_id="ap")
    gw.resolve(d.ticket_id, "cfo@acme.com", True, "ok")
    kinds = [e["kind"] for e in gw.org.ledger.entries()]
    assert kinds == ["decision", "human_decision", "executed"]
    assert gw.org.ledger.verify()[0]
