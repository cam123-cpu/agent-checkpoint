"""The audit log and the books can't disagree: entries commit with the books, then reach the log once."""
import pytest
from conftest import pay

from agent_checkpoint.ledger import Ledger


def test_a_failure_before_the_books_commit_leaves_nothing_in_the_log(gw, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(gw.org.store, "record_payment", boom)
    with pytest.raises(RuntimeError):
        gw.submit(pay(), agent_id="ap")
    assert gw.org.ledger.find("R1", "decision") is None  # no phantom decision for a retry to trust
    assert gw.org.store.get_request("R1") is None
    monkeypatch.undo()
    d = gw.submit(pay(), agent_id="ap")  # the retry is decided for real
    assert d.status == "executed" and len(gw.org.store.payments()) == 1


def test_entries_left_by_a_crash_after_commit_reach_the_log_on_restart(gw, monkeypatch):
    real = gw.org.ledger.ledger.append

    def down(*a, **k):
        raise OSError("ledger disk unavailable")
    monkeypatch.setattr(gw.org.ledger.ledger, "append", down)
    d = gw.submit(pay(), agent_id="ap")  # the books commit; the log can't be written
    assert d.status == "executed" and gw.org.ledger.pending() >= 2
    monkeypatch.setattr(gw.org.ledger.ledger, "append", real)
    from agent_checkpoint.journal import Journal
    Journal(gw.org.ledger.ledger, gw.org.store)  # what the next start does
    assert gw.org.ledger.pending() == 0
    assert gw.org.ledger.find("R1", "decision") and gw.org.ledger.find("R1", "executed")
    assert gw.org.ledger.verify()[0]


def test_a_flush_interrupted_after_the_log_write_does_not_double_count(tmp_path):
    led = Ledger(str(tmp_path / "l.db"), b"k" * 32)
    led.append("decision", "R1", {"x": 1}, uid="u1")
    led.append("decision", "R1", {"x": 1}, uid="u1")  # the outbox row wasn't deleted before the crash
    assert len(led.entries("decision")) == 1 and led.verify()[0]
