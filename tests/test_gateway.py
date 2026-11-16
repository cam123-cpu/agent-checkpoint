"""Modes, approvals, receipts, retries, concurrency."""

import threading
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
from conftest import ACCT, bank_change, pay

from agent_checkpoint.checks import learned_weights
from agent_checkpoint.gateway import CheckpointError
from agent_checkpoint.models import Verdict
from agent_checkpoint.receipts import ReceiptError, Signer, Verifier


def test_shadow_does_not_keep_a_bank_change_the_checks_would_block(gw):
    from conftest import bank_change
    gw.org.policy = replace(gw.org.policy, mode="shadow")
    before = gw.org.store.vendor("V1").bank_account
    d = gw.submit(bank_change(sender="ap@acmesupp1ies.com"), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and d.returned is Verdict.GO
    assert gw.org.store.vendor("V1").bank_account == before
    assert gw.org.ledger.find("C1", "executed")["bank_change_applied"] is False


def test_shadow_mode_never_blocks_but_records(gw):
    gw.org.policy = replace(gw.org.policy, mode="shadow")
    billed = gw.org.store.po("PO-1").billed_cents
    d = gw.submit(pay(amount=48_000_00), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and d.returned is Verdict.GO and d.status == "observed"
    assert gw.org.store.payments() == []  # a block is not written into the books the next payment trusts
    assert gw.org.store.po("PO-1").billed_cents == billed
    assert gw.org.ledger.find("R1", "executed")["books_changed"] is False
    assert gw.org.store.q("SELECT COUNT(*) FROM transfers")[0][0] == 0  # shadow never moves money
    assert gw.org.ledger.find("R1", "decision")["verdict"] == "block"


def test_pause_notifies_and_approval_executes_with_receipt(gw):
    d = gw.submit(pay(amount=12_000_00, po="PO-BIG"), agent_id="ap")
    assert d.verdict is Verdict.PAUSE and gw.org.store.payments() == []
    [(tid, text)] = gw.org.notifier.sent
    assert tid == d.ticket_id and "$12,000.00" in text and text.endswith("Approve?")
    out = gw.resolve(d.ticket_id, "cfo@acme.com", True)
    assert out["status"] == "approved" and out["execution"] == "executed" and out["transfer_id"]
    assert gw.status("R1")["status"] == "executed"


def test_dual_approval_needs_two_different_people(gw):
    d = gw.submit(pay(amount=60_000_00, po="PO-BIG"), agent_id="ap")
    assert gw.resolve(d.ticket_id, "cfo@acme.com", True)["status"] == "open"
    with pytest.raises(CheckpointError):
        gw.resolve(d.ticket_id, "cfo@acme.com", True)
    assert gw.org.store.payments() == []
    assert gw.resolve(d.ticket_id, "controller@acme.com", True)["status"] == "approved"
    assert len(gw.org.store.payments()) == 1


def test_only_approvers_and_never_the_requester(gw):
    d = gw.submit(pay(amount=12_000_00, po="PO-BIG", instructed_by={"source": "human", "identity": "cfo@acme.com"}),
                  agent_id="ap")
    with pytest.raises(CheckpointError) as e:
        gw.resolve(d.ticket_id, "ap", True)
    assert e.value.status == 403
    with pytest.raises(CheckpointError) as e:
        gw.resolve(d.ticket_id, "cfo@acme.com", True)  # asked for it, can't approve it
    assert e.value.status == 403
    gw.resolve(d.ticket_id, "controller@acme.com", False)
    with pytest.raises(CheckpointError) as e:
        gw.resolve(d.ticket_id, "controller@acme.com", True)
    assert e.value.status == 409
    assert gw.org.store.payments() == []


def test_unanswered_tickets_expire_fail_closed(gw, clock):
    d = gw.submit(pay(amount=12_000_00, po="PO-BIG"), agent_id="ap")
    clock.advance(hours=73)
    assert gw.expire() == [d.ticket_id]
    assert gw.status("R1")["status"] == "expired" and gw.status("R1")["returned"] == "block"
    with pytest.raises(CheckpointError):
        gw.resolve(d.ticket_id, "cfo@acme.com", True)


def test_recheck_at_approval_catches_what_changed(gw):
    d = gw.submit(pay("R1", 12_000_00, "INV-5", "PO-BIG", bank_account_on_invoice="GB00X"), agent_id="ap")
    assert d.verdict is Verdict.PAUSE
    from agent_checkpoint.store import Payment
    gw.org.store.record_payment(Payment("other", "human", "V1", "5", 12_000_00, ACCT, gw.clock().date(), "pay",
                                        "rail"))  # someone paid INV-5 by hand meanwhile
    out = gw.resolve(d.ticket_id, "cfo@acme.com", True)
    assert out["status"] == "blocked_on_recheck" and "already paid" in out["reasons"][0]


def test_retry_is_idempotent_and_reuse_is_refused(gw):
    first = gw.submit(pay(), agent_id="ap")
    again = gw.submit(pay(), agent_id="ap")
    assert again.replayed and again.transfer_id == first.transfer_id and len(gw.org.store.payments()) == 1
    with pytest.raises(CheckpointError) as e:
        gw.submit(pay(amount=1_00), agent_id="ap")
    assert e.value.status == 409
    with pytest.raises(CheckpointError) as e:
        gw.submit(pay(), agent_id="crm")  # another agent can't reuse (or read) the id
    assert e.value.status == 409
    with pytest.raises(CheckpointError):
        gw.status("R1", "crm")


def test_concurrent_copies_of_one_invoice_pay_once(gw):
    results = []

    def go(i):
        results.append(gw.submit(pay(f"C{i}", 1_000_00, "INV-RACE", "PO-BIG"), agent_id="ap"))
    threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(d.verdict is Verdict.GO for d in results) == 1
    assert len(gw.org.store.payments()) == 1


@pytest.mark.parametrize("bad", [
    {"request_id": "x"},
    {"request_id": "bad id!", "action": "pay", "vendor_id": "V1"},
    pay(amount=-5), pay(amount=1.5), pay(action="wire_everything"),
    {**pay(), "agent_id": "someone-else"}, {**pay(), "on": "2020-01-01"}, {**pay(), "bank_account": "GB00EVIL"},
    {**pay(), "amount": "12.345"},
])
def test_malformed_requests_refused_and_logged(gw, bad):
    with pytest.raises(CheckpointError) as e:
        gw.submit(bad, agent_id="ap")
    assert e.value.status == 422
    assert gw.org.ledger.entries("rejected")


def test_amount_strings_parse_exactly(gw):
    raw = pay()
    raw.pop("amount_cents")
    raw["amount"] = "4,800.00"
    d = gw.submit(raw, agent_id="ap")
    assert d.verdict is Verdict.GO and gw.org.store.payments()[0].amount_cents == 4_800_00


def test_receipts_cannot_be_forged_reused_expired_or_altered(gw):
    signer, rail = gw.org.signer, gw.org.rail
    now = gw.clock()
    r = signer.issue(request_id="Z1", action="pay", vendor_id="V1", amount_cents=100, payee_account=ACCT,
                     invoice_key="1", approved_by=[], now=now)
    with pytest.raises(ReceiptError, match="payee"):
        rail.execute(r, payee_account="GB00EVIL", amount_cents=100, now=now)
    with pytest.raises(ReceiptError, match="amount"):
        rail.execute(r, payee_account=ACCT, amount_cents=1_000_000, now=now)
    tampered = {"body": {**r["body"], "amount_cents": 1_000_000}, "sig": r["sig"]}
    with pytest.raises(ReceiptError, match="signature"):
        rail.execute(tampered, payee_account=ACCT, amount_cents=1_000_000, now=now)
    forged = Signer.generate("acme").issue(request_id="Z2", action="pay", vendor_id="V1", amount_cents=100,
                                           payee_account=ACCT, invoice_key="2", approved_by=[], now=now)
    with pytest.raises(ReceiptError, match="signature"):
        rail.execute(forged, payee_account=ACCT, amount_cents=100, now=now)
    with pytest.raises(ReceiptError, match="expired"):
        rail.execute(r, payee_account=ACCT, amount_cents=100, now=now + timedelta(minutes=11))
    assert rail.execute(r, payee_account=ACCT, amount_cents=100, now=now)
    with pytest.raises(ReceiptError, match="already used"):
        rail.execute(r, payee_account=ACCT, amount_cents=100, now=now)


def test_public_key_lets_a_third_party_verify(gw):
    r = gw.org.signer.issue(request_id="Z", action="pay", vendor_id="V1", amount_cents=1, payee_account=ACCT,
                            invoice_key="z", approved_by=["cfo@acme.com"], now=datetime.now().astimezone())
    body = Verifier(gw.org.signer.public_pem()).verify(r, datetime.now().astimezone())
    assert body["approved_by"] == ["cfo@acme.com"]


def test_learned_weights_reorder_but_never_change_verdicts(gw, clock):
    tickets = [{"status": "approved", "findings": [{"check": "no_po"}]}] * 30 + \
              [{"status": "rejected", "findings": [{"check": "invoice_account_differs"}]}] * 3
    w = learned_weights(tickets)
    assert w["no_po"] < 0.2 and w["invoice_account_differs"] == 1.0
    first = None
    for i in range(30):
        d = gw.submit(pay(f"N{i}", 3_000_00 + i, f"N-{i}", po=""), agent_id="ap")
        first = first or d
        gw.resolve(d.ticket_id, "cfo@acme.com", True)
        clock.advance(days=5)
    d = gw.submit(pay("N-last", 3_100_00, "N-last", po=""), agent_id="ap")
    assert [f.check for f in d.findings] == ["no_po"] == [f.check for f in first.findings]
    assert d.verdict is Verdict.PAUSE and d.risk < first.risk / 2  # still asks a human, just ranks lower


def test_bank_change_flow_then_payment_uses_new_account(gw, clock):
    d = gw.submit(bank_change(), agent_id="ap")
    gw.resolve(d.ticket_id, "cfo@acme.com", True, callback_verified=True)
    clock.advance(days=20)
    assert gw.submit(pay("R2"), agent_id="ap").verdict is Verdict.GO
    assert gw.org.store.payments()[0].bank_account == "US7777000011112222"
