"""A paused action is paid only if what the approver saw is still true when the last person approves."""
from datetime import date

from conftest import ACCT, APPROVERS, Clock, pay

from agent_checkpoint.policy import AgentScope, Policy
from agent_checkpoint.sandbox import make_intel, make_org
from agent_checkpoint.store import PurchaseOrder, Vendor


def org():
    clock = Clock()
    pol = Policy(mode="enforce", internal_domains=("acme.com",), approvers=APPROVERS, agents={
        "ap": AgentScope(("pay",), 100_000_00, 500_000_00),
        "crm": AgentScope(("refund",), 100_000_00, 500_000_00),
    })
    gw = make_org(policy=pol, intel=make_intel(), clock=clock)
    gw.org.store.upsert_vendor(Vendor("V1", "Acme Supplies", ACCT, ("acmesupplies.com",), date(2024, 1, 1),
                                      phone="+1 555 0100"))
    gw.org.store.upsert_po(PurchaseOrder("PO-BIG", "V1", 500_000_00))
    return gw, clock


def refund(rid, amount, inv):
    return {"request_id": rid, "action": "refund", "vendor_id": "V1", "amount_cents": amount, "invoice_number": inv,
            "evidence": [{"kind": "email", "ref": "t.eml", "sender": "ar@acmesupplies.com"}],
            "instructed_by": {"source": "email", "identity": "ar@acmesupplies.com"}}


def test_refund_destination_is_bound_to_the_ticket():
    gw, clock = org()
    d = gw.submit(pay("P1", amount=30_000_00, inv="INV-30", po="PO-BIG"), agent_id="ap")
    gw.resolve(d.ticket_id, "cfo@acme.com", True)
    clock.advance(days=3)
    r = gw.submit(refund("F1", 15_000_00, "INV-30"), agent_id="crm")
    assert r.status == "awaiting_approval"
    from agent_checkpoint.views import tickets
    shown = [t for t in tickets(gw) if t["ticket_id"] == r.ticket_id][0]
    assert shown["pays_to"].endswith(ACCT[-4:])  # the approver sees where the refund goes
    # The books are corrected behind the ticket's back: the original payment now names another account.
    s = gw.org.store
    s.q("UPDATE payments SET bank_account = ? WHERE request_id = 'P1'",
        (s.crypto.encrypt("US9999000099990000", "payments.bank:P1"),))
    out = gw.resolve(r.ticket_id, "cfo@acme.com", True)
    assert out["status"] == "blocked_on_recheck"
    assert not s.payments(kind="refund")  # nothing refunded


def test_a_new_pause_reopens_the_ticket_instead_of_paying():
    gw, clock = org()
    first = gw.submit(pay("P1", amount=6_000_00, inv="INV-1", po=None), agent_id="ap")
    assert first.status == "awaiting_approval"
    assert {f.check for f in first.findings} == {"no_po"}
    # While it waits, another bill to the same vendor is paid. Together they now cross the approval limit.
    assert gw.submit(pay("P2", amount=5_500_00, inv="INV-2", po="PO-BIG"), agent_id="ap").status == "executed"
    out = gw.resolve(first.ticket_id, "cfo@acme.com", True)
    assert out["status"] == "open" and out["reopened"] is True
    assert any("approval limit" in r for r in out["reasons"])
    t = gw.org.store.ticket(first.ticket_id)
    assert t["approvals"] == [] and {f["check"] for f in t["findings"]} == {"no_po", "split_payment"}
    assert len(gw.org.store.payments(kind="pay")) == 1  # not paid
    reopened = [e for e in gw.org.ledger.entries("human_decision") if e["body"].get("status") == "reopened"]
    assert reopened
    # Approving again, now that the split is on the ticket, pays it.
    assert gw.resolve(first.ticket_id, "controller@acme.com", True)["status"] == "approved"
    assert len(gw.org.store.payments(kind="pay")) == 2


def test_bank_change_approval_records_the_number_dialled():
    from conftest import bank_change
    gw, _ = org()
    gw.org.policy.agents["ap"] = AgentScope(("pay", "change_bank"), 100_000_00, 500_000_00)
    d = gw.submit(bank_change(), agent_id="ap")
    import pytest

    from agent_checkpoint.gateway import CheckpointError
    for wrong in ("", "+1 555 7777"):
        with pytest.raises(CheckpointError):
            gw.resolve(d.ticket_id, "cfo@acme.com", True, callback_verified=True, called_number=wrong)
    gw.resolve(d.ticket_id, "cfo@acme.com", True, callback_verified=True, called_number="1-555-0100")
    entry = gw.org.ledger.entries("human_decision")[-1]["body"]
    assert entry["called_number"] == "15550100"
    assert gw.org.store.ticket(d.ticket_id)["approvals"][-1]["called_number"] == "15550100"
