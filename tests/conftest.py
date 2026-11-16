from datetime import UTC, date, datetime, timedelta

import pytest

from agent_checkpoint.policy import AgentScope, Policy
from agent_checkpoint.sandbox import make_intel, make_org
from agent_checkpoint.store import PurchaseOrder, Vendor

ACCT = "US0002100000088"
APPROVERS = ("cfo@acme.com", "controller@acme.com")


class Clock:
    def __init__(self, start=datetime(2026, 10, 1, 15, tzinfo=UTC)):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


def policy(mode="enforce", **kw):
    return Policy(mode=mode, internal_domains=("acme.com",), approvers=APPROVERS, agents={
        "ap": AgentScope(("pay", "change_bank"), 100_000_00, 200_000_00),
        "crm": AgentScope(("refund",), 5_000_00, 10_000_00),
        "ops": AgentScope(("edit_record",), 0, 0),
    }, **kw)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def intel():
    return make_intel()


@pytest.fixture
def gw(clock, intel):
    g = make_org(policy=policy(), intel=intel, clock=clock)
    s = g.org.store
    s.upsert_vendor(Vendor("V1", "Acme Supplies", ACCT, ("acmesupplies.com",), date(2024, 1, 1), phone="+1 555 0100"))
    s.upsert_vendor(Vendor("V2", "Beta Freight", "US0009999000011", ("betafreight.com",), date(2024, 1, 1)))
    s.upsert_po(PurchaseOrder("PO-1", "V1", 4_800_00))
    s.upsert_po(PurchaseOrder("PO-BIG", "V1", 500_000_00))
    return g


def pay(rid="R1", amount=4_800_00, inv="INV-1", po="PO-1", vendor="V1", sender="billing@acmesupplies.com", **kw):
    d = {"request_id": rid, "action": "pay", "vendor_id": vendor, "amount_cents": amount, "invoice_number": inv,
         "evidence": [{"kind": "invoice", "ref": "inv.pdf", "sender": sender}],
         "instructed_by": {"source": "email", "identity": sender}}
    if po:
        d["po_number"] = po
    d.update(kw)
    return d


def bank_change(rid="C1", vendor="V1", acct="US7777000011112222", sender="ap@acmesupplies.com"):
    return {"request_id": rid, "action": "change_bank", "vendor_id": vendor, "bank_account": acct,
            "evidence": [{"kind": "email", "ref": "m.eml", "sender": sender}],
            "instructed_by": {"source": "email", "identity": sender}}


def checks(decision):
    return {f.check for f in decision.findings}
