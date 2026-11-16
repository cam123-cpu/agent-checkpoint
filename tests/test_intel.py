"""The shared fraud network."""

from datetime import date

from conftest import bank_change, checks, pay, policy

from agent_checkpoint.models import Verdict
from agent_checkpoint.sandbox import make_org
from agent_checkpoint.store import Vendor

FRAUD = "GB33BUKB20201555555555"


def other_company(intel, clock):
    g = make_org("beta", "Beta Corp", policy(), intel=intel, clock=clock)
    g.org.store.upsert_vendor(Vendor("V1", "Acme Supplies", "US1111", ("acmesupplies.com",), date(2024, 1, 1)))
    return g


def test_rejected_as_fraud_protects_every_company(gw, intel, clock):
    d = gw.submit(pay(bank_account_on_invoice=FRAUD), agent_id="ap")
    gw.resolve(d.ticket_id, "cfo@acme.com", False, "vendor says they never changed banks", fraud=True)
    beta = other_company(intel, clock)
    d2 = beta.submit(bank_change(acct=FRAUD), agent_id="ap")  # from the vendor's real domain, even
    assert d2.verdict is Verdict.BLOCK and "known_fraud" in checks(d2)


def test_blocked_lookalike_domain_can_be_reported(gw, intel, clock):
    gw.submit(bank_change(sender="ap@acmesupp1ies.com"), agent_id="ap")
    gw.report_fraud("C1", "cfo@acme.com")
    beta = other_company(intel, clock)
    d = beta.submit(pay(sender="ap@acmesupp1ies.com"), agent_id="ap")
    assert "known_fraud" in checks(d)


def test_our_own_forwarding_domain_is_never_reported(gw, intel):
    d = gw.submit(pay(amount=12_000_00, po="PO-BIG", sender="fraud@evil.example",
                      instructed_by={"source": "email", "identity": "fraud@evil.example via ap@acme.com"}), agent_id="ap")
    gw.resolve(d.ticket_id, "cfo@acme.com", False, fraud=True)
    assert intel.domain_reports("evil.example") == 1 and intel.domain_reports("acme.com") == 0


def test_real_vendor_details_are_never_reported(gw, intel):
    d = gw.submit(pay(amount=12_000_00, po="PO-BIG"), agent_id="ap")
    gw.resolve(d.ticket_id, "cfo@acme.com", False, fraud=True)
    assert intel.domain_reports("acmesupplies.com") == 0
    assert intel.account_reports(gw.org.store.vendor("V1").bank_account) == 0


def test_payment_to_a_reported_account_on_file_is_blocked_even_if_the_request_omits_it(gw, intel):
    """The payee is the account on file. The request does not have to repeat it for the fraud list to apply."""
    from conftest import ACCT
    intel.report("beta", account=ACCT)
    d = gw.submit(pay(), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and "known_fraud" in checks(d)
    assert gw.org.store.payments() == []


def test_network_stores_no_raw_account_numbers(intel):
    intel.report("acme", account=FRAUD)
    rows = intel.db.execute("SELECT value FROM reports").fetchall()
    assert FRAUD not in str(rows) and intel.account_reports("gb33 bukb 2020 1555 5555 55") == 1
