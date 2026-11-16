"""The shared fraud network."""

from datetime import date

from conftest import bank_change, checks, pay, policy

from agent_checkpoint.models import Verdict
from agent_checkpoint.sandbox import make_org
from agent_checkpoint.store import Vendor

FRAUD = "GB33BUKB20201555555555"


def other_company(intel, clock, org_id="beta"):
    g = make_org(org_id, org_id.title() + " Corp", policy(), intel=intel, clock=clock)
    g.org.store.upsert_vendor(Vendor("V1", "Acme Supplies", "US1111", ("acmesupplies.com",), date(2024, 1, 1)))
    return g


def test_rejected_as_fraud_protects_every_company(gw, intel, clock):
    d = gw.submit(pay(bank_account_on_invoice=FRAUD), agent_id="ap")
    gw.resolve(d.ticket_id, "cfo@acme.com", False, "vendor says they never changed banks", fraud=True)
    beta = other_company(intel, clock)
    d2 = beta.submit(bank_change(acct=FRAUD), agent_id="ap")  # from the vendor's real domain, even
    # One other company's report warns; it doesn't block on its own say-so.
    assert d2.verdict is Verdict.PAUSE and "network_report" in checks(d2) and "known_fraud" not in checks(d2)
    intel.report("gamma", account=FRAUD)  # a second company saw it too
    d3 = beta.submit(bank_change(rid="C2", acct=FRAUD), agent_id="ap")
    assert d3.verdict is Verdict.BLOCK and "known_fraud" in checks(d3)
    # The reporting company's own report blocks for itself.
    d4 = gw.submit(bank_change(rid="C9", acct=FRAUD), agent_id="ap")
    assert d4.verdict is Verdict.BLOCK and "known_fraud" in checks(d4)


def test_blocked_lookalike_domain_can_be_reported(gw, intel, clock):
    gw.submit(bank_change(sender="ap@acmesupp1ies.com"), agent_id="ap")
    gw.report_fraud("C1", "cfo@acme.com")
    beta = other_company(intel, clock)
    d = beta.submit(pay(sender="ap@acmesupp1ies.com"), agent_id="ap")
    assert "network_report" in checks(d)


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
    intel.report("gamma", account=ACCT)
    d = gw.submit(pay(), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and "known_fraud" in checks(d)
    assert gw.org.store.payments() == []


def test_network_stores_no_raw_account_numbers(intel):
    intel.report("acme", account=FRAUD)
    intel.report("acme", domain="evil.example")
    rows = intel.db.execute("SELECT value FROM reports").fetchall()
    assert FRAUD not in str(rows) and "evil" not in str(rows)  # neither accounts nor domains are readable
    assert intel.account_reports("gb33 bukb 2020 1555 5555 55") == 1 and intel.domain_reports("EVIL.example") == 1


def test_free_mail_is_never_listed(gw, intel):
    d = gw.submit(pay(amount=12_000_00, po="PO-BIG", sender="acme.billing@gmail.com"), agent_id="ap")
    gw.resolve(d.ticket_id, "cfo@acme.com", False, fraud=True)
    assert intel.domain_reports("gmail.com") == 0
    assert intel.report("beta", domain="outlook.com") is False


def test_a_report_can_be_withdrawn_and_it_is_logged(gw, intel, clock):
    d = gw.submit(pay(bank_account_on_invoice=FRAUD), agent_id="ap")
    gw.resolve(d.ticket_id, "cfo@acme.com", False, fraud=True)
    assert intel.account_reports(FRAUD) == 1
    import pytest

    from agent_checkpoint.gateway import CheckpointError
    with pytest.raises(CheckpointError):
        gw.withdraw_report("R1", "someone@else.com")
    out = gw.withdraw_report("R1", "cfo@acme.com", "the vendor really did move banks")
    assert out["withdrawn"] >= 1 and intel.account_reports(FRAUD) == 0
    assert gw.org.ledger.entries("fraud_report_withdrawn")[-1]["body"]["by"] == "cfo@acme.com"
    with pytest.raises(CheckpointError):  # nothing left to withdraw
        gw.withdraw_report("R1", "cfo@acme.com")


def test_old_readable_domains_are_hashed_on_upgrade(tmp_path):
    import sqlite3

    from agent_checkpoint.intel import Intel
    path, key = str(tmp_path / "intel.db"), b"k" * 32
    db = sqlite3.connect(path)
    db.executescript("""CREATE TABLE reports (kind TEXT NOT NULL, value TEXT NOT NULL, org_id TEXT NOT NULL,
                        at TEXT NOT NULL, PRIMARY KEY (kind, value, org_id));
                        INSERT INTO reports VALUES ('domain', 'evil.example', 'acme', '2026-01-01');
                        INSERT INTO reports VALUES ('domain', 'gmail.com', 'acme', '2026-01-01');""")
    db.commit()
    db.close()
    intel = Intel(path, key)
    rows = intel.db.execute("SELECT value FROM reports").fetchall()
    assert len(rows) == 1 and "evil" not in str(rows)
    assert intel.standing("domain", "evil.example", "beta") == (False, 1)
