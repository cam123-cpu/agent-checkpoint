"""Each check, through the real gateway."""

from datetime import date

import pytest
from conftest import ACCT, bank_change, checks, pay

from agent_checkpoint.models import Verdict
from agent_checkpoint.store import PurchaseOrder, Vendor, norm_invoice


def test_clean_payment_goes_and_moves_money_to_account_on_file(gw):
    d = gw.submit(pay(), agent_id="ap")
    assert d.verdict is Verdict.GO and d.status == "executed" and d.transfer_id
    [p] = gw.org.store.payments()
    assert p.bank_account == ACCT and p.via == "rail"


def test_invoice_printing_another_account_pauses_but_never_redirects(gw):
    d = gw.submit(pay(bank_account_on_invoice="GB00EVIL000"), agent_id="ap")
    assert d.verdict is Verdict.PAUSE and "invoice_account_differs" in checks(d)
    gw.resolve(d.ticket_id, "cfo@acme.com", True)
    assert gw.org.store.payments()[0].bank_account == ACCT  # approved, still the account on file


def test_decimal_slip_blocked(gw):
    d = gw.submit(pay(amount=48_000_00), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and "amount_magnitude" in checks(d)


@pytest.mark.parametrize("second", ["inv 1", "INV-0001", "Invoice #1"])
def test_same_invoice_twice_blocked_despite_formatting(gw, second):
    assert gw.submit(pay("R1", 1_000_00, "INV-1", "PO-BIG"), agent_id="ap").verdict is Verdict.GO
    d = gw.submit(pay("R2", 1_000_00, second, "PO-BIG"), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and "duplicate_payment" in checks(d)


def test_norm_invoice():
    assert norm_invoice("INV-0042") == norm_invoice("inv 42") == norm_invoice("Invoice #42") == "42"


def test_duplicate_while_first_is_waiting_for_approval(gw):
    first = gw.submit(pay("R1", 12_000_00, "INV-9", "PO-BIG"), agent_id="ap")
    assert first.verdict is Verdict.PAUSE
    d = gw.submit(pay("R2", 12_000_00, "inv 9", "PO-BIG"), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and "duplicate_pending" in checks(d)


def test_near_duplicate_pauses(gw, clock):
    gw.submit(pay("R1", 3_000_00, "A-1", "PO-BIG"), agent_id="ap")
    clock.advance(days=3)
    d = gw.submit(pay("R2", 3_000_00, "A-2", "PO-BIG"), agent_id="ap")
    assert "near_duplicate" in checks(d) and d.verdict is Verdict.PAUSE


def test_po_checks(gw):
    gw.org.store.upsert_po(PurchaseOrder("PO-V2", "V2", 1_000_00))
    assert "po_wrong_vendor" in checks(gw.submit(pay("R1", po="PO-V2"), agent_id="ap"))
    assert "po_unknown" in checks(gw.submit(pay("R2", po="PO-NOPE"), agent_id="ap"))
    assert "po_overrun" in checks(gw.submit(pay("R3", 6_000_00, "I-3"), agent_id="ap"))
    assert "no_po" in checks(gw.submit(pay("R4", 3_000_00, "I-4", po=""), agent_id="ap"))
    assert gw.submit(pay("R5", 2_000_00, "I-5", po=""), agent_id="ap").verdict is Verdict.GO  # small: fine


def test_approval_limit_and_dual_approval(gw):
    d = gw.submit(pay("R1", 60_000_00, "I-1", "PO-BIG"), agent_id="ap")
    assert d.verdict is Verdict.PAUSE and "two approvers" in " ".join(f.message for f in d.findings)
    assert gw.org.store.ticket(d.ticket_id)["needed"] == 2


def test_split_payments(gw, clock):
    gw.submit(pay("R1", 6_000_00, "S-1", "PO-BIG"), agent_id="ap")
    clock.advance(days=1)
    d = gw.submit(pay("R2", 5_000_00, "S-2", "PO-BIG"), agent_id="ap")
    assert "split_payment" in checks(d)


def test_amount_outlier_vs_vendor_history(gw, clock):
    for i in range(10):
        gw.submit(pay(f"H{i}", 1_000_00 + i * 1_00, f"H-{i}", "PO-BIG"), agent_id="ap")
        clock.advance(days=12)
    d = gw.submit(pay("R1", 8_000_00, "BIG-1", "PO-BIG"), agent_id="ap")
    assert "amount_outlier" in checks(d) and d.verdict is Verdict.PAUSE


def test_unknown_and_lookalike_vendor(gw):
    assert "unknown_vendor" in checks(gw.submit(pay(vendor="V-NOPE", po=""), agent_id="ap"))
    gw.org.store.upsert_vendor(Vendor("V9", "Acme Suppiles", "US555", ("acme-sup.com",), date(2026, 9, 28)))
    d = gw.submit(pay("R2", 1_000_00, "X-1", po="", vendor="V9", sender="b@acme-sup.com"), agent_id="ap")
    assert "lookalike_vendor" in checks(d)


def test_sender_domain_checks(gw):
    d = gw.submit(pay("R1", sender="billing@acmesuppIies.com"), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and "lookalike_domain" in checks(d)
    d = gw.submit(pay("R2", 1_000_00, "I-2", "PO-BIG", sender="someone@gmail.com"), agent_id="ap")
    assert d.verdict is Verdict.PAUSE and "unknown_sender" in checks(d)
    d = gw.submit(pay("R3", 1_000_00, "I-3", "PO-BIG", sender="ap@acme.com"), agent_id="ap")  # our own inbox
    assert "unknown_sender" not in checks(d)


def test_punycode_lookalike_is_the_name_not_the_prefix(gw):
    """An internationalized domain is a look-alike only when the name is close, not because it is punycode."""
    from agent_checkpoint.store import Vendor
    homoglyph = "аcmesupplies.com".encode("idna").decode("ascii")  # Cyrillic а
    d = gw.submit(pay("P1", sender=f"billing@{homoglyph}"), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and "lookalike_domain" in checks(d)
    unrelated = "點看.com".encode("idna").decode("ascii")
    d = gw.submit(pay("P2", 1_000_00, "I-9", "PO-BIG", sender=f"billing@{unrelated}"), agent_id="ap")
    assert "lookalike_domain" not in checks(d) and "unknown_sender" in checks(d) and d.verdict is Verdict.PAUSE
    books = "bücher.de"
    gw.org.store.upsert_vendor(Vendor("V3", "Bucher GmbH", "DE89370400440532013000", (books,), date(2024, 1, 1)))
    own = books.encode("idna").decode("ascii")
    d = gw.submit(pay("P3", 1_000_00, "I-10", po="", vendor="V3", sender=f"billing@{own}"), agent_id="ap")
    assert "lookalike_domain" not in checks(d) and "unknown_sender" not in checks(d)


def test_new_vendor_payment_pauses_until_the_window_passes(gw, clock):
    from agent_checkpoint.store import Vendor
    gw.org.store.upsert_vendor(Vendor("V9", "Totally New Supplies", "US444400001111", ("newsupplies.com",),
                                      clock().date()))
    d = gw.submit(pay("N1", 1_000_00, "N-1", po="", vendor="V9", sender="ap@newsupplies.com"), agent_id="ap")
    assert "new_vendor" in checks(d) and d.verdict is Verdict.PAUSE
    clock.advance(days=31)
    d = gw.submit(pay("N2", 1_000_00, "N-2", po="", vendor="V9", sender="ap@newsupplies.com"), agent_id="ap")
    assert "new_vendor" not in checks(d) and "new_vendor_large" not in checks(d)


def test_lookalike_bank_change_blocked(gw):
    d = gw.submit(bank_change(sender="ap@acmesupp1ies.com"), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and "lookalike_domain" in checks(d)
    assert gw.org.store.vendor("V1").bank_account == ACCT


def test_bank_change_to_another_vendors_account_blocked(gw):
    d = gw.submit(bank_change(acct="US0009999000011"), agent_id="ap")
    assert "shared_account" in checks(d) and d.verdict is Verdict.BLOCK


def test_genuine_bank_change_needs_callback_then_payments_pause(gw, clock):
    d = gw.submit(bank_change(), agent_id="ap")
    assert d.verdict is Verdict.PAUSE
    from agent_checkpoint.gateway import CheckpointError
    with pytest.raises(CheckpointError) as e:
        gw.resolve(d.ticket_id, "cfo@acme.com", True)
    assert e.value.status == 422
    gw.resolve(d.ticket_id, "cfo@acme.com", True, "called +1 555 0100", callback_verified=True)
    clock.advance(days=2)
    p = gw.submit(pay("R9"), agent_id="ap")
    assert p.verdict is Verdict.PAUSE and "recent_bank_change" in checks(p)


def test_refund_rules(gw):
    gw.submit(pay(), agent_id="ap")
    refund = {"request_id": "F1", "action": "refund", "vendor_id": "V1", "amount_cents": 100_00,
              "invoice_number": "INV-1", "evidence": [{"kind": "ticket", "ref": "CASE-1"}],
              "instructed_by": {"source": "human", "identity": "rep@acme.com"}}
    assert gw.submit(refund, agent_id="crm").verdict is Verdict.GO
    assert gw.org.store.payments(kind="refund")[0].bank_account == ACCT  # back where it came from
    d = gw.submit({**refund, "request_id": "F2", "bank_account": "US-OTHER-1"}, agent_id="crm")
    assert "refund_new_account" in checks(d)
    d = gw.submit({**refund, "request_id": "F3", "amount_cents": 4_750_00}, agent_id="crm")
    assert "refund_exceeds" in checks(d)
    d = gw.submit({**refund, "request_id": "F4", "invoice_number": "NOPE"}, agent_id="crm")
    assert "refund_no_original" in checks(d)


def test_edit_paid_record_blocked(gw):
    gw.submit(pay(), agent_id="ap")
    edit = {"request_id": "E1", "action": "edit_record", "vendor_id": "V1", "invoice_number": "INV-1",
            "evidence": [{"kind": "ticket", "ref": "OPS-1"}], "instructed_by": {"source": "human", "identity": "j@acme.com"}}
    assert "edit_paid_record" in checks(gw.submit(edit, agent_id="ops"))
    assert gw.submit({**edit, "request_id": "E2", "invoice_number": "INV-UNPAID"}, agent_id="ops").verdict is Verdict.GO


def test_agent_scope_and_caps(gw):
    assert "agent_scope" in checks(gw.submit(pay(), agent_id="crm"))          # wrong action
    assert "agent_scope" in checks(gw.submit(pay("R2"), agent_id="stranger"))  # unregistered
    d = gw.submit(pay("R3", 150_000_00, "I-3", "PO-BIG"), agent_id="ap")      # over per-action max
    assert d.verdict is Verdict.BLOCK


def test_daily_cap(gw):
    for i in range(2):
        r = gw.submit(pay(f"D{i}", 90_000_00, f"D-{i}", "PO-BIG"), agent_id="ap")
        if r.ticket_id:
            gw.resolve(r.ticket_id, "cfo@acme.com", True)
            t = gw.org.store.ticket(r.ticket_id)
            if t["status"] == "open":
                gw.resolve(r.ticket_id, "controller@acme.com", True)
    d = gw.submit(pay("D9", 30_000_00, "D-9", "PO-BIG"), agent_id="ap")
    assert "daily_cap" in checks(d)


def test_burst_of_actions_pauses(gw):
    last = None
    for i in range(25):
        last = gw.submit(pay(f"B{i}", 100_00 + i, f"B-{i}", "PO-BIG"), agent_id="ap")
    assert "burst" in checks(last)


def test_missing_provenance_blocked(gw):
    d = gw.submit(pay(evidence=[], instructed_by=None), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and "provenance" in checks(d)


def test_currency_mismatch_blocked(gw):
    assert "currency" in checks(gw.submit(pay(currency="EUR"), agent_id="ap"))


def test_check_failure_fails_closed(gw, monkeypatch):
    import agent_checkpoint.checks as c

    def broken(req, ctx):
        raise RuntimeError("boom")
    monkeypatch.setattr(c, "CHECKS", c.CHECKS + (broken,))
    d = gw.submit(pay(), agent_id="ap")
    assert d.verdict is Verdict.BLOCK and "checkpoint_error" in checks(d)
    assert gw.org.store.payments() == []
