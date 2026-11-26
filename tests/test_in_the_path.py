"""Documents that something which moves money can check, and the numbers a partner will ask for."""
import hashlib
import json
from datetime import UTC, date, datetime, timedelta

import pytest
from conftest import ACCT, pay, policy

from agent_checkpoint.evidence import evidence, usage
from agent_checkpoint.gateway import CheckpointError
from agent_checkpoint.importers import read_payment_run
from agent_checkpoint.release import ReleaseError, check_allowed, check_release, verify
from agent_checkpoint.sandbox import make_intel, make_org
from agent_checkpoint.store import Vendor

FILE = ("vendor_id,invoice_number,amount,bank_account\n"
        "V1,INV-100,1200.00,\n"
        "V1,INV-101,900.00,\n"
        "V2,INV-7,450.00,\n"
        "V1,INV-102,700.00,GB33BUKB20201555555555\n")


def run(gw, text=FILE, who="cfo@acme.com"):
    rows, errors = read_payment_run(gw.org.store, text)
    assert not errors
    return gw.check_run(rows, who, hashlib.sha256(text.encode()).hexdigest())


def later(gw, clock, **kw):
    clock.advance(**kw)
    return clock.now


def test_release_names_only_ready_lines_and_a_partner_can_check_it(gw, clock):
    out = run(gw)
    assert out["pilot"]["lines"] == 4 and out["pilot"]["not_ready"] == 1  # the line with a different account
    doc = gw.release_run(out["run_id"], "cfo@acme.com")
    pub = gw.org.signer.public_pem()
    body = verify(pub, doc, "release", clock.now)
    assert sorted(r["line"] for r in body["release"]) == [2, 3, 4]
    assert body["hold"] == [5]
    assert ACCT not in json.dumps(doc)  # no account numbers in the document
    res = check_release(body, FILE.encode())
    assert res["ok"] and res["release_lines"] == [2, 3, 4] and res["hold_lines"] == [5]
    # A changed file has no release.
    with pytest.raises(ReleaseError, match="not the file"):
        check_release(body, FILE.replace("900.00", "9000.00").encode())
    # Single use.
    with pytest.raises(ReleaseError, match="already used"):
        check_release(body, FILE.encode(), used_release_ids={body["release_id"]})
    # Released once per run.
    with pytest.raises(CheckpointError):
        gw.release_run(out["run_id"], "cfo@acme.com")


def test_bank_instructions_must_match_amount_and_account(gw, clock):
    body = verify(gw.org.signer.public_pem(), gw.release_run(run(gw)["run_id"], "cfo@acme.com"), "release", clock.now)
    v2 = gw.org.store.vendor("V2").bank_account
    good = [{"line": 1, "amount_cents": 1200_00, "account": ACCT}, {"line": 2, "amount_cents": 450_00, "account": v2}]
    assert check_release(body, instructions=good)["ok"]
    # The bank is about to send 900.00 somewhere else: refused, even though 900.00 was released.
    bad = good + [{"line": 3, "amount_cents": 900_00, "account": "GB33BUKB20201555555555"}]
    res = check_release(body, instructions=bad)
    assert not res["ok"] and res["unmatched"] == [3]
    # The held line can't be sent even to the right account; nor can a released line be sent twice.
    twice = good + [{"line": 4, "amount_cents": 1200_00, "account": ACCT}]
    assert check_release(body, instructions=twice)["unmatched"] == [4]


def test_documents_are_tamper_evident_expire_and_cannot_be_swapped(gw, clock):
    doc = gw.release_run(run(gw)["run_id"], "cfo@acme.com")
    pub = gw.org.signer.public_pem()
    forged = json.loads(json.dumps(doc))
    forged["body"]["release"].append({"line": 5, "vendor_id": "V1", "invoice_number": "INV-102", "amount_cents": 700_00,
                                      "account_tag": "x", "account_last4": "5555"})
    with pytest.raises(ReleaseError, match="signature"):
        verify(pub, forged, "release", clock.now)
    with pytest.raises(ReleaseError, match="not a allowed accounts"):
        verify(pub, doc, "allowed_accounts", clock.now)
    swapped = {**doc, "kind": "allowed_accounts"}  # same signature, other kind: the signing context differs
    with pytest.raises(ReleaseError, match="signature"):
        verify(pub, swapped, "allowed_accounts", clock.now)
    with pytest.raises(ReleaseError, match="expired"):
        verify(pub, doc, "release", clock.now + timedelta(hours=25))
    other = make_org("beta", "Beta", policy(), intel=make_intel())
    with pytest.raises(ReleaseError, match="signature"):
        verify(other.org.signer.public_pem(), doc, "release", clock.now)


def test_an_old_check_is_not_released(gw, clock):
    out = run(gw)
    later(gw, clock, hours=25)
    with pytest.raises(CheckpointError, match="Check the file again"):
        gw.release_run(out["run_id"], "cfo@acme.com")


def test_only_approvers_release_or_issue_lists(gw):
    out = run(gw)
    with pytest.raises(CheckpointError):
        gw.release_run(out["run_id"], "intern@acme.com")
    with pytest.raises(CheckpointError):
        gw.allowed_accounts("intern@acme.com")


def test_allowed_accounts_list(gw, clock):
    pub = gw.org.signer.public_pem()
    first = verify(pub, gw.allowed_accounts("cfo@acme.com"), "allowed_accounts", clock.now)
    second = verify(pub, gw.allowed_accounts("cfo@acme.com"), "allowed_accounts", clock.now)
    assert (first["version"], second["version"]) == (1, 2)
    # Loaded vendors have not been through a bank-change call. The list says so.
    assert second["accounts"] and all(a["confirmed_by_call"] is False for a in second["accounts"])
    gw.org.store.set_bank("V1", ACCT, date(2026, 11, 1))
    third = verify(pub, gw.allowed_accounts("cfo@acme.com"), "allowed_accounts", clock.now)
    by_id = {a["vendor_id"]: a for a in third["accounts"]}
    assert by_id["V1"]["confirmed_by_call"] is True and by_id["V2"]["confirmed_by_call"] is False
    ins = [{"line": 1, "amount_cents": 5_00, "account": ACCT, "vendor_id": "V1"},
           {"line": 2, "amount_cents": 5_00, "account": "GB33BUKB20201555555555"},
           {"line": 3, "amount_cents": 5_00, "account": ACCT, "vendor_id": "V2"}]  # right account, wrong vendor
    res = check_allowed(second, ins)
    assert res["allowed_lines"] == [1] and res["refused_lines"] == [2, 3]
    with pytest.raises(ReleaseError, match="version"):
        check_allowed(first, ins, min_version=2)  # a partner never goes back to an older list


def test_evidence_and_usage_come_from_the_log(gw, clock):
    out = run(gw)
    gw.release_run(out["run_id"], "cfo@acme.com")
    gw.mark_line(out["run_id"], 5, "fraud", "cfo@acme.com", "vendor never changed banks")
    gw.report_miss("cfo@acme.com", 3_000_00, "V2", note="paid a fake invoice by cheque outside the file")
    u = usage(gw.org.ledger)
    assert (u["payment_files_checked"], u["payment_lines_checked"], u["releases_issued"]) == (1, 4, 1)
    assert u["released_cents"] == 1200_00 + 900_00 + 450_00
    ev = evidence(gw.org.ledger)
    assert ev["held_fraud"] == 1 and ev["misses_recorded"] == 1 and ev["fraud_miss_rate_pct"] == 50.0
    assert ev["precision_pct"] == 100.0 and ev["audit_log"]["ok"]
    assert any("anecdotes" in c for c in ev["caveats"])
    with pytest.raises(CheckpointError):
        gw.mark_line(out["run_id"], 99, "fine", "cfo@acme.com")


def test_cli_partner_verification_needs_no_data_folder(gw, clock, tmp_path, capsys):
    from agent_checkpoint.cli import main
    clock.now = datetime.now(UTC)  # the partner checks against the real time
    out = run(gw)
    doc = gw.release_run(out["run_id"], "cfo@acme.com")
    (tmp_path / "pub.pem").write_text(gw.org.signer.public_pem())
    (tmp_path / "release.json").write_text(json.dumps(doc))
    (tmp_path / "run.csv").write_text(FILE)
    args = ["verify-release", str(tmp_path / "release.json"), "--public-key", str(tmp_path / "pub.pem"),
            "--file", str(tmp_path / "run.csv"), "--used", str(tmp_path / "used.txt")]
    assert main(args) == 0 and '"release_lines"' in capsys.readouterr().out
    assert main(args) == 1 and "already used" in capsys.readouterr().out
    (tmp_path / "run.csv").write_text(FILE.replace("450.00", "4500.00"))
    (tmp_path / "used.txt").write_text("")
    assert main(args) == 1 and "not the file" in capsys.readouterr().out


# --- what real payment files punish -------------------------------------------------------

def test_no_currency_column_means_the_company_currency(clock):
    g = make_org(policy=policy(currency="EUR"), intel=make_intel(), clock=clock)
    g.org.store.upsert_vendor(Vendor("V1", "Acme", ACCT, ("acme.de",), date(2024, 1, 1)))
    out = run(g, "vendor_id,invoice_number,amount\nV1,A-1,100.00\n")
    assert out["rows"][0]["verdict"] == "go"
    out = run(g, "vendor_id,invoice_number,amount,currency\nV1,A-2,100.00,USD\n")
    assert out["rows"][0]["verdict"] == "block"  # never converted


def test_instalments_pause_and_duplicates_block(gw):
    gw.submit(pay(), agent_id="ap")  # INV-1, 4,800.00, paid
    out = run(gw, "vendor_id,invoice_number,amount\nV1,INV-1,2000.00\nV1,INV-1,4800.00\n")
    by_line = {r["line"]: r for r in out["rows"]}
    assert by_line[2]["verdict"] == "pause" and "instalment" in " ".join(by_line[2]["reasons"])
    assert by_line[3]["verdict"] == "block"


def test_missing_invoice_number_is_held(gw):
    out = run(gw, "vendor_id,invoice_number,amount\nV1,,120.00\n")
    assert out["rows"][0]["verdict"] == "pause"
    assert "duplicate can't be caught" in out["rows"][0]["reasons"][0]


def test_many_small_bills_in_a_file_are_not_a_split(gw):
    lines = "".join(f"V1,S-{i},{900 + i}.00\n" for i in range(12))  # 12 small bills, together over the limit
    out = run(gw, "vendor_id,invoice_number,amount\n" + lines)
    assert all(r["verdict"] == "go" for r in out["rows"]), [r["reasons"] for r in out["rows"]]
    out = run(gw, "vendor_id,invoice_number,amount\nV1,B-1,6000.00\nV1,B-2,5000.00\n")
    assert any("split" in " ".join(r["reasons"]).lower() or "under the approval limit" in " ".join(r["reasons"])
               for r in out["rows"])
