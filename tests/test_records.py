"""Self-service records, agents and people; payment history; payment-run checks. Including attacks on them."""

import json
import sqlite3
import threading
from dataclasses import replace
from datetime import date

import pytest
from test_web_security import PW, Client, register

from agent_checkpoint.importers import import_history, import_vendors, map_headers, parse_date, read_payment_run
from agent_checkpoint.server import ServerConfig, make_server
from agent_checkpoint.store import PurchaseOrder, Store, Vendor
from agent_checkpoint.tenancy import Registry

ACCT = "US0002100000088123"


@pytest.fixture
def site(tmp_path):
    reg = Registry(str(tmp_path))
    reg.create_org("acme", "Acme")
    reg.save_policy("acme", replace(reg.policy("acme"), mode="enforce"))
    for email, role in (("admin@acme.com", "admin"), ("admin2@acme.com", "admin"), ("approver@acme.com", "approver"),
                        ("audit@acme.com", "auditor")):
        reg.add_user("acme", email, role, PW)
    reg.create_org("beta", "Beta")
    reg.add_user("beta", "admin@beta.com", "admin", PW)
    gw = reg.gateway("acme")
    gw.org.store.upsert_vendor(Vendor("V1", "Northwind Supplies", ACCT, ("northwind.com",), date(2024, 1, 1), phone="+1 555"))
    gw.org.store.upsert_vendor(Vendor("V2", "Contoso", "US0009999000111", ("contoso.com",), date(2024, 1, 1)))
    gw.org.store.upsert_po(PurchaseOrder("PO-1", "V1", 50_000_00))
    srv = register(make_server(reg, "127.0.0.1", 0, ServerConfig(secure_cookies=False)), reg)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def as_(email):
        c = Client("127.0.0.1", port)
        assert c.login(email)[0] == 200
        return c
    yield reg, gw, as_, port
    srv.shutdown()


def history_csv(rows):
    return "Supplier,Invoice #,Amount Paid,Payment Date\n" + "\n".join(rows) + "\n"


# --- importing --------------------------------------------------------------------------

def test_reimport_cannot_blank_or_replace_the_phone_or_the_domains(site):
    reg, gw, as_, _ = site
    store = gw.org.store
    before = store.vendor("V1")
    # No phone or domain columns: a refresh of the vendor file must not wipe the callback number.
    n, errors = import_vendors(store, f"vendor_id,name,bank_account\nV1,Northwind Supplies,{ACCT}\n")
    assert n == 1 and errors == []
    kept = store.vendor("V1")
    assert kept.phone == before.phone and kept.email_domains == before.email_domains
    # A file that names a different phone or domain is refused. The bank account is untouched.
    n, errors = import_vendors(store, "vendor_id,name,bank_account,email_domains,phone\n"
                               f"V1,Northwind Supplies,{ACCT},evil.example,+1 999 555 0199\n")
    assert n == 0 and any("on file" in e for e in errors)
    assert store.vendor("V1").phone == before.phone
    assert store.vendor("V1").email_domains == before.email_domains


def test_columns_are_matched_by_meaning():
    m = map_headers(["Supplier", "Invoice #", "Amount Paid", "Payment Date", "Remittance email"],
                    ["name", "invoice_number", "amount", "paid_on", "email_domains"])
    assert m == {"name": 0, "invoice_number": 1, "amount": 2, "paid_on": 3, "email_domains": 4}


def test_dates_are_never_guessed():
    assert parse_date("03/04/2026", "mdy") == date(2026, 3, 4)
    assert parse_date("03/04/2026", "dmy") == date(2026, 4, 3)
    assert parse_date("2026-03-04") == parse_date("4 Mar 2026") == parse_date("Mar 4, 2026") == date(2026, 3, 4)
    for bad in ("13/13/2026", "yesterday", ""):
        with pytest.raises(ValueError):
            parse_date(bad)


def test_history_import(site):
    reg, gw, as_, _ = site
    store = gw.org.store
    rows = [f"Northwind Supplies,INV-{i:03d},\"{1000 + i * 10:,}.00\",2026-0{1 + i % 8}-1{i % 9}" for i in range(12)]
    added, already, errors = import_history(store, history_csv(rows + ["Nobody Inc,X-1,10,2026-01-01",
                                                                       "Northwind Supplies,F-1,10,2099-01-01"]))
    assert added == 12 and already == 0 and len(errors) == 2
    assert "unknown vendor" in errors[0] and "future" in errors[1]
    assert import_history(store, history_csv(rows))[:2] == (0, 12)  # idempotent
    assert store.counts()["vendors_with_history"] == 1
    # history now protects against paying an old invoice again, and gives a baseline for amounts
    d = gw.submit({"request_id": "R1", "action": "pay", "vendor_id": "V1", "amount_cents": 1_000_00,
                   "invoice_number": "inv 000", "po_number": "PO-1",
                   "evidence": [{"kind": "invoice", "ref": "i.pdf"}], "instructed_by": {"source": "human", "identity": "x"}},
                  agent_id="none")
    assert "duplicate_payment" in {f.check for f in d.findings}
    from agent_checkpoint.checks import Context, check_amount_outlier
    from agent_checkpoint.models import ActionRequest
    req = ActionRequest.from_dict({"request_id": "z", "action": "pay", "vendor_id": "V1", "amount_cents": 9_000_00,
                                   "invoice_number": "Z"}, agent_id="a", on=date.today())
    assert check_amount_outlier(req, Context(store, gw.org.policy, gw.clock()))


def test_history_import_cannot_choose_a_refund_account(site):
    _, gw, _, _ = site
    store = gw.org.store
    on_file = store.vendor("V1").bank_account
    same = f"vendor_id,invoice_number,amount,paid_on,bank_account\nV1,H-1,25.00,2026-02-02,{on_file}\n"
    added, _, errors = import_history(store, same)
    assert added == 1 and errors == []
    assert store.payments()[0].bank_account == on_file
    other = "vendor_id,invoice_number,amount,paid_on,bank_account\nV1,H-2,25.00,2026-02-03,US9999999999999999\n"
    added, _, errors = import_history(store, other)
    assert added == 0 and any("account on file" in e for e in errors)
    assert [p.invoice_key for p in store.payments()] == ["H1"]


def test_old_databases_are_upgraded(tmp_path):
    path = str(tmp_path / "old.db")
    db = sqlite3.connect(path)
    db.executescript("""CREATE TABLE payments (id INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, agent_id TEXT NOT NULL,
        vendor_id TEXT NOT NULL, invoice_key TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
        bank_account TEXT NOT NULL, on_date TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('pay', 'refund')),
        via TEXT NOT NULL CHECK (via IN ('rail', 'observed')));
        CREATE INDEX payments_vendor ON payments (vendor_id, kind);
        INSERT INTO payments VALUES (1, 'r1', 'a', 'V1', '1', 100, 'x', '2026-01-01', 'pay', 'rail');""")
    db.commit()
    db.close()
    s = Store(path, b"k" * 32)
    assert s.q("SELECT COUNT(*) FROM payments")[0][0] == 1
    s.q("INSERT INTO payments (request_id, agent_id, vendor_id, invoice_key, amount_cents, bank_account, on_date, kind, via) "
        "VALUES ('r2', 'h', 'V1', '2', 5, 'x', '2026-01-02', 'pay', 'imported')")


# --- payment runs -------------------------------------------------------------------------

RUN = """Supplier,Invoice #,Amount,Pay to account
Northwind Supplies,A-1,"1,200.00",{acct}
Northwind Supplies,A-1,"1,200.00",{acct}
Northwind Supplies,A-2,"1,300.00",GB00ATTACKER000001
Contoso,C-1,"4,000.00",
Unknown Ltd,U-1,"500.00",
"""


def test_payment_run_finds_problems_and_changes_nothing(site):
    reg, gw, as_, _ = site
    store = gw.org.store
    before = (store.counts(), store.po("PO-1").billed_cents, len(gw.org.ledger.entries("decision")))
    rows, errors = read_payment_run(store, RUN.format(acct=ACCT))
    out = gw.check_run(rows, "approver@acme.com", "abc")
    by_line = {r["line"]: r for r in out["rows"]}
    assert by_line[2]["verdict"] == "go"
    assert by_line[3]["verdict"] == "block" and "line 2 of this payment run" in by_line[3]["reasons"][0]
    assert by_line[4]["verdict"] == "block" and "payment file sends this to account ...0001" in by_line[4]["reasons"][0]
    assert by_line[5]["verdict"] == "go"  # no PO needed in a run; no account given means the account on file
    assert by_line[6]["verdict"] == "block" and "not on the vendor list" in by_line[6]["reasons"][0]
    assert out["summary"]["block"]["count"] == 3
    assert (store.counts(), store.po("PO-1").billed_cents, len(gw.org.ledger.entries("decision"))) == before
    entry = gw.org.ledger.entries("payment_run_checked")[-1]["body"]
    assert entry["by"] == "approver@acme.com" and entry["file_sha256"] == "abc"
    assert {line["invoice_number"] for line in entry["lines"]} >= {"A-1", "A-2"}
    assert ACCT not in json.dumps(entry["lines"]) and "GB00ATTACKER" not in json.dumps(entry["lines"])
    from agent_checkpoint.report import render_text, shadow_report
    text = render_text(shadow_report(gw.org.ledger))
    assert "Nothing was paid" in text and "A-2" in text
    from agent_checkpoint.views import activity, audit
    flagged = activity(gw)
    assert any(r["agent_id"] == "payment-run" and r["invoice_number"] == "A-2" for r in flagged)
    assert "don't pay" in audit(gw)["recent"][0]["summary"]


def test_payment_run_names_suffixes_limits_and_columns(site):
    reg, gw, as_, _ = site
    store = gw.org.store
    text = f"Supplier,Num,Amount,Account,Payee account\n\"Northwind Supplies, LLC\",BIG-1,\"20,000.00\",1000,{ACCT}\n"
    rows, errors = read_payment_run(store, text)
    assert errors == [] and rows[0]["vendor_id"] == "V1" and rows[0]["bank_account"] == ACCT
    out = gw.check_run(rows, "approver@acme.com", "hash")
    assert out["rows"][0]["verdict"] == "go"
    assert not any("approval limit" in reason for reason in out["rows"][0]["reasons"])
    # Two vendors that strip to the same name are not silently merged.
    store.upsert_vendor(Vendor("V3", "Northwind Supplies Inc", "US1111222233334444", ("n2.com",), date(2024, 1, 1)))
    ambiguous, errors = read_payment_run(store, "Vendor,Amount\nNorthwind Supplies LLC,100.00\n")
    assert errors == [] and ambiguous[0]["vendor_id"] == "Northwind Supplies LLC"
    bare = map_headers(["Vendor", "Amount", "Account"], ["name", "amount", "bank_account"])
    assert "bank_account" not in bare
    numbered = map_headers(["Vendor", "Num", "Amount"], ["name", "invoice_number", "amount"])
    assert numbered["invoice_number"] == 1


def test_payment_run_over_the_web(site):
    reg, gw, as_, _ = site
    body = RUN.format(acct=ACCT).encode()
    status, out, _ = as_("approver@acme.com").req("POST", "/api/web/payment-run", raw=body, ctype="text/csv")
    assert status == 200 and len(out["rows"]) == 5
    assert ACCT not in json.dumps(out) and "GB00ATTACKER000001" not in json.dumps(out)  # last four only
    assert as_("audit@acme.com").req("POST", "/api/web/payment-run", raw=body, ctype="text/csv")[0] == 403
    assert as_("approver@acme.com").req("POST", "/api/web/payment-run", raw=b"x,y\n1,2\n", ctype="text/csv")[0] == 422
    big = b"Supplier,Amount\n" + b"Contoso,1\n" * 5001
    assert as_("approver@acme.com").req("POST", "/api/web/payment-run", raw=big, ctype="text/csv")[0] == 422


def test_formula_and_script_text_in_a_run_is_only_data(site):
    reg, gw, as_, _ = site
    csv = b'Supplier,Invoice #,Amount\n"=HYPERLINK(""http://evil"")",<script>x</script>,10\n'
    status, out, _ = as_("admin@acme.com").req("POST", "/api/web/payment-run", raw=csv, ctype="text/csv")
    assert status == 200 and out["rows"][0]["verdict"] == "block"


# --- records through the web --------------------------------------------------------------

def test_vendor_add_edit_and_no_bank_edit(site):
    reg, gw, as_, _ = site
    admin = as_("admin@acme.com")
    assert admin.req("POST", "/api/web/vendors", {"vendor_id": "V9", "name": "New Co", "bank_account": "US1234567890",
                                                  "email_domains": "billing@newco.com, newco-pay.com", "phone": "+1"})[0] == 200
    v = gw.org.store.vendor("V9")
    assert v.email_domains == ("newco.com", "newco-pay.com")
    assert admin.req("POST", "/api/web/vendors", {"vendor_id": "V9", "name": "Dup", "bank_account": "US1234567890"})[0] == 409
    assert admin.req("POST", "/api/web/vendors/V9", {"bank_account": "GB00EVIL000001"})[0] == 422
    assert admin.req("POST", "/api/web/vendors/V9", {"phone": "+1 415 555 0199"})[0] == 200
    assert gw.org.store.vendor("V9").bank_account == "US1234567890"
    assert as_("approver@acme.com").req("POST", "/api/web/vendors", {"vendor_id": "V8", "name": "x",
                                                                     "bank_account": "US1234567890"})[0] == 403


def test_bank_change_requested_in_the_app_needs_another_person_and_a_call(site):
    reg, gw, as_, _ = site
    approver = as_("approver@acme.com")
    status, d, _ = approver.req("POST", "/api/web/vendors/V1/bank-change", {"new_account": "US5555000011112222",
                                                                           "note": "Letter dated Nov 10"})
    assert status == 200 and d["verdict"] == "pause" and d["ticket_id"]
    assert approver.req("POST", f"/api/web/tickets/{d['ticket_id']}", {"approve": True, "callback_verified": True})[0] == 403
    admin = as_("admin@acme.com")
    assert admin.req("POST", f"/api/web/tickets/{d['ticket_id']}", {"approve": True})[0] == 422  # no call
    assert admin.req("POST", f"/api/web/tickets/{d['ticket_id']}",
                     {"approve": True, "callback_verified": True, "called_number": "+1 555"})[0] == 200
    assert gw.org.store.vendor("V1").bank_account == "US5555000011112222"
    status, d, _ = approver.req("POST", "/api/web/vendors/V2/bank-change", {"new_account": "US5555000011112222"})
    assert d["verdict"] == "block"  # another vendor's account


def test_purchase_orders(site):
    reg, gw, as_, _ = site
    admin = as_("admin@acme.com")
    assert admin.req("POST", "/api/web/pos", {"number": "PO-77", "vendor_id": "V1", "amount": "4,800.00"})[0] == 200
    assert gw.org.store.po("PO-77").amount_cents == 4_800_00
    assert admin.req("POST", "/api/web/pos", {"number": "PO-77", "vendor_id": "V1", "amount": "1"})[0] == 409
    assert admin.req("POST", "/api/web/pos", {"number": "PO-78", "vendor_id": "NOPE", "amount": "1"})[0] == 422


def test_agents_created_and_removed_in_the_app(site):
    reg, gw, as_, port = site
    admin = as_("admin@acme.com")
    status, r, _ = admin.req("POST", "/api/web/agents", {"agent_id": "claude-ap", "made_by": "Claude",
                                                         "allowed_actions": ["pay"], "max_amount": "5000", "daily_cap": "20000"})
    assert status == 200 and r["key"].startswith("ack_acme_")
    agent = Client("127.0.0.1", port, headers={"Authorization": f"Bearer {r['key']}"})
    assert agent.req("GET", "/v1/vendors?q=north")[0] == 200
    assert admin.req("POST", "/api/web/agents", {"agent_id": "claude-ap", "allowed_actions": ["pay"], "max_amount": "1",
                                                 "daily_cap": "1"})[0] == 409
    for bad in ({"agent_id": "Bad Name!"}, {"agent_id": "x2", "allowed_actions": ["wire_everything"]},
                {"agent_id": "x3", "allowed_actions": ["pay"], "max_amount": "100", "daily_cap": "10"}):
        base = {"allowed_actions": ["pay"], "max_amount": "1", "daily_cap": "1"}
        assert admin.req("POST", "/api/web/agents", {**base, **bad})[0] == 422
    assert admin.req("POST", "/api/web/agents/claude-ap", {"allowed_actions": ["pay"], "max_amount": "100",
                                                           "daily_cap": "200"})[0] == 200
    assert gw.org.policy.agents["claude-ap"].max_amount_cents == 100_00
    assert admin.req("POST", "/api/web/agents/claude-ap/remove", {})[1]["keys_revoked"] == 1
    assert agent.req("GET", "/v1/vendors?q=north")[0] == 401
    assert as_("approver@acme.com").req("POST", "/api/web/agents", {"agent_id": "zz", "allowed_actions": ["pay"],
                                                                    "max_amount": "1", "daily_cap": "1"})[0] == 403


def test_people_managed_in_the_app(site):
    reg, gw, as_, port = site
    admin = as_("admin@acme.com")
    status, r, _ = admin.req("POST", "/api/web/people", {"email": "New.Person@acme.com", "role": "approver"})
    assert status == 200 and len(r["temporary_password"]) >= 12
    assert Client("127.0.0.1", port).login("new.person@acme.com", r["temporary_password"])[0] == 200
    assert "new.person@acme.com" in gw.org.policy.approvers
    assert admin.req("POST", "/api/web/people/new.person%40acme.com/disable", {})[0] == 200
    assert Client("127.0.0.1", port).login("new.person@acme.com", r["temporary_password"])[0] == 401
    assert admin.req("POST", "/api/web/people/admin%40beta.com/disable", {})[0] == 404       # other company
    assert admin.req("POST", "/api/web/people/admin%40acme.com/disable", {})[0] == 422       # yourself
    assert admin.req("POST", "/api/web/people", {"email": "admin@beta.com", "role": "admin"})[0] == 409
    assert admin.req("POST", "/api/web/people", {"email": "x@acme.com", "role": "owner"})[0] == 422
    assert as_("approver@acme.com").req("POST", "/api/web/people", {"email": "y@acme.com", "role": "admin"})[0] == 403


def test_setup_checklist(site):
    reg, gw, as_, _ = site
    s = as_("audit@acme.com").req("GET", "/api/web/setup")[1]
    steps = {x["id"]: x["done"] for x in s["steps"]}
    assert steps["vendors"] and steps["pos"] and steps["people"] and not steps["history"] and not steps["agents"]
    assert any("no phone number" in x["text"] for x in s["health"])  # Contoso has none


def test_history_import_over_the_web(site):
    reg, gw, as_, _ = site
    csv = history_csv(["Northwind Supplies,H-1,100.00,03/04/2026"]).encode()
    out = as_("admin@acme.com").req("POST", "/api/web/import/history?date_order=dmy", raw=csv, ctype="text/csv")[1]
    assert out["imported"] == 1
    assert gw.org.store.payments("V1")[0].on == date(2026, 4, 3)
    assert as_("admin@acme.com").req("POST", "/api/web/import/history?date_order=ymd", raw=csv, ctype="text/csv")[0] == 422
    assert as_("approver@acme.com").req("POST", "/api/web/import/history", raw=csv, ctype="text/csv")[0] == 403


def test_release_and_evidence_over_the_web(site):
    from datetime import UTC, datetime

    from agent_checkpoint.release import check_release, verify
    reg, gw, as_, _ = site
    body = b"Vendor,Invoice,Amount\nNorthwind Supplies,N-1,100.00\nContoso,C-1,50.00\nNobody Ltd,X-1,10.00\n"
    approver = as_("approver@acme.com")
    status, out, _ = approver.req("POST", "/api/web/payment-run", raw=body, ctype="text/csv")
    assert status == 200 and out["pilot"]["not_ready"] == 1
    run_id = out["run_id"]
    assert as_("audit@acme.com").req("POST", f"/api/web/payment-run/{run_id}/release", {})[0] == 403
    assert as_("admin@beta.com").req("POST", f"/api/web/payment-run/{run_id}/release", {})[0] == 404  # other company
    status, doc, _ = approver.req("POST", f"/api/web/payment-run/{run_id}/release", {})
    assert status == 200
    signed = verify(gw.org.signer.public_pem(), doc, "release", datetime.now(UTC))
    assert check_release(signed, body)["release_lines"] == [2, 3]
    assert approver.req("POST", f"/api/web/payment-run/{run_id}/lines/4/outcome", {"outcome": "fraud"})[0] == 200
    assert approver.req("POST", f"/api/web/payment-run/{run_id}/lines/4/outcome", {"outcome": "maybe"})[0] == 422
    assert approver.req("POST", "/api/web/misses", {"amount": "250.00", "note": "wire outside the file"})[0] == 200
    status, ev, _ = as_("audit@acme.com").req("GET", "/api/web/evidence")
    assert status == 200 and ev["held_fraud"] == 1 and ev["misses_recorded"] == 1 and "PUBLIC KEY" in ev["public_key"]
    status, lst, _ = approver.req("POST", "/api/web/allowed-accounts", {})
    assert status == 200 and lst["body"]["version"] == 1 and len(lst["body"]["accounts"]) == 2


def test_po_import_cannot_move_or_raise_an_existing_po(site):
    _, gw, _, _ = site
    from agent_checkpoint.importers import import_pos
    store = gw.org.store
    n, errors = import_pos(store, "PO number,Vendor,Amount\nPO-1,Contoso,50000.00\nPO-1,Northwind Supplies,90000.00\n"
                                  "PO-1,Northwind Supplies,40000.00\nPO-9,Contoso,10.00\n")
    assert len(errors) == 2 and "another vendor" in errors[0] and "go up" in errors[1]
    assert store.po("PO-1").vendor_id == "V1" and store.po("PO-1").amount_cents == 40_000_00
    assert store.po("PO-9").vendor_id == "V2"
    n, errors = import_pos(store, "PO number,Vendor,Amount,Billed\nPO-1,Northwind Supplies,40000.00,1000.00\n")
    assert n == 0 and any("billed" in e for e in errors)
    assert store.po("PO-1").billed_cents == 0


def test_vendor_added_later_without_a_date_is_new(tmp_path):
    from datetime import date as d
    store = Store(str(tmp_path / "b.db"), b"k" * 32)
    import_vendors(store, "name,bank account\nOld Co,US0001112223334\n")
    assert store.vendor("V-OLDCO").created_on == d(2000, 1, 1)  # first load: long-standing vendors
    import_vendors(store, "name,bank account\nNew Co,US0005556667778\n")
    assert store.vendor("V-NEWCO").created_on == d.today()  # added later: new, so new-vendor checks apply
