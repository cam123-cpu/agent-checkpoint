"""The command line, start to finish."""

import json

from agent_checkpoint.cli import main


def test_onboarding_flow(tmp_path, capsys):
    h = ["--home", str(tmp_path)]
    assert main(h + ["create-org", "acme", "--name", "Acme"]) == 0
    assert main(h + ["add-agent", "acme", "ap", "--actions", "pay,change_bank", "--max", "100000",
                     "--daily", "150000"]) == 0
    agent_key = capsys.readouterr().out.strip().splitlines()[-1]
    assert agent_key.startswith("ack_acme_")
    assert main(h + ["add-approver", "acme", "cfo@acme.com"]) == 0
    (tmp_path / "v.csv").write_text("vendor_id,name,bank_account,email_domains,created_on,phone\n"
                                    "V1,Acme Supplies,US0001,acmesupplies.com,2024-01-01,+1 555\n"
                                    ",missing,,,,\n")
    (tmp_path / "p.csv").write_text("number,vendor_id,amount\nPO-1,V1,\"4,800.00\"\nPO-2,V9,10\n")
    assert main(h + ["import-vendors", "acme", str(tmp_path / "v.csv")]) == 1   # one bad row reported
    assert main(h + ["import-pos", "acme", str(tmp_path / "p.csv")]) == 1
    err = capsys.readouterr().err
    assert "line 3" in err and "unknown vendor V9" in err
    assert main(h + ["set-mode", "acme", "enforce"]) == 0

    from agent_checkpoint.tenancy import Registry
    reg = Registry(str(tmp_path))
    gw = reg.gateway("acme")
    assert gw.org.store.po("PO-1").amount_cents == 4_800_00
    who = reg.lookup(agent_key)
    d = gw.submit({"request_id": "R1", "action": "pay", "vendor_id": "V1", "amount": "12000", "invoice_number": "I1",
                   "evidence": [{"kind": "invoice", "ref": "i.pdf"}],
                   "instructed_by": {"source": "human", "identity": "x@acme.com"}}, agent_id=who["name"])
    capsys.readouterr()
    assert main(h + ["tickets", "acme"]) == 0
    assert d.ticket_id in capsys.readouterr().out
    assert main(h + ["approve", "acme", d.ticket_id, "--as", "cfo@acme.com"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "approved"
    assert main(h + ["verify", "acme"]) == 0
    assert capsys.readouterr().out.startswith("OK")
    assert main(h + ["report", "acme", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["actions_checked"] == 1
    assert main(h + ["approve", "acme", d.ticket_id, "--as", "nobody@x.com"]) == 2


def test_policy_file_is_validated(tmp_path):
    h = ["--home", str(tmp_path)]
    main(h + ["create-org", "acme", "--name", "Acme"])
    p = tmp_path / "orgs" / "acme" / "policy.json"
    p.write_text(p.read_text().replace('"mode": "shadow"', '"mode": "yolo"'))
    assert main(h + ["verify", "acme"]) == 2
