"""HTTP API over real company folders: keys, isolation between companies, and the MCP remote backend."""

import json
import threading
import urllib.error
import urllib.request
from dataclasses import replace
from datetime import date

import pytest

from agent_checkpoint.mcp_server import MCPServer, RemoteBackend
from agent_checkpoint.policy import AgentScope
from agent_checkpoint.server import make_server
from agent_checkpoint.store import PurchaseOrder, Vendor
from agent_checkpoint.tenancy import Registry


@pytest.fixture
def env(tmp_path):
    reg = Registry(str(tmp_path))
    keys = {}
    for org in ("acme", "beta"):
        reg.create_org(org, org.title())
        reg.save_policy(org, replace(reg.policy(org), mode="enforce"))
        keys[org] = {"agent": reg.add_agent(org, "ap", AgentScope(("pay",), 100_000_00, 200_000_00)),
                     "approver": reg.add_approver(org, f"cfo@{org}.com")}
        s = reg.gateway(org).org.store
        s.upsert_vendor(Vendor("V1", "Acme Supplies", "US0001", ("acmesupplies.com",), date(2024, 1, 1)))
        s.upsert_po(PurchaseOrder("PO-1", "V1", 500_000_00))
    srv = make_server(reg, port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", keys, reg
    srv.shutdown()


def call(base, method, path, key=None, body=None):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(base + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def pay(rid, amount=4_800_00, inv="INV-1"):
    return {"request_id": rid, "action": "pay", "vendor_id": "V1", "amount_cents": amount, "invoice_number": inv,
            "po_number": "PO-1", "evidence": [{"kind": "invoice", "ref": "x.pdf", "sender": "b@acmesupplies.com"}],
            "instructed_by": {"source": "email", "identity": "b@acmesupplies.com"}}


def test_full_flow_and_isolation(env):
    base, keys, reg = env
    a, b = keys["acme"], keys["beta"]
    assert call(base, "GET", "/health") == (200, {"ok": True})
    assert call(base, "POST", "/v1/actions", "wrong", pay("R1"))[0] == 401
    assert call(base, "POST", "/v1/actions", a["approver"], pay("R1"))[0] == 401   # approver key isn't an agent key
    s, d = call(base, "POST", "/v1/actions", a["agent"], pay("R1", 12_000_00))
    assert s == 200 and d["verdict"] == "pause"
    # Beta's approver can't see or touch Acme's ticket; Beta's agent can't read Acme's request.
    assert call(base, "GET", "/v1/tickets", b["approver"])[1]["tickets"] == []
    assert call(base, "POST", f"/v1/tickets/{d['ticket_id']}", b["approver"], {"approve": True})[0] == 404
    assert call(base, "GET", "/v1/actions/R1", b["agent"])[0] == 404
    assert call(base, "POST", f"/v1/tickets/{d['ticket_id']}", a["agent"], {"approve": True})[0] == 401
    s, t = call(base, "POST", f"/v1/tickets/{d['ticket_id']}", a["approver"], {"approve": True, "note": "ok"})
    assert s == 200 and t["status"] == "approved" and t["execution"] == "executed"
    assert call(base, "GET", "/v1/actions/R1", a["agent"])[1]["status"] == "executed"
    assert call(base, "GET", "/v1/ledger/verify", a["approver"])[1]["ok"]
    assert "BEGIN PUBLIC KEY" in call(base, "GET", "/v1/public-key?org=acme")[1]["public_key"]
    assert call(base, "GET", "/v1/report", a["approver"])[1]["actions_checked"] == 1
    assert len(reg.gateway("beta").org.store.payments()) == 0


def test_bad_bodies(env):
    base, keys, _ = env
    k = keys["acme"]["agent"]
    req = urllib.request.Request(base + "/v1/actions", method="POST", data=b"{not json",
                                 headers={"Authorization": f"Bearer {k}"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 400
    assert call(base, "POST", "/v1/actions", k, {**pay("R1"), "agent_id": "someone-else"})[0] == 422


def test_revoked_key_stops_working(env):
    base, keys, reg = env
    assert reg.revoke(keys["acme"]["agent"])
    assert call(base, "POST", "/v1/actions", keys["acme"]["agent"], pay("R1"))[0] == 401


def test_mcp_remote_backend_over_http(env):
    base, keys, reg = env
    s = MCPServer(RemoteBackend(base, keys["acme"]["agent"]))
    found = s.call("find_vendor", {"query": "acme"})
    assert found["structuredContent"]["vendors"][0]["account_on_file"] == "...0001"
    r = s.call("pay_invoice", {"vendor_id": "V1", "amount": "4800.00", "invoice_number": "INV-1", "po_number": "PO-1",
                               "evidence": [{"kind": "invoice", "ref": "x.pdf", "sender": "b@acmesupplies.com"}],
                               "requested_by": {"source": "email", "identity": "b@acmesupplies.com"}})
    assert r["content"][0]["text"].startswith("DONE")
    rid = r["structuredContent"]["request_id"]
    assert s.call("get_action_status", {"request_id": rid})["structuredContent"]["status"] == "executed"
    down = MCPServer(RemoteBackend("http://127.0.0.1:9", keys["acme"]["agent"]))
    r = down.call("pay_invoice", {"vendor_id": "V1", "amount": "1", "invoice_number": "I", "evidence": [
        {"kind": "invoice", "ref": "x"}], "requested_by": {"source": "human", "identity": "x"}})
    assert r["isError"] and "unreachable" in r["content"][0]["text"] and "Nothing was done" in r["content"][0]["text"]
