"""The MCP server: protocol, tool mapping, and a real subprocess the way a client launches it."""

import json
import os
import subprocess
import sys

import pytest
from conftest import ACCT

from agent_checkpoint.mcp_server import TOOLS, MCPServer, describe, to_action


class Direct:
    """Backend straight onto a sandbox gateway."""

    def __init__(self, gw, agent="ap"):
        self.gw, self.agent = gw, agent

    def submit(self, action):
        return self.gw.submit(action, agent_id=self.agent).to_dict()

    def status(self, rid):
        return self.gw.status(rid, self.agent)

    def find_vendor(self, q):
        from agent_checkpoint.mcp_server import _vendor_rows
        return _vendor_rows(self.gw.org.store.vendors(), q)


EV = [{"kind": "invoice", "ref": "inv.pdf", "sender": "billing@acmesupplies.com"}]
WHO = {"source": "email", "identity": "billing@acmesupplies.com"}


def rpc(server, method, params=None, mid=1):
    return server.handle({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})


def test_initialize_and_list(gw):
    s = MCPServer(Direct(gw))
    r = rpc(s, "initialize", {"protocolVersion": "2025-03-26"})["result"]
    assert r["protocolVersion"] == "2025-03-26" and r["capabilities"] == {"tools": {"listChanged": False}}
    assert "only way to pay" in r["instructions"]
    assert rpc(s, "initialize", {"protocolVersion": "1999-01-01"})["result"]["protocolVersion"] == "2025-06-18"
    names = [t["name"] for t in rpc(s, "tools/list")["result"]["tools"]]
    assert names == ["pay_invoice", "change_vendor_bank_account", "refund_payment", "edit_invoice_record",
                     "get_action_status", "find_vendor"]
    assert s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert rpc(s, "nope")["error"]["code"] == -32601
    assert s.handle({"id": 1})["error"]["code"] == -32600


def test_schemas_never_offer_a_payee_account():
    pay_schema = next(t for t in TOOLS if t["name"] == "pay_invoice")["inputSchema"]
    assert "bank_account" not in pay_schema["properties"] and pay_schema["additionalProperties"] is False


def test_pay_through_mcp(gw):
    s = MCPServer(Direct(gw))
    args = {"vendor_id": "V1", "amount": "4800.00", "invoice_number": "INV-1", "po_number": "PO-1",
            "evidence": EV, "requested_by": WHO}
    r = rpc(s, "tools/call", {"name": "pay_invoice", "arguments": args})["result"]
    assert not r["isError"] and r["content"][0]["text"].startswith("DONE")
    again = rpc(s, "tools/call", {"name": "pay_invoice", "arguments": args})["result"]
    assert again["structuredContent"]["replayed"] and len(gw.org.store.payments()) == 1
    assert gw.org.store.payments()[0].bank_account == ACCT


def test_blocked_and_paused_results_tell_the_agent_what_to_do(gw):
    s = MCPServer(Direct(gw))
    r = rpc(s, "tools/call", {"name": "pay_invoice", "arguments": {
        "vendor_id": "V1", "amount": "48000", "invoice_number": "X", "po_number": "PO-1", "evidence": EV,
        "requested_by": WHO}})["result"]
    assert r["isError"] and r["content"][0]["text"].startswith("BLOCKED") and "Do not retry" in r["content"][0]["text"]
    r = rpc(s, "tools/call", {"name": "pay_invoice", "arguments": {
        "vendor_id": "V1", "amount": "12000", "invoice_number": "Y", "po_number": "PO-BIG", "evidence": EV,
        "requested_by": WHO}})["result"]
    text = r["content"][0]["text"]
    assert text.startswith("PAUSED") and "Do not resubmit" in text
    rid = r["structuredContent"]["request_id"]
    gw.resolve(r["structuredContent"]["ticket_id"], "cfo@acme.com", False)
    st = rpc(s, "tools/call", {"name": "get_action_status", "arguments": {"request_id": rid}})["result"]
    assert "BLOCKED (rejected)" in st["content"][0]["text"]


@pytest.mark.parametrize("args", [
    {"vendor_id": "V1", "amount": "4800", "invoice_number": "I", "evidence": EV, "requested_by": WHO,
     "bank_account": "GB00EVIL"},
    {"vendor_id": "V1", "amount": "$4,800.001", "invoice_number": "I", "evidence": EV, "requested_by": WHO},
])
def test_bad_arguments_refused(gw, args):
    r = rpc(MCPServer(Direct(gw)), "tools/call", {"name": "pay_invoice", "arguments": args})["result"]
    assert r["isError"] and r["content"][0]["text"].startswith("REFUSED")
    assert gw.org.store.payments() == []


def test_to_action_mapping():
    a = to_action("change_vendor_bank_account", {"vendor_id": "V1", "new_bank_account": "X", "evidence": EV,
                                                 "requested_by": WHO})
    assert a["action"] == "change_bank" and a["bank_account"] == "X" and a["request_id"].startswith("mcp-")
    assert to_action("refund_payment", {"vendor_id": "V", "invoice_number": "I", "amount": "1", "evidence": EV,
                                        "requested_by": WHO, "idempotency_key": "k1"})["request_id"] == "k1"


def test_describe_shadow_hides_nothing_dangerous():
    d = {"request_id": "r", "returned": "go", "status": "observed", "mode": "shadow", "verdict": "block",
         "findings": [{"message": "x"}], "next_step": "Allowed (shadow mode: recorded only)."}
    assert describe(d).startswith("ALLOWED") and "x" not in describe(d)


def test_real_subprocess_over_stdio(tmp_path):
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
    demo = subprocess.run([sys.executable, "-m", "agent_checkpoint.cli", "--home", str(tmp_path), "demo"],
                          capture_output=True, text=True, env=env, check=True)
    key = json.loads(demo.stdout)["agent_key"]
    p = subprocess.Popen([sys.executable, "-m", "agent_checkpoint.cli", "--home", str(tmp_path), "mcp"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         env={**env, "CHECKPOINT_AGENT_KEY": key})
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "pay_invoice", "arguments": {
            "vendor_id": "V-CONTO", "amount": "4800.00", "invoice_number": "INV-77", "po_number": "PO-1001",
            "evidence": [{"kind": "invoice", "ref": "a.pdf", "sender": "billing@contoso.com"}],
            "requested_by": {"source": "email", "identity": "billing@contoso.com"}}}},
    ]
    out, _ = p.communicate("\n".join(json.dumps(m) for m in msgs) + "\n", timeout=20)
    replies = [json.loads(line) for line in out.splitlines()]
    assert [r["id"] for r in replies] == [1, 2]
    assert replies[1]["result"]["content"][0]["text"].startswith("DONE")


def test_bad_key_refused(tmp_path):
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"),
               CHECKPOINT_AGENT_KEY="ack_nope")
    subprocess.run([sys.executable, "-m", "agent_checkpoint.cli", "--home", str(tmp_path), "demo"],
                   capture_output=True, env=env, check=True)
    p = subprocess.run([sys.executable, "-m", "agent_checkpoint.cli", "--home", str(tmp_path), "mcp"],
                       input="", capture_output=True, text=True, env=env, timeout=20)
    assert p.returncode != 0 and "not a valid agent key" in p.stderr
