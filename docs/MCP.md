# The MCP server

The checkpoint gives agents **six tools**. Give an agent these *instead of* direct payment or ERP
write access, and every money-touching action passes through the checkpoint by construction.

| Tool | Does | Notes |
|---|---|---|
| `pay_invoice` | Pay a supplier invoice | No payee field: money goes to the account on file. Report the invoice's printed account in `bank_account_on_invoice` |
| `change_vendor_bank_account` | Change where a vendor is paid | Always needs a human, who must confirm by phone with the number on file |
| `refund_payment` | Refund part or all of an earlier payment | Goes back to where the original payment went |
| `edit_invoice_record` | Change an invoice record | Paid invoices are corrected with a credit, not edited |
| `get_action_status` | Status of an earlier request | Read-only |
| `find_vendor` | Vendor ids, names, last 4 digits of account, known domains | Read-only |

Amounts are decimal strings (`"4800.00"`) because language models are unreliable with integer
cents. They are parsed exactly, and anything ambiguous (`"4,800.001"`) is refused.

## What the agent sees

Results lead with the outcome in capitals, then the reasons, then what to do:

```
BLOCKED. request_id: mcp-6f90...
Findings:
- $48,000.00 is 10x the $4,800.00 left on PO PO-1003: looks like a misplaced decimal
Blocked. Do not retry this action or try to achieve it another way. Tell the person who asked what the checkpoint found.
```

```
PAUSED FOR HUMAN APPROVAL. request_id: mcp-7b9e...
ticket: T-a7d41dbeb288
Findings:
- Invoice lists account ...5555, but the account on file for Northwind Supplies is ...1234. ...
Waiting for human approval (ticket T-a7d41dbeb288). Do not resubmit. Check back later with the request id.
```

Blocked results set `isError: true`, so clients treat them as failures. Every result also carries
`structuredContent` with the full decision.

## Identity and retries

- The agent's identity comes from `CHECKPOINT_AGENT_KEY`, never from the arguments.
- Each call gets a request id derived from its arguments (or `idempotency_key`). An identical
  retry returns the original decision. It never pays twice.

## Local or remote

```bash
# In-process: the MCP server opens the company's folder directly (single machine, demos, pilots)
CHECKPOINT_AGENT_KEY=ack_... agent-checkpoint --home ./checkpoint-data mcp

# Remote: the MCP server holds only the agent key and calls the checkpoint over HTTPS.
# This is the production shape: the agent's machine never has the rail credentials or the books.
CHECKPOINT_AGENT_KEY=ack_... agent-checkpoint mcp --url https://checkpoint.example.com
```

If the remote checkpoint is unreachable, tools answer `REFUSED (503) ... Nothing was done.`:
the agent fails closed, it doesn't fall back to anything.

## Protocol

MCP over stdio, newline-delimited JSON-RPC 2.0. Implements `initialize` (2025-06-18, 2025-03-26,
2024-11-05), `ping`, `tools/list`, `tools/call`, and batches. No SDK dependency. Logs go to
stderr. `tests/test_mcp.py` launches it as a real subprocess.
