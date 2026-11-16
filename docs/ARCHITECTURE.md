# Architecture

## The one idea

Agents don't get payment tools. They get a request form. The checkpoint decides, and only the
checkpoint can make money move, because the rail executes only with its signed receipt.

```mermaid
sequenceDiagram
    participant A as Agent (any vendor)
    participant M as MCP server (agent key only)
    participant G as Gateway
    participant C as 20 checks
    participant H as Approver (phone)
    participant R as Rail (bank / ERP)
    participant L as Ledger
    A->>M: pay_invoice(vendor, amount, invoice, evidence, requested_by)
    M->>G: POST /v1/actions (Bearer agent key)
    G->>G: identity from key, date from clock, lock books (BEGIN IMMEDIATE)
    G->>C: evaluate(request, company records, network)
    C-->>G: verdict + findings + risk
    G->>L: decision (request, verdict, reasons)
    alt go (enforce)
        G->>R: Ed25519 receipt: payee from vendor master, amount, 10-min expiry
        R->>R: verify signature, expiry, single use, contents match
        G->>L: executed (transfer id)
    else pause
        G->>H: "Agent wants to pay $48,000 to X. Bank account changed 2 days ago. Approve?"
        H->>G: approve (2 people above the dual limit; phone callback for bank changes)
        G->>C: re-check: anything new that blocks?
        G->>R: receipt → transfer
        G->>L: human_decision, executed
    else block
        G->>L: blocked
        H-->>G: optional: report fraud → shared network
    end
    G-->>M: decision + next step
    M-->>A: "BLOCKED. ... Do not retry."
```

## Decisions and why

| Decision | Why |
|---|---|
| Payee always from the vendor master | Removes the whole class of "agent was talked into a new account". The agent can only *report* what the invoice says |
| Agent identity from its key; date from the checkpoint's clock | An agent can't impersonate another agent or backdate past the "recent bank change" window |
| Check-then-execute inside one `BEGIN IMMEDIATE` | Two copies of an invoice at the same instant, even from two processes, are checked in turn. Tested with 8 threads |
| Re-check when the last approval arrives | Tickets wait hours; the world changes. Something that now blocks wins |
| Fail closed everywhere | A check that errors blocks; unanswered tickets expire; an unreachable checkpoint means "nothing was done" |
| Learning changes ranking only | Approvers' decisions re-weight the queue (Laplace-smoothed, as in the detector) but can never turn a pause into a go. Feedback can't train the control away |
| Ed25519 receipts, public key published | Third parties (bank, ERP, auditor) can verify without being able to forge. This is how "no receipt, no money" gets enforced outside our code |
| One folder and DB per company | Isolation that doesn't depend on remembering a `WHERE org_id = ?` |
| Network stores only HMAC of accounts | Companies share what's been seen, not anyone's bank details |
| Shadow mode runs the same checks | The report a CFO sees in week 3 is exactly what enforcement would have done |

## Data

Per company (`orgs/<id>/books.db`): `vendors`, `pos`, `payments` (via `rail` or `observed`),
`tickets` (approvals, expiry, fraud flag), `transfers` (one row per receipt, unique), `activity`
(for loop detection). `ledger.db`: append-only, chained, signed entries of kind `decision`,
`human_decision`, `executed`, `execution_failed`, `rejected`, `fraud_report`.

Shared (`network/intel.db`): `reports(kind, value, org_id)`, where `value` is a blind index for
accounts and the domain itself for domains.

## Performance

Decisions take well under 2 ms on the simulated company (SQLite, one process). The costliest
checks are the vendor-history ones (outlier, split), which are linear in that vendor's payments.
At scale: index payments by (vendor, date), cache per-vendor statistics, and move to PostgreSQL
with the detector's row-level security.
