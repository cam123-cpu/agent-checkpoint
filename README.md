# Agent Checkpoint

**An independent checkpoint between AI agents and a company's money.**

Before any AI agent pays an invoice, issues a refund, changes a supplier's bank details or edits
a financial record, it has to show the checkpoint **what** it wants to do, **why** (the invoice,
PO, email or ticket) and **who asked**. In about a millisecond the checkpoint checks this against
the company's own books and returns **go**, **pause** (a human approves from their phone) or
**block**. Money moves only with the checkpoint's signed, single-use receipt, and every decision
goes into a tamper-evident log, which is what you show auditors and insurers.

It works with any agent from any vendor. The agent connects over **MCP** (or HTTP) and gets six
tools. None of them lets the agent choose where money goes.

```
  Agents from any vendor              Agent Checkpoint                         Company systems
 ┌──────────────────────┐   MCP   ┌───────────────────────────────┐  receipt  ┌──────────────────┐
 │ AP agent (Claude)    │────────▶│ 19 checks (< 2 ms)             │─────────▶│ Payment rail     │
 │ CRM refund agent     │  HTTP   │ go / pause / block             │          │ (bank, ERP pay)  │
 │ Ops agent            │────────▶│ approvals: phone, 2-person     │          └──────────────────┘
 └──────────────────────┘         │ signed receipts (Ed25519)      │  read    ┌──────────────────┐
                                  │ tamper-evident ledger          │◀─────────│ Vendor master,   │
          approvers ◀── notify ───│ shared fraud network           │          │ POs, payments    │
                                  └───────────────────────────────┘          └──────────────────┘
```

> Sibling project to the Invoice Anomaly Detector: the detector reviews invoices *after* they
> arrive; the checkpoint stops actions *before* they happen. Same habits: pure check functions,
> strictest verdict wins, a noisy-OR risk score, honest evaluation on planted problems.

## Try it in two minutes

```bash
pip install -e ".[dev]"                     # Python 3.11+; one dependency: cryptography
agent-checkpoint simulate --seeds 10        # a quarter of synthetic agent traffic, shadow then enforce
agent-checkpoint demo                       # sandbox company + an agent key + an approver key (enforce mode)
```

Then connect an agent to it. **Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agent-checkpoint": {
      "command": "agent-checkpoint",
      "args": ["--home", "/absolute/path/to/checkpoint-data", "mcp"],
      "env": { "CHECKPOINT_AGENT_KEY": "ack_demo_..." }
    }
  }
}
```

**Claude Code:**

```bash
claude mcp add agent-checkpoint -e CHECKPOINT_AGENT_KEY=ack_demo_... -- agent-checkpoint --home "$PWD/checkpoint-data" mcp
```

Ask it: *"Pay Contoso invoice INV-77 for $4,800 against PO-1001."* Then try $48,000 on PO-1003,
or the same invoice twice, or a bank change "from" `billing@northwind-supp1ies.com`. See
[docs/MCP.md](docs/MCP.md) for the tools and for running the MCP server against a remote checkpoint.

Approve or reject from the command line (a phone app would call the same API):

```bash
agent-checkpoint tickets demo
agent-checkpoint approve demo T-... --as controller@demo.example            # add --callback-verified for bank changes
agent-checkpoint reject  demo T-... --as controller@demo.example --fraud    # reports it to the shared network
```

## The web app

`agent-checkpoint serve` also serves a private web app for the people who approve. It works on
a phone (add it to the home screen) and on a desktop:

- **Approvals.** Each paused request as a hold slip: the amount, why it was paused, the account
  on file against the one on the invoice, the evidence, and Approve / Reject / Report as fraud.
  Bank changes can't be approved until you tick that you phoned the number on file.
- **Overview.** What was checked, sent to a person and stopped, with amounts.
- **Activity.** Every agent action, filterable, with the reasons, and CSV export for auditors.
- **Audit log.** The integrity check and the fingerprint to hand to your auditor.
- **Vendors** and **Settings** (limits, mode, agents, people, CSV import for admins).

```bash
agent-checkpoint add-user acme cfo@acme.com --role admin           # prints a password once
agent-checkpoint serve --tls-cert cert.pem --tls-key key.pem       # or --force-https behind deploy/Caddyfile
agent-checkpoint serve --dev                                       # localhost only, for trying it
```

Sign-in supports **two-step codes** from any authenticator app (with recovery codes; a company can
require it) and **single sign-on** with Microsoft Entra ID, Google Workspace or any OpenID Connect
provider. See [deploy/DEPLOY.md](deploy/DEPLOY.md) for TLS, Cloudflare bot protection and SSO set-up.

A clickable demo with sample data builds with `python scripts/build_demo.py --out dist/demo`.
The web app meets a 20-point pre-launch security checklist (see [SECURITY.md](SECURITY.md)), and
its design rules (no gradients, glass, emoji, icon kits, em dashes, opacity hovers, low contrast)
are enforced by `tests/test_web_rules.py`.

## Results on the simulated quarter

Three months at a synthetic company with eight suppliers and three agents from different
"vendors", plus 12 planted incidents: the $48,000 look-alike-domain bank change and invoice, a
$4,800 invoice read as $48,000, one invoice paid from two inboxes, a split to dodge the approval
limit, an amount 3x the vendor's norm, a **prompt injection** inside a real vendor's invoice, a
look-alike vendor added last week, a CRM agent refunding to a new account, an ops agent editing
a paid invoice, and a payment to a vendor that doesn't exist.

| 10 random seeds | Shadow mode | Enforce mode |
|---|---|---|
| Incidents stopped | 113 / 120 | 113 / 120 |
| Over-limit / bank-change actions sent to a human | 68 / 68 | 68 / 68 |
| Clean actions interrupted | 23 / 536 (4.3%)\* | **1 / 536 (0.2%)** |
| Money lost to incidents | $1,378,500 (it only watches) | $45,900 |
| Slowest decision | < 2 ms | < 2 ms |

\*Mostly side effects of the planted fraud: shadow mode lets the fraudster's bank change through,
so the real supplier's next invoices clash with the poisoned record. That's worth a pause too.

**The 7 misses are honest misses.** Six are the *first* half of a split payment, which looks
normal on its own (the second half is always caught). One is a 3x amount at a vendor whose
history was too noisy that quarter. **Read all of these numbers as an upper bound:** the same
person wrote the incidents and the checks. The real test is shadow mode on a company's own
traffic.

Then a second company joins the network. Two weeks later the same fraudster tries the same bank
account there from a *new* look-alike domain, and it is blocked because the first company marked
it as fraud.

## How it works

| Piece | What it does |
|---|---|
| `models.py` | The request: what, why, who. Validated strictly. Agents can't set the payee, the date or their own identity. Money is integer cents |
| `checks.py` | 19 pure checks. Strictest verdict wins; noisy-OR risk; **fails closed** if a check errors; learning from approvals changes ranking, never verdicts |
| `gateway.py` | `submit` / `resolve`. Shadow vs enforce, tickets, two-person approval, expiry, a **re-check at approval time**, idempotent retries, serialized check-then-execute |
| `receipts.py` · `rails.py` | Ed25519-signed, 10-minute, single-use receipts. The rail pays only what a receipt says, to the account it names. Partners can verify with the public key |
| `ledger.py` | Append-only, hash-chained, HMAC-signed log; publish `head` to make truncation detectable |
| `intel.py` | Shared fraud network: blind-indexed accounts and domains reported by any company |
| `tenancy.py` | One folder and one set of databases per company; keys stored as hashes |
| `server.py` · `mcp_server.py` | HTTP API and MCP server (stdio, local or remote) |
| `simulate.py` | The quarter above, with labels the checkpoint never sees |

### The checks

| Check | Verdict | Catches |
|---|---|---|
| `agent_scope`, `daily_cap`, `burst` | block / pause | Agent outside its licence, spending too fast, or stuck in a loop |
| `provenance`, `currency` | block | No evidence, nobody who asked, wrong currency |
| `unknown_vendor`, `lookalike_vendor`, `new_vendor_large` | block / pause | Fake, hallucinated or look-alike payees |
| `known_fraud` | block | Account or domain reported by any company on the network |
| `lookalike_domain`, `unknown_sender` | block / pause | Invoices and requests from domains that aren't the vendor's |
| `invoice_account_differs` | pause | Invoice prints a different account (redirection, prompt injection). Payment still goes to the account on file |
| `recent_bank_change` | pause | Paying an account changed in the last 14 days |
| `bank_change`, `shared_account` | pause / block | Any bank change needs a phone call to the number on file; another vendor's account is blocked |
| `amount_magnitude`, `po_*`, `no_po` | block / pause | Decimal slips, overruns, wrong or exhausted POs |
| `duplicate_payment`, `duplicate_pending`, `near_duplicate` | block / pause | Same invoice twice (`INV-0042` = `inv 42`), even while the first is awaiting approval |
| `approval_limit`, `split_payment`, `amount_outlier` | pause | Over the limit, split under it, or far from the vendor's own history (robust z-score) |
| `refund_*`, `edit_paid_record` | block | Refunds to new accounts or over the original; editing paid records |

### What "tamper-evident" means here

Triggers refuse UPDATE and DELETE. Every entry chains to the previous one and is HMAC-signed, so a
rewrite fails `verify()` even if someone with file access drops the triggers. Deleting the newest
entries is caught by comparing with a published `head`. Claim **tamper-evident**, not "impossible
to edit".

## Running it for a real pilot

```bash
agent-checkpoint create-org acme --name "Acme Manufacturing"
agent-checkpoint add-agent acme ap-agent --actions pay,change_bank --max 100000 --daily 150000 --vendor "Claude"
agent-checkpoint add-approver acme controller@acme.com
agent-checkpoint import-vendors acme examples/vendors.csv
agent-checkpoint import-pos acme examples/pos.csv
agent-checkpoint serve --port 8077                # behind TLS; agents use HTTP or `mcp --url`
agent-checkpoint report acme --since 2026-11-01   # the shadow-mode report for the CFO
```

Edit `orgs/acme/policy.json` for limits. Add `orgs/acme/notify.json` with `{"webhook_url": ...}`
for Slack or phone push (ntfy). Start in **shadow** mode. Switch with `set-mode acme enforce` once
the report has earned it.

## Not built yet (and what each would take)

- **Live connectors.** QuickBooks/Xero/NetSuite read sync (vendor master, POs) and bill-payment
  write-back. CSV import works today.
- **A real rail.** Implement `Rail.execute` for a bank or ERP payment API. The receipt contract is done.
- **Bank-ownership verification.** Partner with an account-validation provider for "does this
  account belong to this company?"
- **Approver app.** Passkey step-up on approve, and push. The API is there.
- **Encryption at rest** for bank details, **PostgreSQL**, SSO. All already solved in the Invoice
  Anomaly Detector and portable.
- **Bypass through other tools.** An agent that still has *other* payment tools can go around the
  checkpoint. Deployment has to remove them, and receipts make that enforceable at the bank.

See [docs/MARKET.md](docs/MARKET.md) for the market case and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for the design.

## Development

```bash
pip install -e ".[dev]"
pytest -q          # 135 tests: checks, approvals, receipts, ledger tampering, network, MCP (incl. a real stdio process),
                   # HTTP, CLI, quality bar, the security checklist, design rules, and a real browser (if Playwright is installed)
ruff check src tests scripts
```
