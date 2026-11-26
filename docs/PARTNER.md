# For a bank or payment system: checking a release

This is the page to hand to whoever releases a company's payments: a bank's payments team,
Bill.com, Ramp, an ERP's payment module. It describes two signed documents the company's checkpoint
produces, and the checks that make them a control instead of a report.

Nothing here works by itself. A release is a control on the day your system refuses a payment file
that doesn't have one. Until then it is a record.

## What you receive

Both documents are JSON:

```json
{ "kind": "release" | "allowed_accounts", "body": { ... }, "sig": "<base64 Ed25519>", "sha256": "<hex of body>" }
```

The signature is Ed25519 over a context string followed by the canonical body (keys sorted, no
whitespace: `json.dumps(body, sort_keys=True, separators=(",", ":"))`):

| kind | context (bytes, including the newline) |
|---|---|
| `release` | `agent-checkpoint release v1\n` |
| `allowed_accounts` | `agent-checkpoint allowed-accounts v1\n` |

The context means one kind can never be passed off as another, or as an execution receipt.

Get the company's public key once, out of band (`agent-checkpoint public-key ORG`, or the Audit log page
in the web app), and pin it. Don't take a key that arrives with a document.

### Release

Issued by an approver after a payment file was checked. Fields that matter:

| field | meaning |
|---|---|
| `release_id` | single use: refuse one you have seen before |
| `file_sha256` | SHA-256 of the file that was checked (UTF-8, without a byte-order mark) |
| `release` | lines that may go: `line`, `vendor_id`, `invoice_number`, `amount_cents`, `account_tag`, `account_last4` |
| `hold` | line numbers that must not go in this file |
| `expires_at` | refuse after this (24 hours by default) |
| `salt` | for account tags, below |

### Allowed accounts

The company's list of accounts currently on file. `confirmed_by_call` is true only when that account was
set by a bank change a second person approved after the number on file was recorded. An import, including
the first load, and a vendor an admin adds, are on the list with `confirmed_by_call` false. Refuse those
after go-live if your agreement says every destination must have been confirmed by a call. `version` only
goes up. Keep the highest version you have seen and refuse older ones. The list expires (7 days by
default), so a company that stops issuing it stops being able to pay.

### Account tags

`account_tag = sha256(salt + ":" + normalised_account)`, hex. The account is normalised by keeping
only letters and digits and upper-casing them. Tags keep account numbers out of email and tickets. Account numbers
are short, so a tag can be guessed by someone who tries hard: treat the documents as confidential to you
and the company.

## The checks, in order

For a payment file:

1. The signature verifies with the pinned key, and `kind` is `release`.
2. `expires_at` has not passed.
3. `release_id` has not been used. Record it.
4. The SHA-256 of the file you are about to process equals `file_sha256`.
5. Send only the lines in `release`. For each payment you will actually send, the amount equals the line's
   `amount_cents` and the tag of the destination account equals its `account_tag`. Each released line
   matches at most one payment.
6. Anything else is held: lines in `hold`, and any payment that matched nothing.

For any payment, file or not, against the allowed-accounts list:

1. The signature verifies, `kind` is `allowed_accounts`, it hasn't expired, and `version` is at least the
   newest you have seen.
2. The destination account's tag is on the list, for that vendor if you know the vendor.

## Running the checks without writing code

The open-source package includes a verifier that needs only the public key. It doesn't need the
company's data:

```bash
pip install "git+https://github.com/cam123-cpu/agent-checkpoint"
agent-checkpoint verify-release release.json --public-key acme.pem --file payments.csv --used used-releases.txt
agent-checkpoint verify-release release.json --public-key acme.pem --instructions outgoing.csv
agent-checkpoint verify-release allowed.json --public-key acme.pem --instructions outgoing.csv --min-version 12
```

`outgoing.csv` is what you are about to send, with the columns `amount` and `account`, and optionally
`vendor_id`. The exit code is 0 only if everything may go. The output lists the lines to release and the
lines to hold, or `REFUSE:` and the reason.

The same checks are a few lines in any language with Ed25519 and SHA-256. They are in
`src/agent_checkpoint/release.py` (`verify`, `check_release`, `check_allowed`).

## What we would ask of a partner

- Refuse a payment file from this company that has no valid release, or release only its listed lines.
- Or, simpler: refuse any payment from this company to an account that isn't on its latest allowed list.
- Tell the company when you refuse something, so the held line is worked, not silently dropped.

## What this does not cover

- That an account belongs to the vendor. That is an account-ownership check, a separate service.
- Payments the company sends through a channel you don't check.
- A company whose approvers approve fraud. The record shows who did.
