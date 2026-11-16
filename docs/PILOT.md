# The first pilot: one controller, one real payment file

This is gate 1 of [MARKET.md](MARKET.md). It answers one question: do the checks fit a real company's
books well enough that a controller will work the queue? Nothing else matters until that answer is yes.

## Rules for the whole pilot

- **Stay in shadow.** Leave `mode` as `shadow` in `policy.json`. Do not run `set-mode enforce`.
- **Do not connect an agent.** This pilot is the payment file only.
- **Nothing gets paid** by this software. It reads a file and says what it would hold.
- **Do not take the bank file over personal email.** Use the company's own file share, or the web app
  over HTTPS. If the site is not on HTTPS yet, send the note anyway and hold the file until it is.
- **Secrets apart from the data.** Set `AGENT_CHECKPOINT_KEYS` to a folder outside the data folder
  before creating the company. `agent-checkpoint doctor` should say so.

## Monday

1. Install, in shadow:
   ```bash
   export AGENT_CHECKPOINT_KEYS=/secure/checkpoint-keys
   agent-checkpoint create-org acme --name "Acme Manufacturing"
   agent-checkpoint doctor
   ```
2. Set their dollar limits and currency in `orgs/acme/policy.json` (`currency`,
   `approval_limit_cents`, `dual_approval_cents`, `require_po_above_cents`). Leave `mode` as `shadow`.
3. Import what they already have: the vendor list (with phone numbers: bank changes are confirmed by
   calling the number on file), open purchase orders, and the last 6 to 12 months of payments.
   ```bash
   agent-checkpoint import-vendors acme vendors.csv
   agent-checkpoint import-pos acme pos.csv
   agent-checkpoint import-history acme payments.csv --date-order mdy
   ```
4. Email the controller.

   > **Subject:** I will check this week's payment file before you release it. Nothing gets paid.
   >
   > Send me the file you're about to release this week, the same export you'd upload to the bank. I'll
   > run it against your vendor list and past payments and send back, for each line: ready, review
   > first, or don't pay, with the reason. Nothing is paid or changed, and you release the file as you
   > normally would. It takes about ten minutes of your time to look at the lines I flag.

## When the file arrives

```bash
agent-checkpoint check-run acme thursday.csv --as you@yourcompany.com
```

or upload it on the Payment run page. Then:

1. **Write down how many lines were not Ready, and the share.** It is printed at the bottom and shown
   on the page, and it's recorded in the audit log. **If that is more than about 15%, the wedge failed:**
   the checks don't match these books, and nothing downstream matters until that is fixed. This number
   replaces the 0.2% from the simulation, which came from data we generated ourselves.
2. Go through every held line with the controller. Record what each one really was:
   ```bash
   agent-checkpoint mark-line acme RUN-ID 7 fine  --as you@yourcompany.com --note "instalment, agreed"
   agent-checkpoint mark-line acme RUN-ID 12 error --as you@yourcompany.com --note "duplicate of INV-4410"
   ```
   If they won't work the queue, write that down too. That's the answer.
3. Ask whether anything was paid in the last quarter that shouldn't have been. If so, and it would have
   been in a file like this one, record it as a miss:
   `agent-checkpoint report-miss acme 12000.00 --as you@yourcompany.com --note "..."`.

## What real files punish

Simulated data is kind. Real files are not, and these are the things that cause false holds:

| In real files | What the checker does |
|---|---|
| Vendor names that differ from the vendor list ("Contoso Packaging, LLC") | Matches without suffixes like LLC and Inc; holds only if no vendor matches |
| A column called "Account" that is the general-ledger account | Not read as the bank account |
| No currency column | The file is in the company's currency |
| A currency column with another currency | Held, never converted |
| An invoice paid in parts | The same number for a different amount: review. For the same amount: don't pay |
| No invoice number | Review: a duplicate can't be caught |
| Many small bills to one vendor in a week | Not a split. Only parts that are each a large share of the limit are |
| Lines over the approval limit | Not held for that alone in a file someone is already releasing |

When a hold is wrong, fix the rule (with a test that uses the shape of their file, never their data), not
the controller's file.

## Before any refund or agent exists

- The refund account is bound on the ticket: if the original payment's account changes before approval,
  it isn't paid.
- When the last person approves, a fresh check runs. A new block stops it. A new pause sends it back for
  approval with the reason. It is never paid on a check that only paused.

## Leave unbuilt this month

Live QuickBooks, Xero or NetSuite. A real bank rail. Account-ownership checks. Passkeys. PostgreSQL. SCIM.
A second process. An enforce switch. A pitch that another customer's fraud report will block anything.
An insurer meeting before there is one real line to show. An outside pen test before their money depends
on enforce mode.

## What to say, and what not to

Say: "It checks the file before you release it, and keeps a record you can show your auditor."

Do not claim, anywhere in the product, on a site or in an email, that the bank will refuse payments that
lack this software's receipt. That is only true once a bank or payment system checks releases
([PARTNER.md](PARTNER.md)), and none does yet. `tests/test_web_rules.py` fails the build if that claim
appears in the app or the docs.
