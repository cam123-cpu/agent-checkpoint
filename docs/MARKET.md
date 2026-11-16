# The market case (November 2026)

A working memo, not a pitch deck. It sets out what makes this venture-scale, and what could make
it merely a feature.

## The problem is already expensive, and agents remove the last human check

- The FBI's 2025 Internet Crime Report (published April 2026) puts business email compromise
  (the "we've changed banks" scam) at about $3.05B in reported US losses across roughly 25,000
  complaints. Wire transfers are central to these cases. Reported losses are a floor.
- Agents are moving from demos into production payments. Most guardrails sit inside each platform
  (Ramp, Meow, Razorpay), and some of those platforms argue publicly that model-layer guardrails
  don't hold.

## Why now, and why independent

Companies won't run one agent; they'll run several, from different vendors. A platform's own
guardrails cover only its own agent, and a vendor can't credibly certify its own agent's payouts.
An independent checkpoint that every agent must pass, with a log the company and its auditors
trust, is a new layer.

## Who's around us

| Group | Examples | Overlap | Our angle |
|---|---|---|---|
| Vendor bank verification | Eftsure, Trustpair | Bank-change fraud, account ownership | They verify accounts; we gate **agent actions** and record who asked. Partner for ownership checks |
| Spend platforms and banks with agent guardrails | Ramp, Meow | Limits, approvals for *their* agents | Independence across agents and vendors |
| Horizontal agent security | Straiker ($64M A), Hush ($30M A), Geordie ($30M A), WhiteMatter ($20M A) | Runtime control of agent actions | Sold to CISOs and broad; we are finance-specific (CFO budget, auditor and insurer evidence, accounting checks) |
| AP automation | Bill.com, Coupa, AppZen, Vic.ai | Invoice workflows | They automate AP; we verify whoever, or whatever, does it |

The strength of agent-security funding shows investors believe in the layer. It also means
horizontal players could add a finance module. Speed and depth in finance are the defence.

## What it takes to be more than a control company

A solid control company is a real business and a plausible acquisition. It is not a billion-dollar
company. Business-email-compromise losses run to billions a year, but the budget that gets spent sits
with the bank that releases the file, the system that already pays the bill, and the insurer that
covers the theft. An optional second opinion on a spreadsheet reaches a few thousand controllers.

There is one shape in which this is venture-scale: **something that already moves the money will not
release a payment unless the checkpoint's record says the account is allowed.** A receipt that only our
own software checks does not get there. The gates, in order, with what in the product serves each:

| Gate | Pass if | Stop if | In the product |
|---|---|---|---|
| 1. One real file | A controller lets us check one ordinary payment file, and they work the queue | More than about 15% of ordinary lines held and they won't work it | `check-run`; the hold rate on every run and in the audit log; `docs/PILOT.md` |
| 2. Five paying controllers | Five who already pay through Bill.com, Ramp or their bank pay for the file check | None will | Priced as the locked allowed-accounts list plus the weekly file check, not as an agent product. `usage` meters files checked and lines released |
| 3. One partner in the path | One bank or accounting system rejects a file with no release from us. Ask five; silence is a no for a year | Silence | Signed releases and allowed-accounts lists, an offline verifier, `docs/PARTNER.md`. Until this is a yes, don't describe a path to a unicorn |
| 4. Charge for the path | A fee per payment file, or a small fee on payments released, across that partner's book | One regional bank stays one regional bank | `usage` is the meter. The second path is a cyber insurer that requires the control, which needs a miss rate from real files: `evidence`, `mark-line`, `report-miss` |
| 5. The shared list | Many companies already on the path | One report blocks everyone; key beside the data; no undo | One outside report pauses, two block; free-mail never listed; hashed domains; withdrawal; keys apart from the data (`move-keys`, `doctor`) |

Most companies that try this stop at gate 2 and get bought, or stay a small product. The ones that
reach a billion dollars are the ones a bank or an insurer cannot route around. That outcome is
uncommon, and it is the only one in which this idea is a unicorn.

What stays unbuilt until a gate asks for it: live QuickBooks, Xero or NetSuite; a real bank rail (and
not before the books commit before any outside call); account-ownership checks; passkeys; PostgreSQL;
SCIM; an enforce switch for a pilot; an outside pen test before anyone's money depends on enforce mode;
an insurer meeting before there is one real line to show; and any pitch that another customer's fraud
report will block anything.

Then expand by action type: invoices → refunds → payroll changes → procurement → treasury.

## Risks

- **Timing.** Autonomous agents in mid-size AP are early. Shadow mode helps: it sells value
  before enforcement, and also works on today's RPA and AP-automation traffic.
- **Squeeze.** Banks and spend platforms keep building guardrails in; horizontal security adds
  finance.
- **Bypass.** Until a partner refuses payments without a release, the checkpoint is advisory, whatever
  the receipts say. Gate 3 is the hardest go-to-market work and the one that decides the outcome.
- **The network is one file.** Fraud reports live in `network/intel.db` on a single installation.
  Two customers on two servers do not see each other's reports until someone operates that as a
  shared service. It only becomes worth anything after many companies are on the path (gate 5).
- **Base rates.** Most well-funded startups in hot categories don't reach $1B.

## The first 90 days

- Gate 1: one real payment file, with the controller's permission, in shadow. Write down the hold rate.
- Gate 2: five controllers asked to pay for the file check. Count the yeses.
- Gate 3: five banks or payment systems asked whether they would refuse a file without a release. Count
  the yeses; silence counts as no.
- Nothing else until those numbers exist.

## Sources

- FBI IC3 2025 Internet Crime Report, via [dmarcian](https://dmarcian.com/fbi-internet-crime-report-2025/) and [Techlicious](https://www.techlicious.com/blog/fbi-online-scam-losses-2025/)
- [Meow: customer-configured control plane](https://www.meow.com/blog/customer-configured-control-plane-on-meow) · [Ramp: agentic payments](https://ramp.com/blog/agentic-payments)
- [Eftsure: preventing mistaken B2B transfers](https://www.eftsure.com/blog/processes/how-to-prevent-mistaken-b2b-bank-transfers/) · [Trustpair–Coupa](https://www.fintechfutures.com/press-releases/trustpair-and-coupa-expand-partnership-to-help-enterprises-prevent-ai-driven-vendor-payment-fraud)
- [Straiker $64M Series A](https://thenextweb.com/news/straiker-64m-series-a-agentic-security) · [Hush $30M](https://www.securityweek.com/hush-security-raises-30-million-for-ai-agent-governance/amp/) · [Geordie $30M](https://www.balderton.com/news/geordie-raises-30m-to-help-enterprises-securely-adopt-agentic-ai-at-scale/) · [WhiteMatter $20M](https://letsdatascience.com/news/whitematter-raises-20-million-series-a-for-ai-agent-security-47e2b339)
