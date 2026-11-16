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

## What makes it venture-scale (all four, not one)

1. **Own the path money takes.** Signed receipts the rail requires ("no receipt, no money"). An
   optional control is a feature; a required one is infrastructure.
2. **Independence.** One referee across Salesforce, Microsoft and startup agents.
3. **The fraud network.** A fraud account or domain seen at one customer is blocked at all of
   them. This is the data moat; it compounds with every customer and is the one thing a
   single-company tool can't copy.
4. **Become the evidence standard.** The ledger becomes what auditors and insurers ask for:
   premium discounts for checkpoint users would turn insurers into distribution.

Then expand by action type: invoices → refunds → payroll changes → procurement → treasury.

## Risks

- **Timing.** Autonomous agents in mid-size AP are early. Shadow mode helps: it sells value
  before enforcement, and also works on today's RPA and AP-automation traffic.
- **Squeeze.** Banks and spend platforms keep building guardrails in; horizontal security adds
  finance.
- **Bypass.** If deployments leave agents other payment paths, the checkpoint is advisory.
  Receipts plus rail and bank partnerships are the answer, and the hardest go-to-market work.
- **Base rates.** Most well-funded startups in hot categories don't reach $1B.

## The first 90 days

- 3–5 design partners in shadow mode on real AP traffic (agents, RPA or humans).
- One real near-miss caught, written up with the customer's permission.
- One rail integration (an ERP bill-payment API) enforcing receipts.
- One conversation with a crime and cyber insurer about premium credit.

## Sources

- FBI IC3 2025 Internet Crime Report, via [dmarcian](https://dmarcian.com/fbi-internet-crime-report-2025/) and [Techlicious](https://www.techlicious.com/blog/fbi-online-scam-losses-2025/)
- [Meow: customer-configured control plane](https://www.meow.com/blog/customer-configured-control-plane-on-meow) · [Ramp: agentic payments](https://ramp.com/blog/agentic-payments)
- [Eftsure: preventing mistaken B2B transfers](https://www.eftsure.com/blog/processes/how-to-prevent-mistaken-b2b-bank-transfers/) · [Trustpair–Coupa](https://www.fintechfutures.com/press-releases/trustpair-and-coupa-expand-partnership-to-help-enterprises-prevent-ai-driven-vendor-payment-fraud)
- [Straiker $64M Series A](https://thenextweb.com/news/straiker-64m-series-a-agentic-security) · [Hush $30M](https://www.securityweek.com/hush-security-raises-30-million-for-ai-agent-governance/amp/) · [Geordie $30M](https://www.balderton.com/news/geordie-raises-30m-to-help-enterprises-securely-adopt-agentic-ai-at-scale/) · [WhiteMatter $20M](https://letsdatascience.com/news/whitematter-raises-20-million-series-a-for-ai-agent-security-47e2b339)
