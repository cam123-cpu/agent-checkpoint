# Working on Agent Checkpoint (for AI agents and people)

This code decides whether money moves. Read this before changing anything.

## Workflow

1. **Work on a branch and open a pull request.** Never push to `main`. CI must be green on Linux and
   macOS before merge, and one reviewer (person or agent) who didn't write the change approves it.
2. **One concern per pull request**, with a description of *what changed, why, and what you tested*.
   Fill in the pull request template.
3. Before pushing, run:
   ```bash
   pip install -e ".[dev]"
   ruff check src tests scripts
   pytest -q                              # everything, incl. the 30 pen-test attacks
   agent-checkpoint simulate --seeds 10   # detection quality must not get worse
   ```
4. **Report the simulation numbers** in the pull request if you touched `checks.py`, `gateway.py`,
   `importers.py` or `simulate.py`. Baseline (enforce mode, 10 seeds): 113/120 incidents stopped,
   1/536 clean actions interrupted (0.2%), 68/68 holds paused.

## Invariants: never weaken these (each is guarded by a test)

| Rule | Guarded by |
|---|---|
| Agents never choose the payee: payments go to the vendor-master account | `test_schemas_never_offer_a_payee_account`, `test_PT18_*` |
| Agent identity and the date come from the checkpoint, not the request | `test_malformed_requests_refused_and_logged`, `test_PT18_*` |
| A paused payment is re-checked at approval; payee changes since the pause block it | `test_recheck_at_approval_catches_what_changed`, `test_PT15_*` |
| A refund's destination is bound to its ticket; a new pause at final approval sends it back, never pays | `test_refund_destination_is_bound_to_the_ticket`, `test_a_new_pause_reopens_the_ticket_instead_of_paying` |
| Imports never change an existing vendor's bank account | `test_PT16_*`, `test_vendor_add_edit_and_no_bank_edit` |
| Bank changes need a *different* person and a call to the number on file, typed in and recorded | `test_bank_change_requested_in_the_app_needs_another_person_and_a_call`, `test_bank_change_approval_records_the_number_dialled` |
| Imports never move a purchase order to another vendor or raise its amount | `test_po_import_cannot_move_or_raise_an_existing_po` |
| The person who asked can't approve; large payments need two people | `test_only_approvers_and_never_the_requester`, `test_dual_approval_needs_two_different_people` |
| A failing check blocks (fail closed); unanswered tickets expire | `test_check_failure_fails_closed`, `test_unanswered_tickets_expire_fail_closed` |
| Learning from approvals changes ranking only, never a verdict | `test_learned_weights_reorder_but_never_change_verdicts` |
| The sandbox rail moves money only with a valid, single-use, signed receipt | `test_receipts_cannot_be_forged_reused_expired_or_altered` |
| A release covers only Ready lines of the exact file checked; single use; expires; only approvers issue it; kinds can't be swapped | `test_release_names_only_ready_lines_and_a_partner_can_check_it`, `test_documents_are_tamper_evident_expire_and_cannot_be_swapped`, `test_only_approvers_release_or_issue_lists` |
| Nothing claims a bank or payment system enforces receipts (none does yet) | `test_no_claim_that_the_bank_enforces_receipts` |
| Checking a payment run changes nothing | `test_payment_run_finds_problems_and_changes_nothing` |
| Bank details and stored requests are encrypted; the audit log keeps last-4 only | `test_bank_details_encrypted_at_rest` |
| The audit log is append-only and tamper-evident | `tests/test_ledger.py` |
| Fraud reports never include the vendor's or the company's own domains, or free-mail domains | `test_our_own_forwarding_domain_is_never_reported`, `test_free_mail_is_never_listed` |
| One other company's fraud report only pauses; two or more, or your own, block; a report can be withdrawn | `test_rejected_as_fraud_protects_every_company`, `test_a_report_can_be_withdrawn_and_it_is_logged` |
| Secrets can live apart from the data, never inside it | `test_move_keys_then_everything_still_opens`, `test_keys_folder_inside_the_data_folder_is_refused` |
| A password-only session in a company that requires two-step can only set up two-step | `test_web_flow_end_to_end`, `test_required_two_step_gives_a_limited_session` |
| Every SQL value is a parameter | `test_sql_is_never_built_from_input` |
| The web app inserts text only with `textContent`; strict CSP; no third-party code | `tests/test_web_rules.py`, `test_security_headers` |
| One company never sees another's data | `test_company_isolation_and_roles`, `test_PT11_role_matrix` |

**If a test above fails, fix your change, not the test.** Changing or deleting one of these tests
needs a written reason in the pull request and a person's approval.

## Other rules

- **Money is integer cents.** No floats for amounts.
- **No new runtime dependencies** without a reason in the PR; `pip-audit` runs in CI.
- **Never commit secrets**: keys, `.pem`, `.key`, `keys.json`, company data folders. Gitleaks scans
  the full history.
- **Web app design rules** (`tests/test_web_rules.py`): no gradients, glass, emoji, icon kits, em
  dashes, opacity hovers, or `innerHTML`; colours must pass WCAG AA in light and dark mode.
- **Copy:** plain words, sentence case, no buzzwords. Errors say what happened and what to do.
- New checks go in `checks.py` as pure functions, added to `CHECKS`, with tests for both the
  catch and a no-false-alarm case, and a row in the README checks table.
- New web routes: role check, an allow-list of body fields, a view model in `views.py` (never a raw
  row), an audit-log entry for changes, and a test in `tests/test_records.py` or `test_pentest.py`.

## Map

`checks.py` (rules), `gateway.py` (submit, approve, payment runs, releases), `release.py` (signed documents a
partner verifies), `evidence.py` (usage and insurer evidence), `store.py` (company data,
encrypted), `ledger.py` (audit log), `receipts.py`/`rails.py` (moving money), `server.py` (HTTP)
· `web/` (app), `mcp_server.py`, `accounts.py`/`totp.py`/`oidc.py` (sign-in), `importers.py`
(CSV), `simulate.py` (quality), docs: `README.md`, `SECURITY.md`, `docs/` (`PILOT.md` for the first pilot, `PARTNER.md` for a bank).

## Product rules from the pilot plan

- Pilots stay in shadow. No agent is connected for the first file. Don't add an enforce switch for them.
- The hold rate on a real file is the number that matters; more than about 15% means the checks don't fit.
- Don't build live accounting connectors, a real bank rail, ownership checks, passkeys, PostgreSQL or SCIM
  until a gate in `docs/MARKET.md` asks for it. A real rail waits until the books commit before any outside call.
