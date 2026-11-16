## What changed and why

## How it was tested

- [ ] `ruff check src tests scripts` clean
- [ ] `pytest -q` all pass (including `tests/test_pentest.py`)
- [ ] If detection logic changed: `agent-checkpoint simulate --seeds 10` numbers (baseline enforce: 113/120 stopped, 1/536 false alarms)

## Safety

- [ ] No invariant in AGENTS.md weakened, and no guarding test changed or removed (if one was, explain why)
- [ ] No secrets, keys or company data committed
- [ ] New web routes: role check, field allow-list, view model, audit-log entry, tests
