"""A company's rules, as data: limits, agents and what each may do, and who approves.

Stored as `policy.json` in the company's folder so a controller can read and change it without
touching code, and so every change is a diff someone can review.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields

from .models import ACTIONS


@dataclass(frozen=True)
class AgentScope:
    allowed_actions: tuple[str, ...]
    max_amount_cents: int
    daily_cap_cents: int
    vendor: str = ""  # who makes this agent (Salesforce, Microsoft, in-house...), for the record

    def __post_init__(self):
        bad = set(self.allowed_actions) - set(ACTIONS)
        if bad:
            raise ValueError(f"unknown actions {sorted(bad)}")


@dataclass(frozen=True)
class Policy:
    currency: str = "USD"
    approval_limit_cents: int = 10_000_00      # at or above: a human approves
    dual_approval_cents: int = 50_000_00       # at or above: two different humans
    recent_bank_change_days: int = 14
    po_tolerance: float = 0.02
    require_po_above_cents: int = 2_500_00
    near_duplicate_days: int = 10
    split_window_days: int = 3
    outlier_z: float = 4.0
    outlier_min_history: int = 8
    new_vendor_days: int = 30
    new_vendor_multiple: float = 5.0
    lookalike_name_ratio: float = 0.85
    burst_per_minute: int = 20                 # more actions than this a minute: a runaway loop
    ticket_hours: int = 72                     # unanswered tickets are rejected (fail closed)
    mode: str = "shadow"                       # shadow | enforce
    agents: dict[str, AgentScope] = field(default_factory=dict)
    approvers: tuple[str, ...] = ()
    internal_domains: tuple[str, ...] = ()       # your own mail domains (forwarded invoices)
    require_two_step: bool = False               # everyone signing in with a password needs an authenticator code

    def __post_init__(self):
        if self.mode not in ("shadow", "enforce"):
            raise ValueError("mode must be shadow or enforce")
        if self.dual_approval_cents < self.approval_limit_cents:
            raise ValueError("dual_approval_cents must be at least approval_limit_cents")

    def to_json(self) -> str:
        d = asdict(self)
        d["agents"] = {k: {**asdict(v), "allowed_actions": list(v.allowed_actions)} for k, v in self.agents.items()}
        d["approvers"] = list(self.approvers)
        d["internal_domains"] = list(self.internal_domains)
        return json.dumps(d, indent=2)

    @classmethod
    def from_json(cls, text: str) -> Policy:
        d = json.loads(text)
        known = {f.name for f in fields(cls)}
        unknown = set(d) - known
        if unknown:
            raise ValueError(f"unknown policy settings: {sorted(unknown)}")
        d["agents"] = {k: AgentScope(tuple(v["allowed_actions"]), v["max_amount_cents"], v["daily_cap_cents"],
                                     v.get("vendor", "")) for k, v in d.get("agents", {}).items()}
        d["approvers"] = tuple(d.get("approvers", ()))
        d["internal_domains"] = tuple(d.get("internal_domains", ()))
        return cls(**d)
