"""agent-policy-guard: Declarative guardrail policies for AI agent autonomy."""

from __future__ import annotations

__version__ = "0.1.0"

from .engine import PolicyEngine
from .loader import load_policy_set, load_policy_set_from_str
from .models import (
    Channel,
    Condition,
    Defaults,
    Effect,
    EvalContext,
    Metadata,
    Policy,
    PolicySet,
    Verdict,
)

__all__ = [
    "Channel",
    "Condition",
    "Defaults",
    "Effect",
    "EvalContext",
    "Metadata",
    "Policy",
    "PolicyEngine",
    "PolicySet",
    "Verdict",
    "load_policy_set",
    "load_policy_set_from_str",
]
