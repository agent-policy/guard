"""Data models for agent-policy-guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Effect(str, Enum):
    """The effect a policy applies to a matching tool invocation.

    Well-known effects are available as class attributes (``Effect.allow``,
    ``Effect.hitl``, etc.).  Custom effects are supported for extensibility
    -- call ``Effect("my-custom-strategy")`` to create one.
    """

    allow = "allow"
    deny = "deny"
    ask = "ask"
    hitl = "hitl"
    pitl = "pitl"
    aitl = "aitl"
    filter = "filter"

    @classmethod
    def _missing_(cls, value: object) -> Effect | None:
        """Accept any string as a custom effect for extensibility."""
        if not isinstance(value, str):
            return None
        obj = str.__new__(cls, value)
        obj._name_ = value
        obj._value_ = value
        return obj


class Channel(str, Enum):
    """Approval channel for 'ask' effects."""

    chat = "chat"
    phone = "phone"


# ── Context passed at evaluation time ────────────────────────────────────


@dataclass(frozen=True)
class EvalContext:
    """Snapshot of runtime state for a single tool invocation.

    All fields are optional.  The engine matches each field against the
    policy condition; unset fields are ignored during matching.
    """

    mode: str = ""
    model: str = ""
    channel: str = ""
    tool: str = ""
    mcp_server: str = ""
    risk: str = ""
    user: str = ""
    session: str = ""


# ── Policy definition ───────────────────────────────────────────────────


@dataclass
class Condition:
    """Matching criteria for a policy.

    All specified fields must match (AND logic across fields).
    Each field's list uses OR logic (any item in the list may match).
    ``None`` means "don't care" -- the field is not evaluated.
    String values support glob patterns: ``*`` matches everything,
    ``prefix*`` matches any string starting with prefix.
    """

    modes: list[str] | None = None
    models: list[str] | None = None
    channels: list[str] | None = None
    tools: list[str] | None = None
    mcp_servers: list[str] | None = None
    risk: list[str] | None = None
    users: list[str] | None = None
    sessions: list[str] | None = None


@dataclass
class Policy:
    """A single guardrail policy."""

    id: str
    effect: Effect
    name: str = ""
    description: str = ""
    enabled: bool = True
    priority: int = 100
    condition: Condition = field(default_factory=Condition)
    channel: Channel = Channel.chat


# ── PolicySet (top-level document) ──────────────────────────────────────


@dataclass
class Metadata:
    """Descriptive metadata for a policy set."""

    name: str
    description: str = ""
    version: str = ""
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class Defaults:
    """Fallback behaviour when no policy matches."""

    effect: Effect = Effect.ask
    channel: Channel = Channel.chat


@dataclass
class PolicySet:
    """A complete set of guardrail policies loaded from YAML."""

    api_version: str = "agent-policy/v1"
    kind: str = "PolicySet"
    metadata: Metadata = field(default_factory=lambda: Metadata(name="unnamed"))
    defaults: Defaults = field(default_factory=Defaults)
    policies: list[Policy] = field(default_factory=list)
    context_fallbacks: dict[str, str] = field(default_factory=dict)


# ── Evaluation result ───────────────────────────────────────────────────


@dataclass(frozen=True)
class Verdict:
    """The result of evaluating a context against a policy set."""

    effect: Effect
    channel: Channel = Channel.chat
    policy_id: str | None = None
