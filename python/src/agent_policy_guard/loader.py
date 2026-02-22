"""YAML/dict loader for PolicySet documents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import Channel, Condition, Defaults, Effect, Metadata, Policy, PolicySet


def _parse_condition(raw: dict[str, Any] | None) -> Condition:
    if not raw:
        return Condition()
    return Condition(
        modes=raw.get("modes"),
        models=raw.get("models"),
        channels=raw.get("channels"),
        tools=raw.get("tools"),
        mcp_servers=raw.get("mcp_servers"),
        risk=raw.get("risk"),
        users=raw.get("users"),
        sessions=raw.get("sessions"),
    )


def _parse_policy(raw: dict[str, Any]) -> Policy:
    return Policy(
        id=raw["id"],
        effect=Effect(raw["effect"]),
        name=raw.get("name", ""),
        description=raw.get("description", ""),
        enabled=raw.get("enabled", True),
        priority=raw.get("priority", 100),
        condition=_parse_condition(raw.get("condition")),
        channel=Channel(raw.get("channel", "chat")),
    )


def _parse_defaults(raw: dict[str, Any] | None) -> Defaults:
    if not raw:
        return Defaults()
    return Defaults(
        effect=Effect(raw.get("effect", "ask")),
        channel=Channel(raw.get("channel", "chat")),
    )


def _parse_metadata(raw: dict[str, Any] | None) -> Metadata:
    if not raw:
        return Metadata(name="unnamed")
    return Metadata(
        name=raw.get("name", "unnamed"),
        description=raw.get("description", ""),
        version=raw.get("version", ""),
        labels=raw.get("labels") or {},
    )


def load_policy_set_from_dict(data: dict[str, Any]) -> PolicySet:
    """Parse a PolicySet from a raw dictionary (e.g. parsed YAML/JSON)."""
    api_version = data.get("apiVersion", "agent-policy/v1")
    kind = data.get("kind", "PolicySet")
    if kind != "PolicySet":
        raise ValueError(f"Unsupported kind: {kind} (expected PolicySet)")
    return PolicySet(
        api_version=api_version,
        kind=kind,
        metadata=_parse_metadata(data.get("metadata")),
        defaults=_parse_defaults(data.get("defaults")),
        policies=[_parse_policy(p) for p in data.get("policies", [])],
        context_fallbacks=data.get("context_fallbacks") or {},
    )


def load_policy_set_from_str(text: str) -> PolicySet:
    """Parse a PolicySet from a YAML string."""
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Expected a YAML mapping at the top level")
    return load_policy_set_from_dict(data)


def load_policy_set(path: str | Path) -> PolicySet:
    """Load a PolicySet from a YAML file on disk."""
    p = Path(path)
    return load_policy_set_from_str(p.read_text(encoding="utf-8"))
