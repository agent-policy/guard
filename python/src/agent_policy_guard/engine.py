"""Policy evaluation engine."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any

from .match import list_matches
from .models import (
    Condition,
    Defaults,
    EvalContext,
    Policy,
    PolicySet,
    Verdict,
)

logger = logging.getLogger(__name__)


def _condition_matches(cond: Condition, ctx: EvalContext) -> bool:
    """Return True when every specified condition field matches the context.

    Fields set to ``None`` are ignored (wildcard).  Non-None fields
    require at least one pattern in the list to match the corresponding
    context value.
    """
    if not list_matches(cond.modes, ctx.mode):
        return False
    if not list_matches(cond.models, ctx.model):
        return False
    if not list_matches(cond.channels, ctx.channel):
        return False
    if not list_matches(cond.tools, ctx.tool):
        return False
    if not list_matches(cond.risk, ctx.risk):
        return False
    if not list_matches(cond.users, ctx.user):
        return False
    if not list_matches(cond.sessions, ctx.session):
        return False

    # mcp_servers: if patterns are specified but no mcp_server in context -> no match
    if cond.mcp_servers is not None:
        if not ctx.mcp_server:
            return False
        if not list_matches(cond.mcp_servers, ctx.mcp_server):
            return False

    return True


class PolicyEngine:
    """Evaluates tool invocations against a PolicySet.

    Policies are sorted by priority (ascending).  The first matching
    enabled policy wins.  If nothing matches, the engine falls back
    to the PolicySet's defaults.
    """

    def __init__(self, policy_set: PolicySet | None = None) -> None:
        self._defaults = Defaults()
        self._policies: list[Policy] = []
        self._context_fallbacks: dict[str, str] = {}
        if policy_set is not None:
            self.load(policy_set)

    # ── Loading ──────────────────────────────────────────────────────

    def load(self, policy_set: PolicySet) -> None:
        """Load (or replace) the active policy set."""
        self._defaults = policy_set.defaults
        self._policies = sorted(policy_set.policies, key=lambda p: p.priority)
        self._context_fallbacks = dict(policy_set.context_fallbacks)

    @property
    def policies(self) -> list[Policy]:
        """Return the currently loaded policies (sorted by priority)."""
        return list(self._policies)

    @property
    def defaults(self) -> Defaults:
        return self._defaults

    @property
    def context_fallbacks(self) -> dict[str, str]:
        """Return the context fallback chain."""
        return dict(self._context_fallbacks)

    # ── Evaluation ───────────────────────────────────────────────────

    def _evaluate_once(self, ctx: EvalContext) -> Verdict | None:
        """Try to match a single policy against the given context.

        Returns a :class:`Verdict` on match, or ``None`` when no enabled
        policy's condition matches.
        """
        for policy in self._policies:
            if not policy.enabled:
                continue
            if _condition_matches(policy.condition, ctx):
                logger.debug(
                    "[guard.match] policy=%s effect=%s tool=%s mode=%s",
                    policy.id,
                    policy.effect.value,
                    ctx.tool,
                    ctx.mode,
                )
                return Verdict(
                    effect=policy.effect,
                    channel=policy.channel,
                    policy_id=policy.id,
                )
        return None

    def evaluate(self, ctx: EvalContext) -> Verdict:
        """Evaluate all policies and return a verdict for the given context.

        Walks policies in priority order.  The first enabled policy whose
        condition matches wins.  If no policy matches, the engine walks
        the ``context_fallbacks`` chain -- retrying evaluation with each
        fallback mode until a match is found or the chain is exhausted.

        If nothing matches after all fallbacks, returns the defaults.
        """
        verdict = self._evaluate_once(ctx)
        if verdict is not None:
            return verdict

        # Walk the context fallback chain
        mode = ctx.mode
        visited = {mode}
        while mode in self._context_fallbacks:
            mode = self._context_fallbacks[mode]
            if mode in visited:
                break
            visited.add(mode)
            verdict = self._evaluate_once(replace(ctx, mode=mode))
            if verdict is not None:
                return verdict

        logger.debug(
            "[guard.default] tool=%s mode=%s effect=%s",
            ctx.tool,
            ctx.mode,
            self._defaults.effect.value,
        )
        return Verdict(
            effect=self._defaults.effect,
            channel=self._defaults.channel,
            policy_id=None,
        )

    def resolve(self, ctx: EvalContext) -> str:
        """Convenience method returning just the effect string.

        Equivalent to ``engine.evaluate(ctx).effect.value`` -- useful
        when integrating with systems that dispatch on string strategies.
        """
        return self.evaluate(ctx).effect.value

    def evaluate_all(self, ctx: EvalContext) -> list[dict[str, Any]]:
        """Evaluate all policies and return match results for every policy.

        Useful for debugging and audit trails.  Returns a list of dicts,
        one per policy, with ``matched`` and ``policy_id`` keys.
        """
        results: list[dict[str, Any]] = []
        for policy in self._policies:
            matched = policy.enabled and _condition_matches(policy.condition, ctx)
            results.append({
                "policy_id": policy.id,
                "name": policy.name,
                "priority": policy.priority,
                "effect": policy.effect.value,
                "matched": matched,
                "enabled": policy.enabled,
            })
        return results
