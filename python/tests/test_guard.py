"""Tests for the guard policy engine."""

from __future__ import annotations

from agent_policy_guard import (
    Channel,
    Condition,
    Defaults,
    Effect,
    EvalContext,
    Metadata,
    Policy,
    PolicyEngine,
    PolicySet,
    load_policy_set_from_str,
)

# ── Helper ───────────────────────────────────────────────────────────────


def _make_policy_set(*policies: Policy, default_effect: str = "ask") -> PolicySet:
    return PolicySet(
        metadata=Metadata(name="test"),
        defaults=Defaults(effect=Effect(default_effect)),
        policies=list(policies),
    )


# ── Engine tests ─────────────────────────────────────────────────────────


class TestEngineBasics:
    def test_empty_policies_returns_default(self) -> None:
        ps = _make_policy_set(default_effect="deny")
        engine = PolicyEngine(ps)
        verdict = engine.evaluate(EvalContext(tool="bash"))
        assert verdict.effect == Effect.deny
        assert verdict.policy_id is None

    def test_single_allow_policy_matches(self) -> None:
        ps = _make_policy_set(
            Policy(id="p1", effect=Effect.allow, condition=Condition(tools=["bash"])),
        )
        engine = PolicyEngine(ps)
        verdict = engine.evaluate(EvalContext(tool="bash"))
        assert verdict.effect == Effect.allow
        assert verdict.policy_id == "p1"

    def test_non_matching_policy_falls_through(self) -> None:
        ps = _make_policy_set(
            Policy(id="p1", effect=Effect.deny, condition=Condition(tools=["bash"])),
            default_effect="allow",
        )
        engine = PolicyEngine(ps)
        verdict = engine.evaluate(EvalContext(tool="grep"))
        assert verdict.effect == Effect.allow
        assert verdict.policy_id is None

    def test_disabled_policy_skipped(self) -> None:
        ps = _make_policy_set(
            Policy(
                id="p1",
                effect=Effect.deny,
                enabled=False,
                condition=Condition(tools=["bash"]),
            ),
            default_effect="allow",
        )
        engine = PolicyEngine(ps)
        verdict = engine.evaluate(EvalContext(tool="bash"))
        assert verdict.effect == Effect.allow


class TestPriorityOrdering:
    def test_lower_priority_wins(self) -> None:
        ps = _make_policy_set(
            Policy(id="low", effect=Effect.allow, priority=10, condition=Condition(tools=["bash"])),
            Policy(id="high", effect=Effect.deny, priority=50, condition=Condition(tools=["bash"])),
        )
        engine = PolicyEngine(ps)
        verdict = engine.evaluate(EvalContext(tool="bash"))
        assert verdict.effect == Effect.allow
        assert verdict.policy_id == "low"

    def test_priority_respected_regardless_of_insertion_order(self) -> None:
        ps = _make_policy_set(
            Policy(id="high", effect=Effect.deny, priority=50, condition=Condition(tools=["*"])),
            Policy(id="low", effect=Effect.allow, priority=5, condition=Condition(tools=["*"])),
        )
        engine = PolicyEngine(ps)
        verdict = engine.evaluate(EvalContext(tool="anything"))
        assert verdict.policy_id == "low"


class TestConditionMatching:
    def test_mode_match(self) -> None:
        ps = _make_policy_set(
            Policy(
                id="bg",
                effect=Effect.deny,
                condition=Condition(modes=["background"]),
            ),
            default_effect="allow",
        )
        engine = PolicyEngine(ps)
        assert engine.evaluate(EvalContext(tool="bash", mode="background")).effect == Effect.deny
        assert engine.evaluate(EvalContext(tool="bash", mode="interactive")).effect == Effect.allow

    def test_model_glob(self) -> None:
        ps = _make_policy_set(
            Policy(
                id="gpt",
                effect=Effect.deny,
                condition=Condition(models=["gpt-*"]),
            ),
            default_effect="allow",
        )
        engine = PolicyEngine(ps)
        assert engine.evaluate(EvalContext(tool="bash", model="gpt-5.2")).effect == Effect.deny
        ctx = EvalContext(tool="bash", model="claude-sonnet-4.6")
        assert engine.evaluate(ctx).effect == Effect.allow

    def test_tool_glob(self) -> None:
        ps = _make_policy_set(
            Policy(
                id="mcp",
                effect=Effect.ask,
                condition=Condition(tools=["mcp:github-*"]),
            ),
            default_effect="allow",
        )
        engine = PolicyEngine(ps)
        ctx = EvalContext(tool="mcp:github-mcp-server")
        assert engine.evaluate(ctx).effect == Effect.ask

    def test_mcp_server_match(self) -> None:
        ps = _make_policy_set(
            Policy(
                id="mcp",
                effect=Effect.deny,
                condition=Condition(mcp_servers=["azure-*"]),
            ),
            default_effect="allow",
        )
        engine = PolicyEngine(ps)
        assert engine.evaluate(
            EvalContext(tool="deploy", mcp_server="azure-mcp-server")
        ).effect == Effect.deny
        assert engine.evaluate(
            EvalContext(tool="deploy", mcp_server="github-mcp")
        ).effect == Effect.allow

    def test_mcp_server_with_no_server_in_context(self) -> None:
        ps = _make_policy_set(
            Policy(
                id="mcp",
                effect=Effect.deny,
                condition=Condition(mcp_servers=["azure-*"]),
            ),
            default_effect="allow",
        )
        engine = PolicyEngine(ps)
        assert engine.evaluate(EvalContext(tool="deploy")).effect == Effect.allow

    def test_risk_match(self) -> None:
        ps = _make_policy_set(
            Policy(
                id="high",
                effect=Effect.deny,
                condition=Condition(risk=["high", "critical"]),
            ),
            default_effect="allow",
        )
        engine = PolicyEngine(ps)
        assert engine.evaluate(EvalContext(tool="bash", risk="high")).effect == Effect.deny
        assert engine.evaluate(EvalContext(tool="bash", risk="critical")).effect == Effect.deny
        assert engine.evaluate(EvalContext(tool="bash", risk="low")).effect == Effect.allow

    def test_user_match(self) -> None:
        ps = _make_policy_set(
            Policy(
                id="admin",
                effect=Effect.allow,
                condition=Condition(users=["admin-*"]),
            ),
            default_effect="deny",
        )
        engine = PolicyEngine(ps)
        assert engine.evaluate(EvalContext(tool="bash", user="admin-alice")).effect == Effect.allow
        assert engine.evaluate(EvalContext(tool="bash", user="guest-bob")).effect == Effect.deny

    def test_and_logic_across_fields(self) -> None:
        ps = _make_policy_set(
            Policy(
                id="combo",
                effect=Effect.deny,
                condition=Condition(
                    modes=["background"],
                    tools=["bash"],
                    risk=["high"],
                ),
            ),
            default_effect="allow",
        )
        engine = PolicyEngine(ps)
        # All match -> deny
        assert engine.evaluate(
            EvalContext(tool="bash", mode="background", risk="high")
        ).effect == Effect.deny
        # Mode mismatch -> allow (default)
        assert engine.evaluate(
            EvalContext(tool="bash", mode="interactive", risk="high")
        ).effect == Effect.allow
        # Tool mismatch -> allow
        assert engine.evaluate(
            EvalContext(tool="grep", mode="background", risk="high")
        ).effect == Effect.allow

    def test_channel_override(self) -> None:
        ps = _make_policy_set(
            Policy(
                id="phone",
                effect=Effect.ask,
                channel=Channel.phone,
                condition=Condition(tools=["make_voice_call"]),
            ),
        )
        engine = PolicyEngine(ps)
        verdict = engine.evaluate(EvalContext(tool="make_voice_call"))
        assert verdict.effect == Effect.ask
        assert verdict.channel == Channel.phone


class TestEvaluateAll:
    def test_returns_all_policies(self) -> None:
        ps = _make_policy_set(
            Policy(id="p1", effect=Effect.allow, condition=Condition(tools=["bash"])),
            Policy(id="p2", effect=Effect.deny, condition=Condition(tools=["grep"])),
        )
        engine = PolicyEngine(ps)
        results = engine.evaluate_all(EvalContext(tool="bash"))
        assert len(results) == 2
        matched = [r for r in results if r["matched"]]
        assert len(matched) == 1
        assert matched[0]["policy_id"] == "p1"


# ── Custom effects ───────────────────────────────────────────────────────


class TestCustomEffects:
    def test_well_known_hitl_effect(self) -> None:
        ps = _make_policy_set(
            Policy(id="p1", effect=Effect.hitl, condition=Condition(tools=["bash"])),
        )
        engine = PolicyEngine(ps)
        verdict = engine.evaluate(EvalContext(tool="bash"))
        assert verdict.effect == Effect.hitl
        assert verdict.effect.value == "hitl"

    def test_well_known_aitl_effect(self) -> None:
        ps = _make_policy_set(
            Policy(id="p1", effect=Effect.aitl, condition=Condition(tools=["bash"])),
        )
        engine = PolicyEngine(ps)
        assert engine.evaluate(EvalContext(tool="bash")).effect == Effect.aitl

    def test_well_known_filter_effect(self) -> None:
        ps = _make_policy_set(
            Policy(id="p1", effect=Effect.filter, condition=Condition(tools=["bash"])),
        )
        engine = PolicyEngine(ps)
        assert engine.evaluate(EvalContext(tool="bash")).effect == Effect.filter

    def test_well_known_pitl_effect(self) -> None:
        ps = _make_policy_set(
            Policy(id="p1", effect=Effect.pitl, condition=Condition(tools=["call"])),
        )
        engine = PolicyEngine(ps)
        assert engine.evaluate(EvalContext(tool="call")).effect == Effect.pitl

    def test_custom_effect_string(self) -> None:
        custom = Effect("my-org-auth")
        ps = _make_policy_set(
            Policy(id="p1", effect=custom, condition=Condition(tools=["bash"])),
        )
        engine = PolicyEngine(ps)
        verdict = engine.evaluate(EvalContext(tool="bash"))
        assert verdict.effect == "my-org-auth"
        assert verdict.effect.value == "my-org-auth"

    def test_custom_effect_loaded_from_yaml(self) -> None:
        yaml_doc = """\
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: custom-effects
policies:
  - id: p1
    effect: my-org-mfa
    condition:
      tools: [deploy]
"""
        ps = load_policy_set_from_str(yaml_doc)
        engine = PolicyEngine(ps)
        verdict = engine.evaluate(EvalContext(tool="deploy"))
        assert verdict.effect.value == "my-org-mfa"

    def test_resolve_returns_effect_string(self) -> None:
        ps = _make_policy_set(
            Policy(id="p1", effect=Effect.aitl, condition=Condition(tools=["bash"])),
            default_effect="deny",
        )
        engine = PolicyEngine(ps)
        assert engine.resolve(EvalContext(tool="bash")) == "aitl"
        assert isinstance(engine.resolve(EvalContext(tool="bash")), str)
        assert engine.resolve(EvalContext(tool="grep")) == "deny"


# ── Context fallbacks ───────────────────────────────────────────────────


class TestContextFallbacks:
    def test_fallback_to_background(self) -> None:
        ps = PolicySet(
            metadata=Metadata(name="test"),
            defaults=Defaults(effect=Effect("allow")),
            policies=[
                Policy(
                    id="bg-deny",
                    effect=Effect.deny,
                    condition=Condition(modes=["background"], tools=["bash"]),
                ),
            ],
            context_fallbacks={"scheduler": "background"},
        )
        engine = PolicyEngine(ps)
        # Direct background match
        v = engine.evaluate(EvalContext(tool="bash", mode="background"))
        assert v.effect == Effect.deny
        # Scheduler falls back to background
        v = engine.evaluate(EvalContext(tool="bash", mode="scheduler"))
        assert v.effect == Effect.deny
        assert v.policy_id == "bg-deny"
        # Interactive has no fallback -- uses default
        v = engine.evaluate(EvalContext(tool="bash", mode="interactive"))
        assert v.effect == Effect.allow

    def test_multi_level_fallback(self) -> None:
        ps = PolicySet(
            metadata=Metadata(name="test"),
            defaults=Defaults(effect=Effect("deny")),
            policies=[
                Policy(
                    id="bg",
                    effect=Effect.hitl,
                    condition=Condition(modes=["background"]),
                ),
            ],
            context_fallbacks={
                "scheduler": "bot_processor",
                "bot_processor": "background",
            },
        )
        engine = PolicyEngine(ps)
        # scheduler -> bot_processor -> background (matches)
        v = engine.evaluate(EvalContext(tool="bash", mode="scheduler"))
        assert v.effect == Effect.hitl
        assert v.policy_id == "bg"

    def test_cycle_prevention(self) -> None:
        ps = PolicySet(
            metadata=Metadata(name="test"),
            defaults=Defaults(effect=Effect("deny")),
            policies=[],
            context_fallbacks={"a": "b", "b": "a"},
        )
        engine = PolicyEngine(ps)
        # Should not infinite loop -- falls to default
        v = engine.evaluate(EvalContext(tool="bash", mode="a"))
        assert v.effect == Effect.deny

    def test_fallback_loaded_from_yaml(self) -> None:
        yaml_doc = """\
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: fallback-test
defaults:
  effect: allow
context_fallbacks:
  scheduler: background
  bot_processor: background
policies:
  - id: deny-bg-bash
    effect: deny
    condition:
      modes: [background]
      tools: [bash]
"""
        ps = load_policy_set_from_str(yaml_doc)
        assert ps.context_fallbacks == {
            "scheduler": "background",
            "bot_processor": "background",
        }
        engine = PolicyEngine(ps)
        assert engine.resolve(EvalContext(tool="bash", mode="scheduler")) == "deny"
        assert isinstance(engine.resolve(EvalContext(tool="bash", mode="scheduler")), str)
        assert engine.resolve(EvalContext(tool="grep", mode="scheduler")) == "allow"

    def test_context_fallbacks_property(self) -> None:
        ps = PolicySet(
            metadata=Metadata(name="test"),
            context_fallbacks={"a": "b"},
        )
        engine = PolicyEngine(ps)
        assert engine.context_fallbacks == {"a": "b"}


# ── Loader tests ─────────────────────────────────────────────────────────


class TestLoader:
    YAML_DOC = """\
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: test-set
  description: A test policy set
  version: "1.0.0"
  labels:
    env: test
defaults:
  effect: deny
  channel: chat
policies:
  - id: allow-readonly
    name: Allow read-only tools
    priority: 10
    condition:
      tools:
        - view
        - grep
        - glob
    effect: allow
  - id: ask-terminal
    name: Ask for terminal
    priority: 50
    condition:
      modes: [interactive]
      tools: [bash, run]
    effect: ask
    channel: phone
  - id: deny-background-high
    name: Deny background high risk
    enabled: false
    priority: 20
    condition:
      modes: [background]
      risk: [high]
    effect: deny
"""

    def test_load_from_string(self) -> None:
        ps = load_policy_set_from_str(self.YAML_DOC)
        assert ps.api_version == "agent-policy/v1"
        assert ps.kind == "PolicySet"
        assert ps.metadata.name == "test-set"
        assert ps.metadata.version == "1.0.0"
        assert ps.metadata.labels == {"env": "test"}
        assert ps.defaults.effect == Effect.deny
        assert len(ps.policies) == 3

    def test_loaded_policies_have_correct_fields(self) -> None:
        ps = load_policy_set_from_str(self.YAML_DOC)
        p0 = ps.policies[0]
        assert p0.id == "allow-readonly"
        assert p0.priority == 10
        assert p0.effect == Effect.allow
        assert p0.condition.tools == ["view", "grep", "glob"]
        assert p0.enabled is True

    def test_disabled_policy_parsed(self) -> None:
        ps = load_policy_set_from_str(self.YAML_DOC)
        p2 = ps.policies[2]
        assert p2.id == "deny-background-high"
        assert p2.enabled is False

    def test_channel_override_parsed(self) -> None:
        ps = load_policy_set_from_str(self.YAML_DOC)
        p1 = ps.policies[1]
        assert p1.channel == Channel.phone

    def test_load_and_evaluate(self) -> None:
        ps = load_policy_set_from_str(self.YAML_DOC)
        engine = PolicyEngine(ps)

        # view -> allow (matches allow-readonly)
        v = engine.evaluate(EvalContext(tool="view"))
        assert v.effect == Effect.allow

        # bash interactive -> ask via phone (matches ask-terminal)
        v = engine.evaluate(EvalContext(tool="bash", mode="interactive"))
        assert v.effect == Effect.ask
        assert v.channel == Channel.phone

        # unknown tool -> deny (default)
        v = engine.evaluate(EvalContext(tool="unknown"))
        assert v.effect == Effect.deny

    def test_invalid_kind_raises(self) -> None:
        bad = "apiVersion: agent-policy/v1\nkind: NotAPolicy\nmetadata:\n  name: x\npolicies: []"
        try:
            load_policy_set_from_str(bad)
            assert False, "Should have raised ValueError"
        except ValueError as exc:
            assert "PolicySet" in str(exc)


# ── Match tests ──────────────────────────────────────────────────────────


class TestGlobMatch:
    def test_exact_match(self) -> None:
        from agent_policy_guard.match import glob_match
        assert glob_match("bash", "bash") is True
        assert glob_match("bash", "grep") is False

    def test_star_matches_all(self) -> None:
        from agent_policy_guard.match import glob_match
        assert glob_match("*", "anything") is True

    def test_prefix_glob(self) -> None:
        from agent_policy_guard.match import glob_match
        assert glob_match("mcp:github-*", "mcp:github-mcp-server") is True
        assert glob_match("mcp:github-*", "mcp:azure-mcp-server") is False

    def test_suffix_glob(self) -> None:
        from agent_policy_guard.match import glob_match
        assert glob_match("*-server", "github-mcp-server") is True
        assert glob_match("*-server", "github-mcp-client") is False

    def test_empty_pattern(self) -> None:
        from agent_policy_guard.match import glob_match
        assert glob_match("", "anything") is False

    def test_question_mark(self) -> None:
        from agent_policy_guard.match import glob_match
        assert glob_match("gpt-?", "gpt-5") is True
        assert glob_match("gpt-?", "gpt-55") is False


class TestLoadExampleFiles:
    """Verify that all example YAML files load and evaluate correctly."""

    def _load_example(self, name: str) -> PolicySet:
        import os
        examples_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "examples"
        )
        path = os.path.join(examples_dir, f"{name}.yaml")
        from agent_policy_guard import load_policy_set
        return load_policy_set(path)

    def test_permissive_loads(self) -> None:
        ps = self._load_example("permissive")
        assert ps.metadata.name == "permissive"
        assert ps.defaults.effect == Effect.allow
        assert ps.context_fallbacks["scheduler"] == "background"
        engine = PolicyEngine(ps)
        v = engine.evaluate(EvalContext(tool="view"))
        assert v.effect == Effect.allow

    def test_balanced_loads(self) -> None:
        ps = self._load_example("balanced")
        assert ps.metadata.name == "balanced"
        assert ps.defaults.effect == Effect.hitl
        engine = PolicyEngine(ps)
        # Low risk -> allow
        v = engine.evaluate(EvalContext(tool="view", risk="low"))
        assert v.effect == Effect.allow
        # High risk background -> deny
        v = engine.evaluate(EvalContext(tool="bash", mode="background", risk="high"))
        assert v.effect == Effect.deny
        # Medium risk interactive -> filter
        v = engine.evaluate(EvalContext(tool="edit", mode="interactive", risk="medium"))
        assert v.effect == Effect.filter
        # Medium risk background -> aitl
        v = engine.evaluate(EvalContext(tool="edit", mode="background", risk="medium"))
        assert v.effect == Effect.aitl
        # Scheduler falls back to background
        v = engine.evaluate(EvalContext(tool="bash", mode="scheduler", risk="high"))
        assert v.effect == Effect.deny

    def test_restrictive_loads(self) -> None:
        ps = self._load_example("restrictive")
        assert ps.metadata.name == "restrictive"
        assert ps.defaults.effect == Effect.deny
        engine = PolicyEngine(ps)
        # Read-only -> allow
        v = engine.evaluate(EvalContext(tool="grep"))
        assert v.effect == Effect.allow
        # Background medium risk -> deny
        v = engine.evaluate(EvalContext(tool="edit", mode="background", risk="medium"))
        assert v.effect == Effect.deny
        # Interactive writes -> hitl
        v = engine.evaluate(EvalContext(tool="edit", mode="interactive"))
        assert v.effect == Effect.hitl
        # Voice call -> pitl
        v = engine.evaluate(EvalContext(tool="make_voice_call"))
        assert v.effect == Effect.pitl
