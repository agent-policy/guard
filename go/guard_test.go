package guard

import (
	"os"
	"path/filepath"
	"testing"
)

// ── Helpers ─────────────────────────────────────────────────────────────

func boolPtr(b bool) *bool { return &b }

func makePolicySet(policies []Policy, defaultEffect Effect) *PolicySet {
	return &PolicySet{
		Metadata: Metadata{Name: "test"},
		Defaults: Defaults{Effect: defaultEffect, Channel: ChannelChat},
		Policies: policies,
	}
}

// ── Engine basics ───────────────────────────────────────────────────────

func TestEmptyPoliciesReturnsDefault(t *testing.T) {
	engine := NewPolicyEngine(makePolicySet(nil, EffectDeny))
	v := engine.Evaluate(EvalContext{Tool: "bash"})
	if v.Effect != EffectDeny {
		t.Errorf("expected deny, got %s", v.Effect)
	}
	if v.PolicyID != "" {
		t.Errorf("expected empty policy ID, got %s", v.PolicyID)
	}
}

func TestSingleAllowMatch(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "p1", Effect: EffectAllow, Condition: Condition{Tools: []string{"bash"}}},
	}, EffectAsk)
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "bash"})
	if v.Effect != EffectAllow {
		t.Errorf("expected allow, got %s", v.Effect)
	}
	if v.PolicyID != "p1" {
		t.Errorf("expected p1, got %s", v.PolicyID)
	}
}

func TestNonMatchingFallsThrough(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "p1", Effect: EffectDeny, Condition: Condition{Tools: []string{"bash"}}},
	}, EffectAllow)
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "grep"})
	if v.Effect != EffectAllow {
		t.Errorf("expected allow, got %s", v.Effect)
	}
}

func TestDisabledPolicySkipped(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "p1", Effect: EffectDeny, Enabled: boolPtr(false), Condition: Condition{Tools: []string{"bash"}}},
	}, EffectAllow)
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "bash"})
	if v.Effect != EffectAllow {
		t.Errorf("expected allow, got %s", v.Effect)
	}
}

// ── Priority ────────────────────────────────────────────────────────────

func TestLowerPriorityWins(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "low", Effect: EffectAllow, Priority: 10, Condition: Condition{Tools: []string{"bash"}}},
		{ID: "high", Effect: EffectDeny, Priority: 50, Condition: Condition{Tools: []string{"bash"}}},
	}, EffectAsk)
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "bash"})
	if v.Effect != EffectAllow {
		t.Errorf("expected allow, got %s", v.Effect)
	}
	if v.PolicyID != "low" {
		t.Errorf("expected low, got %s", v.PolicyID)
	}
}

func TestPriorityRegardlessOfInsertionOrder(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "high", Effect: EffectDeny, Priority: 50, Condition: Condition{Tools: []string{"*"}}},
		{ID: "low", Effect: EffectAllow, Priority: 5, Condition: Condition{Tools: []string{"*"}}},
	}, EffectAsk)
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "anything"})
	if v.PolicyID != "low" {
		t.Errorf("expected low, got %s", v.PolicyID)
	}
}

// ── Condition matching ──────────────────────────────────────────────────

func TestModeMatch(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "bg", Effect: EffectDeny, Priority: 10, Condition: Condition{Modes: []string{"background"}}},
	}, EffectAllow)
	engine := NewPolicyEngine(ps)

	v := engine.Evaluate(EvalContext{Tool: "bash", Mode: "background"})
	if v.Effect != EffectDeny {
		t.Errorf("background: expected deny, got %s", v.Effect)
	}

	v = engine.Evaluate(EvalContext{Tool: "bash", Mode: "interactive"})
	if v.Effect != EffectAllow {
		t.Errorf("interactive: expected allow, got %s", v.Effect)
	}
}

func TestModelGlob(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "gpt", Effect: EffectDeny, Priority: 10, Condition: Condition{Models: []string{"gpt-*"}}},
	}, EffectAllow)
	engine := NewPolicyEngine(ps)

	v := engine.Evaluate(EvalContext{Tool: "bash", Model: "gpt-5.2"})
	if v.Effect != EffectDeny {
		t.Errorf("gpt-5.2: expected deny, got %s", v.Effect)
	}

	v = engine.Evaluate(EvalContext{Tool: "bash", Model: "claude-sonnet-4.6"})
	if v.Effect != EffectAllow {
		t.Errorf("claude: expected allow, got %s", v.Effect)
	}
}

func TestToolGlob(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "mcp", Effect: EffectAsk, Priority: 10, Condition: Condition{Tools: []string{"mcp:github-*"}}},
	}, EffectAllow)
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "mcp:github-mcp-server"})
	if v.Effect != EffectAsk {
		t.Errorf("expected ask, got %s", v.Effect)
	}
}

func TestMcpServersMatch(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "mcp", Effect: EffectDeny, Priority: 10, Condition: Condition{McpServers: []string{"azure-*"}}},
	}, EffectAllow)
	engine := NewPolicyEngine(ps)

	v := engine.Evaluate(EvalContext{Tool: "deploy", McpServer: "azure-mcp-server"})
	if v.Effect != EffectDeny {
		t.Errorf("azure: expected deny, got %s", v.Effect)
	}

	v = engine.Evaluate(EvalContext{Tool: "deploy", McpServer: "github-mcp"})
	if v.Effect != EffectAllow {
		t.Errorf("github: expected allow, got %s", v.Effect)
	}
}

func TestMcpServersNoServerInContext(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "mcp", Effect: EffectDeny, Priority: 10, Condition: Condition{McpServers: []string{"azure-*"}}},
	}, EffectAllow)
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "deploy"})
	if v.Effect != EffectAllow {
		t.Errorf("expected allow, got %s", v.Effect)
	}
}

func TestRiskMatch(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "high", Effect: EffectDeny, Priority: 10, Condition: Condition{Risk: []string{"high", "critical"}}},
	}, EffectAllow)
	engine := NewPolicyEngine(ps)

	for _, risk := range []string{"high", "critical"} {
		v := engine.Evaluate(EvalContext{Tool: "bash", Risk: risk})
		if v.Effect != EffectDeny {
			t.Errorf("%s: expected deny, got %s", risk, v.Effect)
		}
	}
	v := engine.Evaluate(EvalContext{Tool: "bash", Risk: "low"})
	if v.Effect != EffectAllow {
		t.Errorf("low: expected allow, got %s", v.Effect)
	}
}

func TestUserMatch(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "admin", Effect: EffectAllow, Priority: 10, Condition: Condition{Users: []string{"admin-*"}}},
	}, EffectDeny)
	engine := NewPolicyEngine(ps)

	v := engine.Evaluate(EvalContext{Tool: "bash", User: "admin-alice"})
	if v.Effect != EffectAllow {
		t.Errorf("admin: expected allow, got %s", v.Effect)
	}

	v = engine.Evaluate(EvalContext{Tool: "bash", User: "guest-bob"})
	if v.Effect != EffectDeny {
		t.Errorf("guest: expected deny, got %s", v.Effect)
	}
}

func TestANDLogicAcrossFields(t *testing.T) {
	ps := makePolicySet([]Policy{
		{
			ID: "combo", Effect: EffectDeny, Priority: 10,
			Condition: Condition{
				Modes: []string{"background"},
				Tools: []string{"bash"},
				Risk:  []string{"high"},
			},
		},
	}, EffectAllow)
	engine := NewPolicyEngine(ps)

	// All match -> deny
	v := engine.Evaluate(EvalContext{Tool: "bash", Mode: "background", Risk: "high"})
	if v.Effect != EffectDeny {
		t.Errorf("all match: expected deny, got %s", v.Effect)
	}

	// Mode mismatch -> allow
	v = engine.Evaluate(EvalContext{Tool: "bash", Mode: "interactive", Risk: "high"})
	if v.Effect != EffectAllow {
		t.Errorf("mode mismatch: expected allow, got %s", v.Effect)
	}

	// Tool mismatch -> allow
	v = engine.Evaluate(EvalContext{Tool: "grep", Mode: "background", Risk: "high"})
	if v.Effect != EffectAllow {
		t.Errorf("tool mismatch: expected allow, got %s", v.Effect)
	}
}

func TestChannelOverride(t *testing.T) {
	ps := makePolicySet([]Policy{
		{
			ID: "phone", Effect: EffectAsk, Priority: 10,
			Channel:   ChannelPhone,
			Condition: Condition{Tools: []string{"make_voice_call"}},
		},
	}, EffectAsk)
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "make_voice_call"})
	if v.Effect != EffectAsk {
		t.Errorf("expected ask, got %s", v.Effect)
	}
	if v.Channel != ChannelPhone {
		t.Errorf("expected phone, got %s", v.Channel)
	}
}

// ── EvaluateAll ─────────────────────────────────────────────────────────

func TestEvaluateAll(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "p1", Effect: EffectAllow, Priority: 10, Condition: Condition{Tools: []string{"bash"}}},
		{ID: "p2", Effect: EffectDeny, Priority: 20, Condition: Condition{Tools: []string{"grep"}}},
	}, EffectAsk)
	engine := NewPolicyEngine(ps)
	results := engine.EvaluateAll(EvalContext{Tool: "bash"})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	matched := 0
	for _, r := range results {
		if r.Matched {
			matched++
			if r.PolicyID != "p1" {
				t.Errorf("expected p1, got %s", r.PolicyID)
			}
		}
	}
	if matched != 1 {
		t.Errorf("expected 1 match, got %d", matched)
	}
}

// ── Custom effects ──────────────────────────────────────────────────────

func TestWellKnownEffects(t *testing.T) {
	cases := []struct {
		name   string
		effect Effect
		want   string
	}{
		{"hitl", EffectHITL, "hitl"},
		{"aitl", EffectAITL, "aitl"},
		{"pitl", EffectPITL, "pitl"},
		{"filter", EffectFilter, "filter"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := makePolicySet([]Policy{
				{ID: "p1", Effect: tc.effect, Priority: 10, Condition: Condition{Tools: []string{"bash"}}},
			}, EffectDeny)
			engine := NewPolicyEngine(ps)
			v := engine.Evaluate(EvalContext{Tool: "bash"})
			if string(v.Effect) != tc.want {
				t.Errorf("expected %s, got %s", tc.want, v.Effect)
			}
		})
	}
}

func TestCustomEffectString(t *testing.T) {
	custom := Effect("my-org-auth")
	ps := makePolicySet([]Policy{
		{ID: "p1", Effect: custom, Priority: 10, Condition: Condition{Tools: []string{"deploy"}}},
	}, EffectDeny)
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "deploy"})
	if v.Effect != "my-org-auth" {
		t.Errorf("expected my-org-auth, got %s", v.Effect)
	}
}

func TestCustomEffectLoadedFromYAML(t *testing.T) {
	yamlDoc := `
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: custom
policies:
  - id: p1
    effect: my-org-mfa
    condition:
      tools: [deploy]
`
	ps, err := LoadPolicySetFromBytes([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "deploy"})
	if string(v.Effect) != "my-org-mfa" {
		t.Errorf("expected my-org-mfa, got %s", v.Effect)
	}
}

func TestResolve(t *testing.T) {
	ps := makePolicySet([]Policy{
		{ID: "p1", Effect: EffectAITL, Priority: 10, Condition: Condition{Tools: []string{"bash"}}},
	}, EffectDeny)
	engine := NewPolicyEngine(ps)
	if got := engine.Resolve(EvalContext{Tool: "bash"}); got != "aitl" {
		t.Errorf("expected aitl, got %s", got)
	}
	if got := engine.Resolve(EvalContext{Tool: "grep"}); got != "deny" {
		t.Errorf("expected deny, got %s", got)
	}
}

// ── Context fallbacks ───────────────────────────────────────────────────

func TestContextFallbackToBackground(t *testing.T) {
	ps := &PolicySet{
		Metadata: Metadata{Name: "test"},
		Defaults: Defaults{Effect: EffectAllow, Channel: ChannelChat},
		Policies: []Policy{
			{ID: "bg-deny", Effect: EffectDeny, Priority: 10, Condition: Condition{Modes: []string{"background"}, Tools: []string{"bash"}}},
		},
		ContextFallbacks: map[string]string{"scheduler": "background"},
	}
	engine := NewPolicyEngine(ps)

	v := engine.Evaluate(EvalContext{Tool: "bash", Mode: "background"})
	if v.Effect != EffectDeny {
		t.Errorf("background: expected deny, got %s", v.Effect)
	}

	v = engine.Evaluate(EvalContext{Tool: "bash", Mode: "scheduler"})
	if v.Effect != EffectDeny {
		t.Errorf("scheduler fallback: expected deny, got %s", v.Effect)
	}
	if v.PolicyID != "bg-deny" {
		t.Errorf("scheduler fallback: expected bg-deny, got %s", v.PolicyID)
	}

	v = engine.Evaluate(EvalContext{Tool: "bash", Mode: "interactive"})
	if v.Effect != EffectAllow {
		t.Errorf("interactive: expected allow, got %s", v.Effect)
	}
}

func TestContextFallbackMultiLevel(t *testing.T) {
	ps := &PolicySet{
		Metadata: Metadata{Name: "test"},
		Defaults: Defaults{Effect: EffectDeny, Channel: ChannelChat},
		Policies: []Policy{
			{ID: "bg", Effect: EffectHITL, Priority: 10, Condition: Condition{Modes: []string{"background"}}},
		},
		ContextFallbacks: map[string]string{
			"scheduler":     "bot_processor",
			"bot_processor": "background",
		},
	}
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "bash", Mode: "scheduler"})
	if v.Effect != EffectHITL {
		t.Errorf("expected hitl, got %s", v.Effect)
	}
	if v.PolicyID != "bg" {
		t.Errorf("expected bg, got %s", v.PolicyID)
	}
}

func TestContextFallbackCyclePrevention(t *testing.T) {
	ps := &PolicySet{
		Metadata: Metadata{Name: "test"},
		Defaults: Defaults{Effect: EffectDeny, Channel: ChannelChat},
		ContextFallbacks: map[string]string{
			"a": "b",
			"b": "a",
		},
	}
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "bash", Mode: "a"})
	if v.Effect != EffectDeny {
		t.Errorf("expected deny (default), got %s", v.Effect)
	}
}

func TestContextFallbackLoadedFromYAML(t *testing.T) {
	yamlDoc := `
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
`
	ps, err := LoadPolicySetFromBytes([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps.ContextFallbacks) != 2 {
		t.Fatalf("expected 2 fallbacks, got %d", len(ps.ContextFallbacks))
	}
	engine := NewPolicyEngine(ps)
	if got := engine.Resolve(EvalContext{Tool: "bash", Mode: "scheduler"}); got != "deny" {
		t.Errorf("expected deny, got %s", got)
	}
	if got := engine.Resolve(EvalContext{Tool: "grep", Mode: "scheduler"}); got != "allow" {
		t.Errorf("expected allow, got %s", got)
	}
}

func TestContextFallbacksProperty(t *testing.T) {
	ps := &PolicySet{
		Metadata:         Metadata{Name: "test"},
		Defaults:         Defaults{Effect: EffectAsk, Channel: ChannelChat},
		ContextFallbacks: map[string]string{"a": "b"},
	}
	engine := NewPolicyEngine(ps)
	fb := engine.ContextFallbacks()
	if fb["a"] != "b" {
		t.Errorf("expected a->b, got %v", fb)
	}
}

// ── Loader ──────────────────────────────────────────────────────────────

func TestLoadFromBytes(t *testing.T) {
	yamlDoc := `
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
      tools: [view, grep, glob]
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
`
	ps, err := LoadPolicySetFromBytes([]byte(yamlDoc))
	if err != nil {
		t.Fatal(err)
	}
	if ps.Metadata.Name != "test-set" {
		t.Errorf("expected test-set, got %s", ps.Metadata.Name)
	}
	if ps.Defaults.Effect != EffectDeny {
		t.Errorf("expected deny default, got %s", ps.Defaults.Effect)
	}
	if len(ps.Policies) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(ps.Policies))
	}
	if ps.Policies[0].ID != "allow-readonly" {
		t.Errorf("expected allow-readonly, got %s", ps.Policies[0].ID)
	}
	if !ps.Policies[0].IsEnabled() {
		t.Error("policy 0 should be enabled")
	}
	if ps.Policies[2].IsEnabled() {
		t.Error("policy 2 should be disabled")
	}
	if ps.Policies[1].Channel != ChannelPhone {
		t.Errorf("expected phone channel, got %s", ps.Policies[1].Channel)
	}

	// Test evaluation
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "view"})
	if v.Effect != EffectAllow {
		t.Errorf("view: expected allow, got %s", v.Effect)
	}

	v = engine.Evaluate(EvalContext{Tool: "bash", Mode: "interactive"})
	if v.Effect != EffectAsk {
		t.Errorf("bash interactive: expected ask, got %s", v.Effect)
	}
	if v.Channel != ChannelPhone {
		t.Errorf("bash interactive: expected phone, got %s", v.Channel)
	}

	v = engine.Evaluate(EvalContext{Tool: "unknown"})
	if v.Effect != EffectDeny {
		t.Errorf("unknown: expected deny, got %s", v.Effect)
	}
}

func TestInvalidKind(t *testing.T) {
	bad := `apiVersion: agent-policy/v1
kind: NotAPolicy
metadata:
  name: x
policies: []`
	_, err := LoadPolicySetFromBytes([]byte(bad))
	if err == nil {
		t.Fatal("expected error for invalid kind")
	}
}

// ── Glob match ──────────────────────────────────────────────────────────

func TestGlobMatchExact(t *testing.T) {
	if !GlobMatch("bash", "bash") {
		t.Error("bash should match bash")
	}
	if GlobMatch("bash", "grep") {
		t.Error("bash should not match grep")
	}
}

func TestGlobMatchStar(t *testing.T) {
	if !GlobMatch("*", "anything") {
		t.Error("* should match anything")
	}
}

func TestGlobMatchPrefix(t *testing.T) {
	if !GlobMatch("gpt-*", "gpt-5.2") {
		t.Error("gpt-* should match gpt-5.2")
	}
	if GlobMatch("gpt-*", "claude-opus") {
		t.Error("gpt-* should not match claude-opus")
	}
}

func TestGlobMatchQuestion(t *testing.T) {
	if !GlobMatch("gpt-?", "gpt-5") {
		t.Error("gpt-? should match gpt-5")
	}
	if GlobMatch("gpt-?", "gpt-55") {
		t.Error("gpt-? should not match gpt-55")
	}
}

func TestGlobMatchEmpty(t *testing.T) {
	if GlobMatch("", "anything") {
		t.Error("empty pattern should not match")
	}
}

// ── Example file tests ──────────────────────────────────────────────────

func TestExamplePermissive(t *testing.T) {
	ps, err := LoadPolicySet(filepath.Join("..", "examples", "permissive.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if ps.Metadata.Name != "permissive" {
		t.Errorf("expected permissive, got %s", ps.Metadata.Name)
	}
	if ps.ContextFallbacks["scheduler"] != "background" {
		t.Errorf("expected scheduler->background fallback")
	}
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "view"})
	if v.Effect != EffectAllow {
		t.Errorf("view: expected allow, got %s", v.Effect)
	}
}

func TestExampleBalanced(t *testing.T) {
	ps, err := LoadPolicySet(filepath.Join("..", "examples", "balanced.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if ps.Metadata.Name != "balanced" {
		t.Errorf("expected balanced, got %s", ps.Metadata.Name)
	}
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "view", Risk: "low"})
	if v.Effect != EffectAllow {
		t.Errorf("low risk: expected allow, got %s", v.Effect)
	}
	v = engine.Evaluate(EvalContext{Tool: "bash", Mode: "background", Risk: "high"})
	if v.Effect != EffectDeny {
		t.Errorf("bg high: expected deny, got %s", v.Effect)
	}
	// Medium risk interactive -> filter
	v = engine.Evaluate(EvalContext{Tool: "edit", Mode: "interactive", Risk: "medium"})
	if v.Effect != EffectFilter {
		t.Errorf("interactive medium: expected filter, got %s", v.Effect)
	}
	// Medium risk background -> aitl
	v = engine.Evaluate(EvalContext{Tool: "edit", Mode: "background", Risk: "medium"})
	if v.Effect != EffectAITL {
		t.Errorf("bg medium: expected aitl, got %s", v.Effect)
	}
	// Scheduler falls back to background
	v = engine.Evaluate(EvalContext{Tool: "bash", Mode: "scheduler", Risk: "high"})
	if v.Effect != EffectDeny {
		t.Errorf("scheduler fallback: expected deny, got %s", v.Effect)
	}
}

func TestExampleRestrictive(t *testing.T) {
	ps, err := LoadPolicySet(filepath.Join("..", "examples", "restrictive.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if ps.Metadata.Name != "restrictive" {
		t.Errorf("expected restrictive, got %s", ps.Metadata.Name)
	}
	engine := NewPolicyEngine(ps)
	v := engine.Evaluate(EvalContext{Tool: "grep"})
	if v.Effect != EffectAllow {
		t.Errorf("grep: expected allow, got %s", v.Effect)
	}
	v = engine.Evaluate(EvalContext{Tool: "edit", Mode: "background", Risk: "medium"})
	if v.Effect != EffectDeny {
		t.Errorf("bg medium: expected deny, got %s", v.Effect)
	}
	// Interactive writes -> hitl
	v = engine.Evaluate(EvalContext{Tool: "edit", Mode: "interactive"})
	if v.Effect != EffectHITL {
		t.Errorf("interactive edit: expected hitl, got %s", v.Effect)
	}
	// Voice call -> pitl
	v = engine.Evaluate(EvalContext{Tool: "make_voice_call"})
	if v.Effect != EffectPITL {
		t.Errorf("voice call: expected pitl, got %s", v.Effect)
	}
}

// ── Ensure test file runs ───────────────────────────────────────────────

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
