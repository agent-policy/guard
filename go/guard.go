// Package guard provides a declarative guardrail policy engine
// for controlling AI agent autonomy.
//
// Policies are defined in YAML using a schema inspired by Azure Policy but
// tailored for agent guardrails.  The engine evaluates tool invocations
// against a PolicySet and returns a Verdict (allow / deny / ask).
package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// ── Effects & Channels ─────────────────────────────────────────────────

// Effect represents the action to take when a policy matches.
// Well-known effects are provided as constants. Custom string values
// are supported for extensibility.
type Effect string

const (
	EffectAllow  Effect = "allow"
	EffectDeny   Effect = "deny"
	EffectAsk    Effect = "ask"
	EffectHITL   Effect = "hitl"
	EffectPITL   Effect = "pitl"
	EffectAITL   Effect = "aitl"
	EffectFilter Effect = "filter"
)

// Channel represents how the user should be asked for approval.
type Channel string

const (
	ChannelChat  Channel = "chat"
	ChannelPhone Channel = "phone"
)

// ── Data models ────────────────────────────────────────────────────────

// EvalContext is the runtime snapshot for a single tool invocation.
type EvalContext struct {
	Mode      string
	Model     string
	Channel   string
	Tool      string
	McpServer string
	Risk      string
	User      string
	Session   string
}

// Condition defines matching criteria for a policy.
// All specified fields must match (AND). Each field list uses OR logic.
// Nil means "don't care".
type Condition struct {
	Modes      []string `yaml:"modes,omitempty"      json:"modes,omitempty"`
	Models     []string `yaml:"models,omitempty"     json:"models,omitempty"`
	Channels   []string `yaml:"channels,omitempty"   json:"channels,omitempty"`
	Tools      []string `yaml:"tools,omitempty"      json:"tools,omitempty"`
	McpServers []string `yaml:"mcp_servers,omitempty" json:"mcp_servers,omitempty"`
	Risk       []string `yaml:"risk,omitempty"       json:"risk,omitempty"`
	Users      []string `yaml:"users,omitempty"      json:"users,omitempty"`
	Sessions   []string `yaml:"sessions,omitempty"   json:"sessions,omitempty"`
}

// Policy is a single guardrail policy.
type Policy struct {
	ID          string    `yaml:"id"                   json:"id"`
	Effect      Effect    `yaml:"effect"               json:"effect"`
	Name        string    `yaml:"name,omitempty"       json:"name,omitempty"`
	Description string    `yaml:"description,omitempty" json:"description,omitempty"`
	Enabled     *bool     `yaml:"enabled,omitempty"    json:"enabled,omitempty"`
	Priority    int       `yaml:"priority,omitempty"   json:"priority,omitempty"`
	Condition   Condition `yaml:"condition,omitempty"  json:"condition,omitempty"`
	Channel     Channel   `yaml:"channel,omitempty"    json:"channel,omitempty"`
}

// IsEnabled returns whether the policy is active.
func (p *Policy) IsEnabled() bool {
	if p.Enabled == nil {
		return true
	}
	return *p.Enabled
}

// Metadata holds descriptive information about a PolicySet.
type Metadata struct {
	Name        string            `yaml:"name"                 json:"name"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Version     string            `yaml:"version,omitempty"    json:"version,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"     json:"labels,omitempty"`
}

// Defaults defines fallback behaviour when no policy matches.
type Defaults struct {
	Effect  Effect  `yaml:"effect,omitempty"  json:"effect,omitempty"`
	Channel Channel `yaml:"channel,omitempty" json:"channel,omitempty"`
}

// PolicySet is a complete set of guardrail policies loaded from YAML.
type PolicySet struct {
	APIVersion       string            `yaml:"apiVersion" json:"apiVersion"`
	Kind             string            `yaml:"kind"       json:"kind"`
	Metadata         Metadata          `yaml:"metadata"   json:"metadata"`
	Defaults         Defaults          `yaml:"defaults"   json:"defaults"`
	Policies         []Policy          `yaml:"policies"   json:"policies"`
	ContextFallbacks map[string]string `yaml:"context_fallbacks,omitempty" json:"context_fallbacks,omitempty"`
}

// Verdict is the result of evaluating a context against a policy set.
type Verdict struct {
	Effect   Effect
	Channel  Channel
	PolicyID string // empty when no policy matched
}

// ── Glob matching ──────────────────────────────────────────────────────

// GlobMatch matches a value against a glob pattern.
// Supports *, ?, and exact matching.
func GlobMatch(pattern, value string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	matched, err := filepath.Match(pattern, value)
	if err != nil {
		return pattern == value
	}
	return matched
}

// listMatches returns true if patterns is nil (don't care) or any pattern matches.
func listMatches(patterns []string, value string) bool {
	if patterns == nil {
		return true
	}
	for _, p := range patterns {
		if GlobMatch(p, value) {
			return true
		}
	}
	return false
}

// ── Condition matching ─────────────────────────────────────────────────

func conditionMatches(cond Condition, ctx EvalContext) bool {
	if !listMatches(cond.Modes, ctx.Mode) {
		return false
	}
	if !listMatches(cond.Models, ctx.Model) {
		return false
	}
	if !listMatches(cond.Channels, ctx.Channel) {
		return false
	}
	if !listMatches(cond.Tools, ctx.Tool) {
		return false
	}
	if !listMatches(cond.Risk, ctx.Risk) {
		return false
	}
	if !listMatches(cond.Users, ctx.User) {
		return false
	}
	if !listMatches(cond.Sessions, ctx.Session) {
		return false
	}

	// mcp_servers: if patterns specified but no McpServer in context -> no match
	if cond.McpServers != nil {
		if ctx.McpServer == "" {
			return false
		}
		if !listMatches(cond.McpServers, ctx.McpServer) {
			return false
		}
	}

	return true
}

// ── Loader ─────────────────────────────────────────────────────────────

// LoadPolicySetFromBytes parses a PolicySet from YAML bytes.
func LoadPolicySetFromBytes(data []byte) (*PolicySet, error) {
	var ps PolicySet
	if err := yaml.Unmarshal(data, &ps); err != nil {
		return nil, fmt.Errorf("guard: failed to parse YAML: %w", err)
	}
	if ps.Kind != "" && ps.Kind != "PolicySet" {
		return nil, fmt.Errorf("guard: unsupported kind %q (expected PolicySet)", ps.Kind)
	}
	// Apply defaults
	if ps.APIVersion == "" {
		ps.APIVersion = "agent-policy/v1"
	}
	if ps.Kind == "" {
		ps.Kind = "PolicySet"
	}
	if ps.Defaults.Effect == "" {
		ps.Defaults.Effect = EffectAsk
	}
	if ps.Defaults.Channel == "" {
		ps.Defaults.Channel = ChannelChat
	}
	for i := range ps.Policies {
		if ps.Policies[i].Channel == "" {
			ps.Policies[i].Channel = ChannelChat
		}
		if ps.Policies[i].Priority == 0 {
			ps.Policies[i].Priority = 100
		}
	}
	return &ps, nil
}

// LoadPolicySet loads a PolicySet from a YAML file on disk.
func LoadPolicySet(path string) (*PolicySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("guard: failed to read %s: %w", path, err)
	}
	return LoadPolicySetFromBytes(data)
}

// ── Engine ─────────────────────────────────────────────────────────────

// PolicyEngine evaluates tool invocations against a PolicySet.
type PolicyEngine struct {
	defaults         Defaults
	policies         []Policy
	contextFallbacks map[string]string
}

// NewPolicyEngine creates a new engine, optionally loading a PolicySet.
func NewPolicyEngine(ps *PolicySet) *PolicyEngine {
	e := &PolicyEngine{
		defaults:         Defaults{Effect: EffectAsk, Channel: ChannelChat},
		contextFallbacks: make(map[string]string),
	}
	if ps != nil {
		e.Load(ps)
	}
	return e
}

// Load replaces the active policy set.
func (e *PolicyEngine) Load(ps *PolicySet) {
	e.defaults = ps.Defaults
	e.policies = make([]Policy, len(ps.Policies))
	copy(e.policies, ps.Policies)
	sort.Slice(e.policies, func(i, j int) bool {
		return e.policies[i].Priority < e.policies[j].Priority
	})
	e.contextFallbacks = make(map[string]string)
	for k, v := range ps.ContextFallbacks {
		e.contextFallbacks[k] = v
	}
}

// Policies returns the currently loaded policies (sorted by priority).
func (e *PolicyEngine) Policies() []Policy {
	out := make([]Policy, len(e.policies))
	copy(out, e.policies)
	return out
}

// Evaluate returns a Verdict for the given context.
// It walks the context fallback chain when no policy matches the
// original mode.
func (e *PolicyEngine) Evaluate(ctx EvalContext) Verdict {
	if v, ok := e.evaluateOnce(ctx); ok {
		return v
	}

	// Walk the context fallback chain
	mode := ctx.Mode
	visited := map[string]bool{mode: true}
	for {
		next, exists := e.contextFallbacks[mode]
		if !exists {
			break
		}
		if visited[next] {
			break
		}
		visited[next] = true
		mode = next
		fallback := ctx
		fallback.Mode = mode
		if v, ok := e.evaluateOnce(fallback); ok {
			return v
		}
	}

	return Verdict{
		Effect:  e.defaults.Effect,
		Channel: e.defaults.Channel,
	}
}

// Resolve is a convenience method returning just the effect string.
func (e *PolicyEngine) Resolve(ctx EvalContext) string {
	return string(e.Evaluate(ctx).Effect)
}

// evaluateOnce tries to match a policy for a single context (no fallback).
func (e *PolicyEngine) evaluateOnce(ctx EvalContext) (Verdict, bool) {
	for _, p := range e.policies {
		if !p.IsEnabled() {
			continue
		}
		if conditionMatches(p.Condition, ctx) {
			return Verdict{
				Effect:   p.Effect,
				Channel:  p.Channel,
				PolicyID: p.ID,
			}, true
		}
	}
	return Verdict{}, false
}

// Defaults returns the fallback effect and channel.
func (e *PolicyEngine) Defaults() Defaults {
	return e.defaults
}

// ContextFallbacks returns the context fallback chain.
func (e *PolicyEngine) ContextFallbacks() map[string]string {
	out := make(map[string]string, len(e.contextFallbacks))
	for k, v := range e.contextFallbacks {
		out[k] = v
	}
	return out
}

// MatchResult describes whether a single policy matched.
type MatchResult struct {
	PolicyID string
	Name     string
	Priority int
	Effect   Effect
	Matched  bool
	Enabled  bool
}

// EvaluateAll returns match results for every policy. Useful for debugging.
func (e *PolicyEngine) EvaluateAll(ctx EvalContext) []MatchResult {
	results := make([]MatchResult, 0, len(e.policies))
	for _, p := range e.policies {
		enabled := p.IsEnabled()
		matched := enabled && conditionMatches(p.Condition, ctx)
		results = append(results, MatchResult{
			PolicyID: p.ID,
			Name:     p.Name,
			Priority: p.Priority,
			Effect:   p.Effect,
			Matched:  matched,
			Enabled:  enabled,
		})
	}
	return results
}
