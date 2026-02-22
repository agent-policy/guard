---
title: SDK Reference
nav_order: 6
---

# SDK Reference

Agent Policy ships identical evaluation semantics in Python, TypeScript, and Go. This page covers the API surface of each SDK.

<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">
  <img src="{{ '/assets/img/sdk-python.svg' | relative_url }}" alt="Python SDK" height="32" style="background:none;border:none;padding:0">
  <img src="{{ '/assets/img/sdk-typescript.svg' | relative_url }}" alt="TypeScript SDK" height="32" style="background:none;border:none;padding:0">
  <img src="{{ '/assets/img/sdk-go.svg' | relative_url }}" alt="Go SDK" height="32" style="background:none;border:none;padding:0">
</div>

## Core types

All three SDKs share the same conceptual types:

| Concept | Python | TypeScript | Go |
|---------|--------|------------|-----|
| Policy set | `PolicySet` | `PolicySet` | `PolicySet` |
| Single rule | `Policy` | `Policy` | `Policy` |
| Condition | `Condition` | `Condition` | `Condition` |
| Evaluation context | `EvalContext` | `EvalContext` | `EvalContext` |
| Result | `Verdict` | `Verdict` | `Verdict` |
| Engine | `PolicyEngine` | `PolicyEngine` | `PolicyEngine` |

---

## Python

**Package:** `agent_policy_guard`

### Loading

```python
from agent_policy_guard import load_policy_set, load_policy_set_from_str

# From file
ps = load_policy_set("policies.yaml")

# From string
ps = load_policy_set_from_str(yaml_string)
```

### Engine

```python
from agent_policy_guard import PolicyEngine, EvalContext

engine = PolicyEngine(ps)

# Full verdict
verdict = engine.evaluate(EvalContext(
    tool="bash",
    mode="background",
    model="gpt-4o",
    risk="high",
    channel="web",
    mcp_server="github-mcp-server",
    user="user-123",
    session="sess-abc",
))

verdict.effect       # Effect enum member (e.g., Effect.deny)
verdict.effect.value # Plain string (e.g., "deny")
verdict.channel      # Channel enum member
verdict.policy_id    # Matched policy ID or None

# Effect string only
action = engine.resolve(EvalContext(tool="bash", mode="background"))
# Returns: "deny"

# Debug: evaluate all policies
results = engine.evaluate_all(EvalContext(tool="bash"))
# Returns: [{"policy_id": "...", "matched": True/False, ...}, ...]
```

### Properties

```python
engine.policies           # list[Policy] sorted by priority
engine.defaults           # Defaults (effect, channel)
engine.context_fallbacks  # dict[str, str]
```

### EvalContext fields

All fields are optional strings. Omit fields you do not have at evaluation time.

| Field | Description |
|-------|-------------|
| `tool` | Tool name being invoked |
| `mode` | Execution mode (`interactive`, `background`, etc.) |
| `model` | Model identifier |
| `risk` | Risk level (`low`, `medium`, `high`, `critical`) |
| `channel` | Communication channel (input channel, not approval channel) |
| `mcp_server` | MCP server name |
| `user` | User identifier |
| `session` | Session identifier |

---

## TypeScript

**Package:** `@agent-policy/guard`

### Loading

```typescript
import { loadPolicySet, loadPolicySetFromString } from "@agent-policy/guard";

// From file
const ps = await loadPolicySet("policies.yaml");

// From string
const ps = loadPolicySetFromString(yamlString);
```

### Engine

```typescript
import {
  PolicyEngine,
  ALLOW, DENY, HITL, AITL, PITL, FILTER, ASK,
} from "@agent-policy/guard";

const engine = new PolicyEngine(ps);

// Full verdict
const verdict = engine.evaluate({
  tool: "bash",
  mode: "background",
  model: "gpt-4o",
  risk: "high",
  channel: "web",
  mcpServer: "github-mcp-server",
  user: "user-123",
  session: "sess-abc",
});

verdict.effect;    // string (e.g., "deny")
verdict.channel;   // string (e.g., "chat")
verdict.policyId;  // string or null

// Effect string only
const action = engine.resolve({ tool: "bash", mode: "background" });
// Returns: "deny"

// Debug: evaluate all policies
const results = engine.evaluateAll({ tool: "bash" });
```

### Properties

```typescript
engine.policies;          // Policy[]
engine.defaults;          // Defaults
engine.contextFallbacks;  // Record<string, string>
```

### Effect constants

```typescript
import { ALLOW, DENY, HITL, AITL, PITL, FILTER, ASK } from "@agent-policy/guard";
```

---

## Go

**Package:** `github.com/agent-policy/guard`

### Loading

```go
import guard "github.com/agent-policy/guard"

// From file
ps, err := guard.LoadPolicySet("policies.yaml")

// From bytes
ps, err := guard.LoadPolicySetFromBytes(data)
```

### Engine

```go
engine := guard.NewPolicyEngine(ps)

// Full verdict
v := engine.Evaluate(guard.EvalContext{
    Tool:      "bash",
    Mode:      "background",
    Model:     "gpt-4o",
    Risk:      "high",
    Channel:   "web",
    McpServer: "github-mcp-server",
    User:      "user-123",
    Session:   "sess-abc",
})

v.Effect    // guard.Effect (e.g., guard.EffectDeny)
v.Channel   // string
v.PolicyID  // string (empty if default)

// Effect string only
action := engine.Resolve(guard.EvalContext{Tool: "bash", Mode: "background"})
// Returns: "deny"

// Debug: evaluate all policies
results := engine.EvaluateAll(guard.EvalContext{Tool: "bash"})
```

### Properties

```go
engine.Policies()          // []Policy
engine.Defaults()          // Defaults
engine.ContextFallbacks()  // map[string]string
```

### Effect constants

```go
guard.EffectAllow   // "allow"
guard.EffectDeny    // "deny"
guard.EffectAsk     // "ask"
guard.EffectHITL    // "hitl"
guard.EffectAITL    // "aitl"
guard.EffectPITL    // "pitl"
guard.EffectFilter  // "filter"
```

---

## JSON Schema validation

Validate policy files against the schema at `spec/schema.json`:

```bash
# ajv-cli
ajv validate -s spec/schema.json -d policy.yaml

# check-jsonschema
check-jsonschema --schemafile spec/schema.json policy.yaml
```

The schema enforces structure (required fields, types, patterns) but does not restrict effect values -- any string is valid.

---

## Semantic guarantees

All three SDKs guarantee:

1. **Deterministic evaluation** -- same policy set + same context = same verdict.
2. **Priority ordering** -- policies evaluated in ascending priority order.
3. **First match wins** -- the first matching enabled policy ends evaluation.
4. **Context fallback chain** -- walked in order with cycle detection.
5. **Effect passthrough** -- any string effect in YAML is returned as-is.
