# Agent Policy

A declarative policy language for controlling AI agent autonomy.

Agent Policy lets teams define guardrails that govern what an AI agent can do, when it needs human approval, and when it should be blocked entirely. Policies are written in YAML, version-controlled alongside code, and evaluated at runtime before every tool invocation.

The `guard` library -- available in Python, TypeScript, and Go -- is the evaluation engine that loads these policies and returns verdicts.

## Why

Autonomous agents act on behalf of users: merging PRs, running shell commands, calling APIs, making phone calls. Without guardrails, a single misconfigured tool can cause real damage. Agent Policy provides a single, auditable place to express the rules -- no scattered if-statements, no hard-coded checks.

- **Deny** dangerous operations outright (infrastructure changes in background mode).
- **Allow** safe, read-only tools without friction.
- **Require approval** through the verification strategy that fits your system -- human-in-the-loop, AI-in-the-loop, phone verification, content safety filters, or your own custom mechanism.

## Quick start

**1. Write a policy**

```yaml
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: production-guardrails
defaults:
  effect: hitl
  channel: chat
context_fallbacks:
  scheduler: background
  bot_processor: background
policies:
  - id: allow-readonly
    name: Allow read-only tools
    priority: 10
    condition:
      tools: [view, grep, glob]
    effect: allow

  - id: deny-background-infra
    name: Deny infra tools in background
    priority: 20
    condition:
      modes: [background]
      tools: ["mcp:github-*", "mcp:azure-*", bash, run]
    effect: deny

  - id: filter-medium-risk
    name: Run content safety filter on medium-risk tools
    priority: 25
    condition:
      modes: [interactive]
      risk: [medium]
    effect: filter

  - id: phone-verify-calls
    name: Phone verify outbound calls
    priority: 15
    condition:
      tools: [make_voice_call]
    effect: pitl
    channel: phone
```

**2. Evaluate at runtime**

Python:

```python
from agent_policy_guard import PolicyEngine, EvalContext, load_policy_set

ps = load_policy_set("policies.yaml")
engine = PolicyEngine(ps)

verdict = engine.evaluate(EvalContext(
    tool="bash",
    mode="background",
    model="gpt-5.2",
    risk="high",
))
# verdict.effect = "deny"
# verdict.policy_id = "deny-background-infra"

# Or use resolve() to get just the effect string for dispatch:
action = engine.resolve(EvalContext(tool="edit", mode="interactive", risk="medium"))
# action == "filter"
```

TypeScript:

```typescript
import { PolicyEngine, loadPolicySet } from "@agent-policy/guard";

const ps = await loadPolicySet("policies.yaml");
const engine = new PolicyEngine(ps);

const verdict = engine.evaluate({
  tool: "bash",
  mode: "background",
  model: "gpt-5.2",
  risk: "high",
});
// verdict.effect === "deny"

const action = engine.resolve({ tool: "edit", mode: "interactive", risk: "medium" });
// action === "filter"
```

Go:

```go
import guard "github.com/agent-policy/guard"

ps, _ := guard.LoadPolicySet("policies.yaml")
engine := guard.NewPolicyEngine(ps)

v := engine.Evaluate(guard.EvalContext{
    Tool:  "bash",
    Mode:  "background",
    Model: "gpt-5.2",
    Risk:  "high",
})
// v.Effect == guard.EffectDeny

action := engine.Resolve(guard.EvalContext{Tool: "edit", Mode: "interactive", Risk: "medium"})
// action == "filter"
```

## Policy language reference

### Top-level structure

| Field | Required | Description |
|-------|----------|-------------|
| `apiVersion` | Yes | Must be `agent-policy/v1` |
| `kind` | Yes | Must be `PolicySet` |
| `metadata` | Yes | Name, description, version, labels |
| `defaults` | No | Fallback effect and channel when no policy matches |
| `context_fallbacks` | No | Map of execution mode to fallback mode (see below) |
| `policies` | Yes | Ordered list of policy rules |

### Policy fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | Yes | -- | Unique identifier (kebab-case) |
| `effect` | Yes | -- | Any effect string (see Effects below) |
| `name` | No | `""` | Human-readable name |
| `description` | No | `""` | Explanation |
| `enabled` | No | `true` | Whether this policy is active |
| `priority` | No | `100` | Lower number = higher priority. First match wins |
| `condition` | No | match-all | Matching criteria |
| `channel` | No | `chat` | Approval channel: `chat` or `phone` |

### Effects

Effects are **extensible strings**. You can use any value that your runtime knows how to dispatch. The following well-known effects are provided as constants in every SDK:

| Effect | Description |
|--------|-------------|
| `allow` | Auto-approve -- the tool runs without intervention |
| `deny` | Block -- the tool invocation is rejected |
| `hitl` | Human-in-the-loop -- require human approval before execution |
| `aitl` | AI-in-the-loop -- an AI reviewer evaluates the invocation |
| `pitl` | Phone-in-the-loop -- require phone-based verification |
| `filter` | Content safety filter -- run a safety check (e.g. Prompt Shield) |
| `ask` | Alias for `hitl` (backward compatibility) |

Custom effects work out of the box. If your system has a `"manager-approval"` strategy, use it directly in YAML:

```yaml
effect: manager-approval
```

The evaluation engine returns it as-is. Your runtime dispatches on the string.

### Condition fields

All condition fields use AND logic across fields and OR logic within each field's list. Glob patterns (`*`, `?`) are supported for string matching.

| Field | Description |
|-------|-------------|
| `modes` | Execution modes: `interactive`, `background`, `voice`, `api` |
| `models` | Model name patterns: `gpt-*`, `claude-sonnet-*` |
| `channels` | Communication channels: `web`, `teams`, `telegram`, `slack` |
| `tools` | Tool name patterns: `bash`, `mcp:github-*`, `skill:web-*` |
| `mcp_servers` | MCP server name patterns |
| `risk` | Risk levels: `low`, `medium`, `high`, `critical` |
| `users` | User ID patterns |
| `sessions` | Session ID patterns |

### Context fallbacks

When the engine evaluates a context and no policy matches, it can try a fallback mode before resorting to defaults. This lets you define policies for broad categories (like `background`) and have specific modes (like `scheduler` or `bot_processor`) inherit those policies automatically.

```yaml
context_fallbacks:
  scheduler: background
  bot_processor: background
  realtime: background
```

With this configuration, a tool invoked in `scheduler` mode first evaluates against policies that match `scheduler`. If none match, the engine retries with `background` as the mode. Chains are supported (`a -> b -> c`) with cycle detection.

### Evaluation logic

1. Policies are sorted by `priority` (ascending).
2. The first enabled policy whose condition matches returns its effect.
3. If no policy matches and a `context_fallback` exists for the current mode, the engine retries with the fallback mode.
4. If nothing matches after all fallbacks, `defaults` apply.

## Installation

**Python** (PyPI)
```bash
pip install agent-policy-guard
```

**TypeScript** (npm)
```bash
npm install @agent-policy/guard
```

**Go**
```bash
go get github.com/agent-policy/guard
```

## Examples

The [examples/](examples/) directory contains ready-to-use policy sets:

- [permissive.yaml](examples/permissive.yaml) -- Minimal friction for trusted environments
- [balanced.yaml](examples/balanced.yaml) -- Standard production deployment
- [restrictive.yaml](examples/restrictive.yaml) -- High-security lockdown

## Schema

The JSON Schema for policy validation is at [spec/schema.json](spec/schema.json). Use it with any YAML/JSON validator to catch policy errors before deployment.

## Development

The `guard` evaluation engine is implemented in three languages. Each has its own test suite:

```bash
# Python
cd python && pip install -e ".[dev]" && pytest tests/ -v

# TypeScript
cd typescript && npm install && npx vitest run

# Go
cd go && go test -v ./...
```

## License

MIT
