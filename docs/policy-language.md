---
title: Policy Language
nav_order: 2
---

# Policy Language Reference

Agent Policy uses a YAML-based policy language inspired by Kubernetes resource definitions. Every policy file is a `PolicySet` -- a collection of ordered rules evaluated against a runtime context.

## Top-level structure

```yaml
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: my-policy
  description: Human-readable description
  version: "1.0.0"
  labels:
    environment: production
    tier: "2"
defaults:
  effect: hitl
  channel: chat
context_fallbacks:
  scheduler: background
  bot_processor: background
policies:
  - id: rule-1
    # ...
```

| Field | Required | Description |
|-------|----------|-------------|
| `apiVersion` | Yes | Must be `agent-policy/v1`. |
| `kind` | Yes | Must be `PolicySet`. |
| `metadata` | Yes | Name (required), description, version, and labels. |
| `defaults` | No | Fallback effect and channel when no policy matches. Defaults to `effect: ask`, `channel: chat`. |
| `context_fallbacks` | No | Map of execution mode to fallback mode. See [Context Fallbacks]({% link context-fallbacks.md %}). |
| `policies` | Yes | Ordered list of policy rules. |

## Metadata

```yaml
metadata:
  name: production-guardrails      # Required
  description: >                   # Optional
    Guardrails for the production deployment.
  version: "2.1.0"                 # Optional, semver recommended
  labels:                          # Optional key-value pairs
    environment: production
    team: platform
```

Labels are freeform strings. They are stored but not used in evaluation -- use them for filtering, documentation, or tooling.

## Policy rules

Each policy is evaluated independently. The engine sorts policies by `priority` (ascending) and returns the first match.

```yaml
policies:
  - id: allow-readonly
    name: Allow read-only tools
    description: Safe tools that cannot modify state
    enabled: true
    priority: 10
    condition:
      tools: [view, grep, glob]
    effect: allow

  - id: deny-bg-infra
    name: Deny infrastructure tools in background
    priority: 20
    condition:
      modes: [background]
      tools: ["mcp:github-*", "mcp:azure-*", bash]
    effect: deny
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | Yes | -- | Unique identifier. Kebab-case or snake_case, must match `^[a-z0-9][a-z0-9_-]*$`. |
| `effect` | Yes | -- | The action to take. Any string -- see [Effects]({% link effects.md %}). |
| `name` | No | `""` | Human-readable name. |
| `description` | No | `""` | Explanation of intent. |
| `enabled` | No | `true` | Set to `false` to skip this policy without removing it. |
| `priority` | No | `100` | Integer 0--9999. Lower number = higher priority. |
| `condition` | No | match-all | Criteria that must match for this policy to fire. Omit to match everything. |
| `channel` | No | `chat` | Approval channel override: `chat` or `phone`. |

## Conditions

Conditions define when a policy fires. All specified fields must match (AND logic across fields). Each field's list uses OR logic -- at least one value must match.

```yaml
condition:
  modes: [interactive, voice]
  tools: ["mcp:github-*", bash]
  risk: [high, critical]
```

{% include svg/condition-logic.svg %}

This condition matches when: (mode is `interactive` OR `voice`) AND (tool matches `mcp:github-*` OR `bash`) AND (risk is `high` OR `critical`).

| Field | Description | Example values |
|-------|-------------|----------------|
| `modes` | Execution mode | `interactive`, `background`, `voice`, `api` |
| `models` | Model name (glob) | `gpt-*`, `claude-sonnet-*`, `o3-*` |
| `channels` | Communication channel | `web`, `teams`, `telegram`, `slack`, `voice` |
| `tools` | Tool name (glob) | `bash`, `mcp:github-*`, `skill:web-*` |
| `mcp_servers` | MCP server name (glob) | `github-mcp-server`, `azure-*` |
| `risk` | Risk level | `low`, `medium`, `high`, `critical` |
| `users` | User ID (glob) | `admin-*`, `user-12345` |
| `sessions` | Session ID (glob) | `sess-prod-*` |

Omitting a field means "match any value" for that dimension.

### Glob patterns

String fields support glob-style patterns:

| Pattern | Matches |
|---------|---------|
| `*` | Everything |
| `mcp:github-*` | `mcp:github-issues`, `mcp:github-pulls`, etc. |
| `gpt-?` | `gpt-4`, `gpt-5`, but not `gpt-4o` |
| `bash` | Exact match: `bash` only |

## Evaluation logic

1. Policies are sorted by `priority` (ascending).
2. Disabled policies (`enabled: false`) are skipped.
3. The first enabled policy whose condition matches the context returns its effect, channel, and policy ID as a **verdict**.
4. If no policy matches and a `context_fallback` exists for the current mode, the engine retries with the fallback mode. See [Context Fallbacks]({% link context-fallbacks.md %}).
5. If nothing matches after all fallbacks, the `defaults` apply.

The evaluation is deterministic: same policy set + same context = same verdict.

## Defaults

```yaml
defaults:
  effect: hitl
  channel: chat
```

When no policy matches (including after fallback), the engine returns a verdict with the default effect and channel. If `defaults` is omitted, the engine defaults to `effect: ask`, `channel: chat`.

## Putting it together

A complete policy file:

```yaml
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: production
  version: "1.0.0"
defaults:
  effect: hitl
  channel: chat
context_fallbacks:
  scheduler: background
  bot_processor: background
policies:
  - id: allow-readonly
    priority: 10
    condition:
      tools: [view, grep, glob]
    effect: allow

  - id: filter-medium-interactive
    priority: 20
    condition:
      modes: [interactive]
      risk: [medium]
    effect: filter

  - id: aitl-medium-background
    priority: 30
    condition:
      modes: [background]
      risk: [medium]
    effect: aitl

  - id: deny-high-background
    priority: 40
    condition:
      modes: [background]
      risk: [high]
    effect: deny

  - id: phone-verify-calls
    priority: 15
    condition:
      tools: [make_voice_call]
    effect: pitl
    channel: phone
```
