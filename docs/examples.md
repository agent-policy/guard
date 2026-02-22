---
title: Examples
nav_order: 5
---

# Example Policy Sets

The repository includes three ready-to-use policy sets in the `examples/` directory. Each is designed for a different trust and risk profile.

## Permissive

**File:** `examples/permissive.yaml`

For trusted environments with strong frontier models. Minimal friction -- most tools are auto-approved. Only background infrastructure tools and outbound phone calls require additional verification.

```yaml
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: permissive
  version: "1.0.0"
  labels:
    tier: "1"
    environment: development
defaults:
  effect: allow
  channel: chat
context_fallbacks:
  scheduler: background
  bot_processor: background
  realtime: background
policies:
  - id: allow-readonly
    name: Allow read-only tools everywhere
    priority: 10
    condition:
      tools: [view, grep, glob, list_scheduled_tasks, search_memories_tool]
    effect: allow

  - id: hitl-background-infra
    name: Require approval for background infra tools
    priority: 50
    condition:
      modes: [background]
      tools: ["mcp:github-*", "mcp:azure-*", bash, run]
    effect: hitl
    channel: chat

  - id: phone-verify-voice-calls
    name: Phone verify outbound voice calls
    priority: 30
    condition:
      tools: [make_voice_call]
    effect: pitl
    channel: phone
```

**What this policy does:**

| Scenario | Effect |
|----------|--------|
| Any read-only tool | `allow` |
| Interactive `bash` | `allow` (default) |
| Background `bash` | `hitl` |
| Background `mcp:github-issues` | `hitl` |
| `make_voice_call` | `pitl` (phone verification) |
| Anything else | `allow` (default) |

---

## Balanced

**File:** `examples/balanced.yaml`

For standard production deployments. Layered risk-based approach: low risk passes through, medium risk gets filtered or AI-reviewed depending on mode, high risk is denied in background and requires human approval in interactive.

```yaml
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: balanced
  version: "1.0.0"
  labels:
    tier: "2"
    environment: production
defaults:
  effect: hitl
  channel: chat
context_fallbacks:
  scheduler: background
  bot_processor: background
  realtime: background
policies:
  - id: allow-low-risk
    priority: 10
    condition:
      risk: [low]
    effect: allow

  - id: filter-interactive-medium
    priority: 20
    condition:
      modes: [interactive]
      risk: [medium]
    effect: filter

  - id: deny-background-high
    priority: 30
    condition:
      modes: [background]
      risk: [high]
    effect: deny

  - id: hitl-interactive-high
    priority: 40
    condition:
      modes: [interactive]
      risk: [high]
    effect: hitl
    channel: chat

  - id: aitl-background-medium
    priority: 50
    condition:
      modes: [background]
      risk: [medium]
    effect: aitl

  - id: phone-verify-calls
    priority: 25
    condition:
      tools: [make_voice_call]
    effect: pitl
    channel: phone
```

**What this policy does:**

| Scenario | Effect |
|----------|--------|
| Low risk, any mode | `allow` |
| Medium risk, interactive | `filter` (content safety) |
| Medium risk, background | `aitl` (AI review) |
| High risk, interactive | `hitl` (human approval) |
| High risk, background | `deny` |
| `make_voice_call` | `pitl` (phone verification) |
| Scheduler, high risk | `deny` (falls back to background) |
| Anything else | `hitl` (default) |

---

## Restrictive

**File:** `examples/restrictive.yaml`

For high-security environments or less capable models. Default deny -- only explicitly allowed tools pass through. All writes and executions require human approval in interactive mode and are denied in background.

```yaml
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: restrictive
  version: "1.0.0"
  labels:
    tier: "3"
    environment: production
defaults:
  effect: deny
  channel: chat
context_fallbacks:
  scheduler: background
  bot_processor: background
  realtime: background
policies:
  - id: allow-readonly
    priority: 10
    condition:
      tools: [view, grep, glob, list_scheduled_tasks, search_memories_tool]
    effect: allow

  - id: allow-low-risk-interactive
    priority: 15
    condition:
      modes: [interactive]
      risk: [low]
    effect: allow

  - id: deny-background-writes
    priority: 20
    condition:
      modes: [background]
      risk: [medium, high]
    effect: deny

  - id: phone-verify-calls
    priority: 25
    condition:
      tools: [make_voice_call]
    effect: pitl
    channel: phone

  - id: hitl-interactive-writes
    priority: 30
    condition:
      modes: [interactive]
      tools: [create, edit]
    effect: hitl

  - id: hitl-interactive-terminal
    priority: 35
    condition:
      modes: [interactive]
      tools: [bash, run]
    effect: hitl

  - id: hitl-interactive-mcp
    priority: 40
    condition:
      modes: [interactive]
      mcp_servers: ["*"]
    effect: hitl
```

**What this policy does:**

| Scenario | Effect |
|----------|--------|
| Read-only tools | `allow` |
| Low risk, interactive | `allow` |
| Medium/high risk, background | `deny` |
| `edit` / `create`, interactive | `hitl` |
| `bash` / `run`, interactive | `hitl` |
| Any MCP server, interactive | `hitl` |
| `make_voice_call` | `pitl` |
| Anything else | `deny` (default) |

---

## Choosing a policy set

| Factor | Permissive | Balanced | Restrictive |
|--------|-----------|----------|-------------|
| Model trust | High (frontier) | Standard | Low / untrusted |
| Environment | Development | Production | High-security |
| Default effect | `allow` | `hitl` | `deny` |
| Background autonomy | High | Medium | None |
| Approval friction | Low | Medium | High |

Start with `balanced` for most deployments. Move to `permissive` once you have confidence in the model and tooling. Use `restrictive` for sensitive environments or when onboarding a new model.

## Customizing

These examples are starting points. Fork and adapt:

- Add model-specific rules with `models: [gpt-*]` conditions.
- Scope policies to specific users with `users: [admin-*]`.
- Add your own custom effects for organization-specific approval workflows.
- Adjust priorities to change which rules take precedence.
