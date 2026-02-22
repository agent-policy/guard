---
title: Effects
nav_order: 3
---

# Effects

Effects define what happens when a policy matches. Agent Policy treats effects as **extensible strings** -- you can use any value your runtime knows how to dispatch.

{% include svg/effects.svg %}

## Well-known effects

These effects are provided as constants in every SDK and cover the most common agent governance patterns:

| Effect | Constant (Python / TS / Go) | Description |
|--------|-----------------------------|-------------|
| `allow` | `Effect.allow` / `ALLOW` / `EffectAllow` | Auto-approve. The tool runs without any intervention. |
| `deny` | `Effect.deny` / `DENY` / `EffectDeny` | Block. The tool invocation is rejected. |
| `hitl` | `Effect.hitl` / `HITL` / `EffectHITL` | Human-in-the-loop. A human must approve before execution. |
| `aitl` | `Effect.aitl` / `AITL` / `EffectAITL` | AI-in-the-loop. An AI reviewer evaluates the invocation. |
| `pitl` | `Effect.pitl` / `PITL` / `EffectPITL` | Phone-in-the-loop. Verification via outbound phone call. |
| `filter` | `Effect.filter` / `FILTER` / `EffectFilter` | Content safety filter. Run a safety check (e.g., Prompt Shield) before execution. |
| `ask` | `Effect.ask` / `ASK` / `EffectAsk` | Alias for `hitl`. Provided for backward compatibility. |

## Custom effects

Effects are not limited to the values above. If your system has a verification strategy the well-known effects do not cover, use it directly in YAML:

```yaml
policies:
  - id: require-manager-approval
    priority: 30
    condition:
      risk: [critical]
    effect: manager-approval

  - id: require-mfa
    priority: 25
    condition:
      tools: [deploy-production]
    effect: mfa-verification

  - id: audit-only
    priority: 10
    condition:
      modes: [background]
      risk: [low]
    effect: audit-log
```

The engine returns the effect string as-is. Your runtime dispatches on it:

### Python

```python
from agent_policy_guard import PolicyEngine, EvalContext, Effect

# Custom effects work through the Effect enum's extensibility
verdict = engine.evaluate(EvalContext(tool="deploy-production"))

match verdict.effect.value:
    case "allow":
        execute_tool(ctx)
    case "deny":
        reject(ctx)
    case "hitl":
        request_human_approval(ctx)
    case "manager-approval":
        request_manager_sign_off(ctx)
    case "mfa-verification":
        trigger_mfa_flow(ctx)
    case _:
        raise ValueError(f"Unknown effect: {verdict.effect.value}")

# Or use resolve() for cleaner dispatch
action = engine.resolve(EvalContext(tool="deploy-production"))
dispatch_table[action](ctx)
```

### TypeScript

```typescript
import { PolicyEngine, ALLOW, DENY, HITL } from "@agent-policy/guard";

const action = engine.resolve({ tool: "deploy-production" });

const handlers: Record<string, (ctx: Context) => void> = {
  [ALLOW]: (ctx) => executeTool(ctx),
  [DENY]: (ctx) => reject(ctx),
  [HITL]: (ctx) => requestApproval(ctx),
  "manager-approval": (ctx) => requestManagerSignOff(ctx),
  "mfa-verification": (ctx) => triggerMfaFlow(ctx),
};

handlers[action]?.(ctx) ?? throwUnknownEffect(action);
```

### Go

```go
action := engine.Resolve(guard.EvalContext{Tool: "deploy-production"})

switch action {
case string(guard.EffectAllow):
    executeTool(ctx)
case string(guard.EffectDeny):
    reject(ctx)
case string(guard.EffectHITL):
    requestApproval(ctx)
case "manager-approval":
    requestManagerSignOff(ctx)
default:
    return fmt.Errorf("unknown effect: %s", action)
}
```

## The `resolve()` method

Every SDK provides a `resolve()` method that returns just the effect as a plain string. This is the recommended way to integrate with systems that dispatch on strings:

| SDK | Method | Returns |
|-----|--------|---------|
| Python | `engine.resolve(ctx)` | `str` (e.g., `"hitl"`) |
| TypeScript | `engine.resolve(ctx)` | `string` |
| Go | `engine.Resolve(ctx)` | `string` |

Use `resolve()` when you only need the effect. Use `evaluate()` when you also need the channel, matched policy ID, or want to inspect the full verdict.

## Design rationale

Effects are strings rather than a fixed enum so that the policy language can evolve alongside your system. If you add a new approval strategy to your runtime next month, you can use it in policy YAML immediately -- no library upgrade required.

The well-known constants exist for ergonomics and IDE autocompletion, but they are not enforced during evaluation. The engine is intentionally permissive: it evaluates conditions and returns whatever effect string the matched policy declares.
