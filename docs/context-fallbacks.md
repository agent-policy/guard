---
title: Context Fallbacks
nav_order: 4
---

# Context Fallbacks

Context fallbacks let you reuse policies across related execution modes without duplicating rules. When no policy matches a given mode, the engine retries evaluation with a fallback mode.

## The problem

Consider a system with several execution modes: `interactive`, `background`, `scheduler`, `bot_processor`, `realtime`. Many of these non-interactive modes should follow the same policies as `background`, but writing separate rules for each is tedious and error-prone:

```yaml
# Without fallbacks -- repetitive and fragile
policies:
  - id: deny-bg-high
    condition:
      modes: [background]
      risk: [high]
    effect: deny

  - id: deny-scheduler-high      # Same logic, different mode
    condition:
      modes: [scheduler]
      risk: [high]
    effect: deny

  - id: deny-bot-high            # Same logic again
    condition:
      modes: [bot_processor]
      risk: [high]
    effect: deny
```

## The solution

Declare a `context_fallbacks` map at the top level. The engine uses it to walk a fallback chain when no policy matches directly:

```yaml
context_fallbacks:
  scheduler: background
  bot_processor: background
  realtime: background

policies:
  - id: deny-bg-high
    condition:
      modes: [background]
      risk: [high]
    effect: deny
```

Now a tool invoked in `scheduler` mode with `high` risk will:

1. Try to match policies with `mode=scheduler`. No match.
2. Look up `scheduler` in `context_fallbacks` -- finds `background`.
3. Retry evaluation with `mode=background`. Matches `deny-bg-high`.
4. Return `effect: deny`.

One rule covers `background`, `scheduler`, `bot_processor`, and `realtime`.

## Multi-level chains

Fallbacks can chain multiple levels deep:

```yaml
context_fallbacks:
  cron: scheduler
  scheduler: background
```

A tool in `cron` mode will try: `cron` -> `scheduler` -> `background`.

## Cycle detection

The engine detects cycles and stops. If your fallback map contains `a -> b -> a`, the engine will try `a`, then `b`, see that `a` was already visited, and stop. It then falls through to defaults.

```yaml
# Safe -- the engine handles this gracefully
context_fallbacks:
  a: b
  b: a
```

## How it interacts with evaluation

The full evaluation flow:

1. Sort policies by priority.
2. Find the first enabled policy that matches the original context. If found, return its verdict.
3. If no match, check `context_fallbacks` for the current mode.
4. If a fallback exists, replace the mode in the context and re-evaluate (step 2).
5. Repeat until a match is found, the chain is exhausted, or a cycle is detected.
6. If still no match, return the defaults.

Only the `mode` field changes during fallback. All other context fields (tool, model, risk, user, etc.) remain the same.

## Accessing fallbacks programmatically

All three SDKs expose the loaded fallback map:

### Python

```python
engine = PolicyEngine(ps)
print(engine.context_fallbacks)
# {"scheduler": "background", "bot_processor": "background"}
```

### TypeScript

```typescript
const engine = new PolicyEngine(ps);
console.log(engine.contextFallbacks);
// { scheduler: "background", bot_processor: "background" }
```

### Go

```go
engine := guard.NewPolicyEngine(ps)
fmt.Println(engine.ContextFallbacks())
// map[scheduler:background bot_processor:background]
```

## Common patterns

### Non-interactive modes fall back to background

```yaml
context_fallbacks:
  scheduler: background
  bot_processor: background
  realtime: background
```

### Environment-specific chains

```yaml
context_fallbacks:
  staging: production
  preview: staging
```

A tool in `preview` mode inherits `staging` policies, which in turn inherit `production` policies.
