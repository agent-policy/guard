---
title: Getting Started
nav_order: 1
---

# Getting Started

Agent Policy is not yet published to any package registry. While the project is under active development, install directly from the Git repository.

{% include svg/getting-started-steps.svg %}

## Prerequisites

<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">
  <img src="{{ '/assets/img/sdk-python.svg' | relative_url }}" alt="Python 3.10+" height="32" style="background:none;border:none;padding:0">
  <img src="{{ '/assets/img/sdk-typescript.svg' | relative_url }}" alt="TypeScript / Node 18+" height="32" style="background:none;border:none;padding:0">
  <img src="{{ '/assets/img/sdk-go.svg' | relative_url }}" alt="Go 1.21+" height="32" style="background:none;border:none;padding:0">
</div>

## Installation

Clone the repository:

```bash
git clone https://github.com/agent-policy/guard.git
cd agent-policy
```

### Python

```bash
cd python
pip install -e .
```

For development (includes pytest and ruff):

```bash
pip install -e ".[dev]"
```

### TypeScript

```bash
cd typescript
npm install
```

To use it as a dependency in another project, reference the local path in your `package.json`:

```json
{
  "dependencies": {
    "@agent-policy/guard": "file:../path/to/agent-policy/typescript"
  }
}
```

### Go

```bash
# In your go.mod, use a replace directive pointing to the local clone:
# replace github.com/agent-policy/guard => ../path/to/agent-policy/go
go get github.com/agent-policy/guard
```

## Write your first policy

Create a file called `policy.yaml`:

```yaml
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: my-first-policy
defaults:
  effect: deny
policies:
  - id: allow-readonly
    name: Allow read-only tools
    priority: 10
    condition:
      tools: [view, grep, glob]
    effect: allow

  - id: approve-writes
    name: Require approval for write tools
    priority: 20
    condition:
      modes: [interactive]
      tools: [edit, create]
    effect: hitl
```

This policy:

- **Allows** read-only tools (`view`, `grep`, `glob`) with no intervention.
- **Requires human approval** for `edit` and `create` in interactive mode.
- **Denies** everything else by default.

## Evaluate at runtime

### Python

```python
from agent_policy_guard import PolicyEngine, EvalContext, load_policy_set

ps = load_policy_set("policy.yaml")
engine = PolicyEngine(ps)

# Read-only tool -> allow
v = engine.evaluate(EvalContext(tool="view"))
print(v.effect)      # Effect.allow
print(v.policy_id)   # "allow-readonly"

# Write tool, interactive -> hitl
v = engine.evaluate(EvalContext(tool="edit", mode="interactive"))
print(v.effect)      # Effect.hitl
print(v.policy_id)   # "approve-writes"

# Write tool, background -> deny (default)
v = engine.evaluate(EvalContext(tool="edit", mode="background"))
print(v.effect)      # Effect.deny
print(v.policy_id)   # None

# Use resolve() when you just need the effect string
action = engine.resolve(EvalContext(tool="edit", mode="interactive"))
print(action)        # "hitl"
```

### TypeScript

```typescript
import { PolicyEngine, loadPolicySet } from "@agent-policy/guard";

const ps = await loadPolicySet("policy.yaml");
const engine = new PolicyEngine(ps);

const v = engine.evaluate({ tool: "view" });
console.log(v.effect);    // "allow"
console.log(v.policyId);  // "allow-readonly"

const action = engine.resolve({ tool: "edit", mode: "interactive" });
console.log(action);      // "hitl"
```

### Go

```go
package main

import (
    "fmt"
    guard "github.com/agent-policy/guard"
)

func main() {
    ps, err := guard.LoadPolicySet("policy.yaml")
    if err != nil {
        panic(err)
    }
    engine := guard.NewPolicyEngine(ps)

    v := engine.Evaluate(guard.EvalContext{Tool: "view"})
    fmt.Println(v.Effect)    // allow
    fmt.Println(v.PolicyID)  // allow-readonly

    action := engine.Resolve(guard.EvalContext{Tool: "edit", Mode: "interactive"})
    fmt.Println(action)      // hitl
}
```

## Validate with JSON Schema

The repository includes a JSON Schema at `spec/schema.json`. Use it to validate policy files in CI:

```bash
# Using ajv-cli (npm install -g ajv-cli)
ajv validate -s spec/schema.json -d policy.yaml

# Using check-jsonschema (pip install check-jsonschema)
check-jsonschema --schemafile spec/schema.json policy.yaml
```

## Run the tests

```bash
# Python
cd python && pytest tests/ -v

# TypeScript
cd typescript && npx vitest run

# Go
cd go && go test -v ./...
```

## Next steps

- [Policy Language Reference]({% link policy-language.md %}) -- full YAML specification
- [Effects]({% link effects.md %}) -- extensible effect system and well-known values
- [Context Fallbacks]({% link context-fallbacks.md %}) -- mode-based fallback chains
- [Examples]({% link examples.md %}) -- ready-to-use policy sets for common scenarios
