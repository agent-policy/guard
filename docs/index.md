---
title: Home
layout: home
nav_order: 0
---

<p align="center">
  <img src="{{ '/assets/img/logo-wide.svg' | relative_url }}" alt="Agent Policy" width="260" style="background:none;border:none;padding:0">
</p>

# Agent Policy

A declarative policy language for controlling AI agent autonomy.
{: .fs-6 .fw-300 }

Agent Policy lets teams define guardrails that govern what an AI agent can do, when it needs human approval, and when it should be blocked entirely. Policies are written in YAML, version-controlled alongside code, and evaluated at runtime before every tool invocation.

[Get Started]({% link getting-started.md %}){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Policy Language]({% link policy-language.md %}){: .btn .fs-5 .mb-4 .mb-md-0 }

---

{% include svg/hero.svg %}

## How it works

1. **Write a policy** -- a YAML file that maps tools, execution modes, risk levels, and models to effects like `allow`, `deny`, `hitl`, or `filter`.
2. **Load the policy** into a `PolicyEngine` in your runtime -- available in Python, TypeScript, and Go.
3. **Evaluate before every tool call** -- the engine returns a verdict (effect + channel + matched policy ID) that your runtime dispatches on.

```yaml
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: my-guardrails
defaults:
  effect: hitl
policies:
  - id: allow-readonly
    priority: 10
    condition:
      tools: [view, grep, glob]
    effect: allow
  - id: deny-bg-infra
    priority: 20
    condition:
      modes: [background]
      tools: [bash, run, "mcp:github-*"]
    effect: deny
```

```python
from agent_policy_guard import PolicyEngine, EvalContext, load_policy_set

engine = PolicyEngine(load_policy_set("policy.yaml"))
action = engine.resolve(EvalContext(tool="bash", mode="background"))
# action == "deny"
```

## Key features

- **Extensible effects** -- `allow`, `deny`, `hitl`, `aitl`, `pitl`, `filter`, or any custom string your runtime understands.
- **Context fallbacks** -- map execution modes to fallback modes so policies compose without duplication.
- **Glob matching** -- use `*` and `?` patterns in tool names, models, users, and MCP servers.
- **Priority ordering** -- lower number wins, first match returns. Predictable, auditable evaluation.
- **Three SDKs** -- Python, TypeScript, and Go with identical semantics. Write policies once, evaluate anywhere.

<div class="sdk-badges" style="display:flex;gap:12px;flex-wrap:wrap;margin-top:8px">
  <img src="{{ '/assets/img/sdk-python.svg' | relative_url }}" alt="Python SDK" width="120" height="32">
  <img src="{{ '/assets/img/sdk-typescript.svg' | relative_url }}" alt="TypeScript SDK" width="140" height="32">
  <img src="{{ '/assets/img/sdk-go.svg' | relative_url }}" alt="Go SDK" width="120" height="32">
</div>
- **JSON Schema** -- validate policies in CI before they reach production.

{: .warning }
> Agent Policy is under active development. The library is not yet published to any package registry (PyPI, npm, or Go modules). Install from source via `git clone` for now. See [Getting Started]({% link getting-started.md %}) for details.
