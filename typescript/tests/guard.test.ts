import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AITL,
  FILTER,
  HITL,
  PITL,
  PolicyEngine,
  globMatch,
  listMatches,
  loadPolicySet,
  loadPolicySetFromStr,
} from "../src/index.js";
import type {
  Condition,
  EvalContext,
  Policy,
  PolicySet,
} from "../src/index.js";

// ── Helpers ──────────────────────────────────────────────────────────────

function makePolicySet(
  policies: Policy[],
  defaultEffect: "allow" | "deny" | "ask" = "ask",
): PolicySet {
  return {
    metadata: { name: "test" },
    defaults: { effect: defaultEffect, channel: "chat" },
    policies,
  };
}

// ── Engine tests ─────────────────────────────────────────────────────────

describe("PolicyEngine basics", () => {
  it("empty policies returns default", () => {
    const engine = new PolicyEngine(makePolicySet([], "deny"));
    const v = engine.evaluate({ tool: "bash" });
    expect(v.effect).toBe("deny");
    expect(v.policyId).toBeNull();
  });

  it("single allow policy matches", () => {
    const ps = makePolicySet([
      { id: "p1", effect: "allow", condition: { tools: ["bash"] } },
    ]);
    const engine = new PolicyEngine(ps);
    const v = engine.evaluate({ tool: "bash" });
    expect(v.effect).toBe("allow");
    expect(v.policyId).toBe("p1");
  });

  it("non-matching policy falls through", () => {
    const ps = makePolicySet(
      [{ id: "p1", effect: "deny", condition: { tools: ["bash"] } }],
      "allow",
    );
    const engine = new PolicyEngine(ps);
    const v = engine.evaluate({ tool: "grep" });
    expect(v.effect).toBe("allow");
    expect(v.policyId).toBeNull();
  });

  it("disabled policy is skipped", () => {
    const ps = makePolicySet(
      [
        {
          id: "p1",
          effect: "deny",
          enabled: false,
          condition: { tools: ["bash"] },
        },
      ],
      "allow",
    );
    const engine = new PolicyEngine(ps);
    const v = engine.evaluate({ tool: "bash" });
    expect(v.effect).toBe("allow");
  });
});

describe("Priority ordering", () => {
  it("lower priority wins", () => {
    const ps = makePolicySet([
      {
        id: "low",
        effect: "allow",
        priority: 10,
        condition: { tools: ["bash"] },
      },
      {
        id: "high",
        effect: "deny",
        priority: 50,
        condition: { tools: ["bash"] },
      },
    ]);
    const engine = new PolicyEngine(ps);
    const v = engine.evaluate({ tool: "bash" });
    expect(v.effect).toBe("allow");
    expect(v.policyId).toBe("low");
  });

  it("respects priority regardless of insertion order", () => {
    const ps = makePolicySet([
      {
        id: "high",
        effect: "deny",
        priority: 50,
        condition: { tools: ["*"] },
      },
      {
        id: "low",
        effect: "allow",
        priority: 5,
        condition: { tools: ["*"] },
      },
    ]);
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "anything" }).policyId).toBe("low");
  });
});

describe("Condition matching", () => {
  it("mode match", () => {
    const ps = makePolicySet(
      [{ id: "bg", effect: "deny", condition: { modes: ["background"] } }],
      "allow",
    );
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "bash", mode: "background" }).effect).toBe(
      "deny",
    );
    expect(engine.evaluate({ tool: "bash", mode: "interactive" }).effect).toBe(
      "allow",
    );
  });

  it("model glob", () => {
    const ps = makePolicySet(
      [{ id: "gpt", effect: "deny", condition: { models: ["gpt-*"] } }],
      "allow",
    );
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "bash", model: "gpt-5.2" }).effect).toBe(
      "deny",
    );
    expect(
      engine.evaluate({ tool: "bash", model: "claude-sonnet-4.6" }).effect,
    ).toBe("allow");
  });

  it("tool glob", () => {
    const ps = makePolicySet(
      [
        {
          id: "mcp",
          effect: "ask",
          condition: { tools: ["mcp:github-*"] },
        },
      ],
      "allow",
    );
    const engine = new PolicyEngine(ps);
    expect(
      engine.evaluate({ tool: "mcp:github-mcp-server" }).effect,
    ).toBe("ask");
  });

  it("mcp_servers match", () => {
    const ps = makePolicySet(
      [
        {
          id: "mcp",
          effect: "deny",
          condition: { mcp_servers: ["azure-*"] },
        },
      ],
      "allow",
    );
    const engine = new PolicyEngine(ps);
    expect(
      engine.evaluate({ tool: "deploy", mcpServer: "azure-mcp-server" })
        .effect,
    ).toBe("deny");
    expect(
      engine.evaluate({ tool: "deploy", mcpServer: "github-mcp" }).effect,
    ).toBe("allow");
  });

  it("mcp_servers with no server in context", () => {
    const ps = makePolicySet(
      [
        {
          id: "mcp",
          effect: "deny",
          condition: { mcp_servers: ["azure-*"] },
        },
      ],
      "allow",
    );
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "deploy" }).effect).toBe("allow");
  });

  it("risk match", () => {
    const ps = makePolicySet(
      [
        {
          id: "high",
          effect: "deny",
          condition: { risk: ["high", "critical"] },
        },
      ],
      "allow",
    );
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "bash", risk: "high" }).effect).toBe(
      "deny",
    );
    expect(engine.evaluate({ tool: "bash", risk: "critical" }).effect).toBe(
      "deny",
    );
    expect(engine.evaluate({ tool: "bash", risk: "low" }).effect).toBe(
      "allow",
    );
  });

  it("user match", () => {
    const ps = makePolicySet(
      [
        {
          id: "admin",
          effect: "allow",
          condition: { users: ["admin-*"] },
        },
      ],
      "deny",
    );
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "bash", user: "admin-alice" }).effect).toBe(
      "allow",
    );
    expect(engine.evaluate({ tool: "bash", user: "guest-bob" }).effect).toBe(
      "deny",
    );
  });

  it("AND logic across fields", () => {
    const ps = makePolicySet(
      [
        {
          id: "combo",
          effect: "deny",
          condition: {
            modes: ["background"],
            tools: ["bash"],
            risk: ["high"],
          },
        },
      ],
      "allow",
    );
    const engine = new PolicyEngine(ps);
    expect(
      engine.evaluate({ tool: "bash", mode: "background", risk: "high" })
        .effect,
    ).toBe("deny");
    expect(
      engine.evaluate({ tool: "bash", mode: "interactive", risk: "high" })
        .effect,
    ).toBe("allow");
    expect(
      engine.evaluate({ tool: "grep", mode: "background", risk: "high" })
        .effect,
    ).toBe("allow");
  });

  it("channel override", () => {
    const ps = makePolicySet([
      {
        id: "phone",
        effect: "ask",
        channel: "phone",
        condition: { tools: ["make_voice_call"] },
      },
    ]);
    const engine = new PolicyEngine(ps);
    const v = engine.evaluate({ tool: "make_voice_call" });
    expect(v.effect).toBe("ask");
    expect(v.channel).toBe("phone");
  });
});

describe("evaluateAll", () => {
  it("returns all policies with match status", () => {
    const ps = makePolicySet([
      { id: "p1", effect: "allow", condition: { tools: ["bash"] } },
      { id: "p2", effect: "deny", condition: { tools: ["grep"] } },
    ]);
    const engine = new PolicyEngine(ps);
    const results = engine.evaluateAll({ tool: "bash" });
    expect(results).toHaveLength(2);
    const matched = results.filter((r) => r.matched);
    expect(matched).toHaveLength(1);
    expect(matched[0].policyId).toBe("p1");
  });
});

// ── Custom effects ───────────────────────────────────────────────────────

describe("Custom effects", () => {
  it("well-known hitl effect", () => {
    const ps = makePolicySet([
      { id: "p1", effect: HITL, condition: { tools: ["bash"] } },
    ]);
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "bash" }).effect).toBe("hitl");
  });

  it("well-known aitl effect", () => {
    const ps = makePolicySet([
      { id: "p1", effect: AITL, condition: { tools: ["bash"] } },
    ]);
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "bash" }).effect).toBe("aitl");
  });

  it("well-known filter effect", () => {
    const ps = makePolicySet([
      { id: "p1", effect: FILTER, condition: { tools: ["bash"] } },
    ]);
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "bash" }).effect).toBe("filter");
  });

  it("well-known pitl effect", () => {
    const ps = makePolicySet([
      { id: "p1", effect: PITL, condition: { tools: ["call"] } },
    ]);
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "call" }).effect).toBe("pitl");
  });

  it("custom string effect", () => {
    const ps = makePolicySet([
      { id: "p1", effect: "my-org-auth", condition: { tools: ["deploy"] } },
    ]);
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "deploy" }).effect).toBe("my-org-auth");
  });

  it("custom effect loaded from YAML", () => {
    const yaml = `
apiVersion: agent-policy/v1
kind: PolicySet
metadata:
  name: custom
policies:
  - id: p1
    effect: my-org-mfa
    condition:
      tools: [deploy]
`;
    const ps = loadPolicySetFromStr(yaml);
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "deploy" }).effect).toBe("my-org-mfa");
  });

  it("resolve returns effect string", () => {
    const ps = makePolicySet(
      [{ id: "p1", effect: "aitl", condition: { tools: ["bash"] } }],
      "deny",
    );
    const engine = new PolicyEngine(ps);
    expect(engine.resolve({ tool: "bash" })).toBe("aitl");
    expect(engine.resolve({ tool: "grep" })).toBe("deny");
  });
});

// ── Context fallbacks ────────────────────────────────────────────────────

describe("Context fallbacks", () => {
  it("falls back to background", () => {
    const ps: PolicySet = {
      metadata: { name: "test" },
      defaults: { effect: "allow" },
      policies: [
        {
          id: "bg-deny",
          effect: "deny",
          condition: { modes: ["background"], tools: ["bash"] },
        },
      ],
      contextFallbacks: { scheduler: "background" },
    };
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "bash", mode: "background" }).effect).toBe(
      "deny",
    );
    expect(engine.evaluate({ tool: "bash", mode: "scheduler" }).effect).toBe(
      "deny",
    );
    expect(engine.evaluate({ tool: "bash", mode: "interactive" }).effect).toBe(
      "allow",
    );
  });

  it("multi-level fallback", () => {
    const ps: PolicySet = {
      metadata: { name: "test" },
      defaults: { effect: "deny" },
      policies: [
        {
          id: "bg",
          effect: "hitl",
          condition: { modes: ["background"] },
        },
      ],
      contextFallbacks: {
        scheduler: "bot_processor",
        bot_processor: "background",
      },
    };
    const engine = new PolicyEngine(ps);
    const v = engine.evaluate({ tool: "bash", mode: "scheduler" });
    expect(v.effect).toBe("hitl");
    expect(v.policyId).toBe("bg");
  });

  it("prevents cycles", () => {
    const ps: PolicySet = {
      metadata: { name: "test" },
      defaults: { effect: "deny" },
      policies: [],
      contextFallbacks: { a: "b", b: "a" },
    };
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "bash", mode: "a" }).effect).toBe("deny");
  });

  it("loaded from YAML", () => {
    const yaml = `
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
`;
    const ps = loadPolicySetFromStr(yaml);
    expect(ps.contextFallbacks).toEqual({
      scheduler: "background",
      bot_processor: "background",
    });
    const engine = new PolicyEngine(ps);
    expect(engine.resolve({ tool: "bash", mode: "scheduler" })).toBe("deny");
    expect(engine.resolve({ tool: "grep", mode: "scheduler" })).toBe("allow");
  });

  it("contextFallbacks property", () => {
    const ps: PolicySet = {
      metadata: { name: "test" },
      policies: [],
      contextFallbacks: { a: "b" },
    };
    const engine = new PolicyEngine(ps);
    expect(engine.contextFallbacks).toEqual({ a: "b" });
  });
});

// ── Loader tests ─────────────────────────────────────────────────────────

const YAML_DOC = `
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
      tools:
        - view
        - grep
        - glob
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
`;

describe("Loader", () => {
  it("loads from string", () => {
    const ps = loadPolicySetFromStr(YAML_DOC);
    expect(ps.apiVersion).toBe("agent-policy/v1");
    expect(ps.kind).toBe("PolicySet");
    expect(ps.metadata.name).toBe("test-set");
    expect(ps.metadata.version).toBe("1.0.0");
    expect(ps.metadata.labels).toEqual({ env: "test" });
    expect(ps.defaults?.effect).toBe("deny");
    expect(ps.policies).toHaveLength(3);
  });

  it("parsed policies have correct fields", () => {
    const ps = loadPolicySetFromStr(YAML_DOC);
    const p0 = ps.policies[0];
    expect(p0.id).toBe("allow-readonly");
    expect(p0.priority).toBe(10);
    expect(p0.effect).toBe("allow");
    expect(p0.condition?.tools).toEqual(["view", "grep", "glob"]);
    expect(p0.enabled).toBe(true);
  });

  it("disabled policy parsed", () => {
    const ps = loadPolicySetFromStr(YAML_DOC);
    expect(ps.policies[2].enabled).toBe(false);
  });

  it("channel override parsed", () => {
    const ps = loadPolicySetFromStr(YAML_DOC);
    expect(ps.policies[1].channel).toBe("phone");
  });

  it("load and evaluate", () => {
    const ps = loadPolicySetFromStr(YAML_DOC);
    const engine = new PolicyEngine(ps);

    expect(engine.evaluate({ tool: "view" }).effect).toBe("allow");
    const v = engine.evaluate({ tool: "bash", mode: "interactive" });
    expect(v.effect).toBe("ask");
    expect(v.channel).toBe("phone");
    expect(engine.evaluate({ tool: "unknown" }).effect).toBe("deny");
  });

  it("invalid kind throws", () => {
    const bad = `apiVersion: agent-policy/v1\nkind: NotAPolicy\nmetadata:\n  name: x\npolicies: []`;
    expect(() => loadPolicySetFromStr(bad)).toThrow(/PolicySet/);
  });
});

// ── Match tests ──────────────────────────────────────────────────────────

describe("globMatch", () => {
  it("exact match", () => {
    expect(globMatch("bash", "bash")).toBe(true);
    expect(globMatch("bash", "grep")).toBe(false);
  });

  it("star matches all", () => {
    expect(globMatch("*", "anything")).toBe(true);
  });

  it("prefix glob", () => {
    expect(globMatch("mcp:github-*", "mcp:github-mcp-server")).toBe(true);
    expect(globMatch("mcp:github-*", "mcp:azure-mcp-server")).toBe(false);
  });

  it("suffix glob", () => {
    expect(globMatch("*-server", "github-mcp-server")).toBe(true);
    expect(globMatch("*-server", "github-mcp-client")).toBe(false);
  });

  it("empty pattern", () => {
    expect(globMatch("", "anything")).toBe(false);
  });

  it("question mark", () => {
    expect(globMatch("gpt-?", "gpt-5")).toBe(true);
    expect(globMatch("gpt-?", "gpt-55")).toBe(false);
  });
});

// ── Example file tests ──────────────────────────────────────────────────

describe("Example YAML files", () => {
  const examplesDir = resolve(__dirname, "..", "..", "examples");

  it("permissive loads and evaluates", async () => {
    const ps = await loadPolicySet(resolve(examplesDir, "permissive.yaml"));
    expect(ps.metadata.name).toBe("permissive");
    expect(ps.defaults?.effect).toBe("allow");
    expect(ps.contextFallbacks?.scheduler).toBe("background");
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "view" }).effect).toBe("allow");
  });

  it("balanced loads and evaluates", async () => {
    const ps = await loadPolicySet(resolve(examplesDir, "balanced.yaml"));
    expect(ps.metadata.name).toBe("balanced");
    expect(ps.defaults?.effect).toBe("hitl");
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "view", risk: "low" }).effect).toBe(
      "allow",
    );
    expect(
      engine.evaluate({ tool: "bash", mode: "background", risk: "high" })
        .effect,
    ).toBe("deny");
    // Medium risk interactive -> filter
    expect(
      engine.evaluate({ tool: "edit", mode: "interactive", risk: "medium" })
        .effect,
    ).toBe("filter");
    // Medium risk background -> aitl
    expect(
      engine.evaluate({ tool: "edit", mode: "background", risk: "medium" })
        .effect,
    ).toBe("aitl");
    // Scheduler falls back to background
    expect(
      engine.evaluate({ tool: "bash", mode: "scheduler", risk: "high" })
        .effect,
    ).toBe("deny");
  });

  it("restrictive loads and evaluates", async () => {
    const ps = await loadPolicySet(resolve(examplesDir, "restrictive.yaml"));
    expect(ps.metadata.name).toBe("restrictive");
    expect(ps.defaults?.effect).toBe("deny");
    const engine = new PolicyEngine(ps);
    expect(engine.evaluate({ tool: "grep" }).effect).toBe("allow");
    expect(
      engine.evaluate({ tool: "edit", mode: "background", risk: "medium" })
        .effect,
    ).toBe("deny");
    // Interactive writes -> hitl
    expect(
      engine.evaluate({ tool: "edit", mode: "interactive" }).effect,
    ).toBe("hitl");
    // Voice call -> pitl
    expect(
      engine.evaluate({ tool: "make_voice_call" }).effect,
    ).toBe("pitl");
  });
});
