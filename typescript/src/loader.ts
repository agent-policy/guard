/** YAML/dict loader for PolicySet documents. */

import * as yaml from "js-yaml";
import type {
  Channel,
  Condition,
  Defaults,
  Effect,
  Metadata,
  Policy,
  PolicySet,
} from "./models.js";

function parseCondition(raw?: Record<string, unknown>): Condition | undefined {
  if (!raw) return undefined;
  return {
    modes: raw.modes as string[] | undefined,
    models: raw.models as string[] | undefined,
    channels: raw.channels as string[] | undefined,
    tools: raw.tools as string[] | undefined,
    mcp_servers: raw.mcp_servers as string[] | undefined,
    risk: raw.risk as string[] | undefined,
    users: raw.users as string[] | undefined,
    sessions: raw.sessions as string[] | undefined,
  };
}

function parsePolicy(raw: Record<string, unknown>): Policy {
  return {
    id: raw.id as string,
    effect: raw.effect as Effect,
    name: (raw.name as string) ?? "",
    description: (raw.description as string) ?? "",
    enabled: raw.enabled !== undefined ? (raw.enabled as boolean) : true,
    priority: (raw.priority as number) ?? 100,
    condition: parseCondition(raw.condition as Record<string, unknown>),
    channel: (raw.channel as Channel) ?? "chat",
  };
}

function parseDefaults(raw?: Record<string, unknown>): Defaults {
  if (!raw) return { effect: "ask", channel: "chat" };
  return {
    effect: (raw.effect as Effect) ?? "ask",
    channel: (raw.channel as Channel) ?? "chat",
  };
}

function parseMetadata(raw?: Record<string, unknown>): Metadata {
  if (!raw) return { name: "unnamed" };
  return {
    name: (raw.name as string) ?? "unnamed",
    description: (raw.description as string) ?? "",
    version: (raw.version as string) ?? "",
    labels: (raw.labels as Record<string, string>) ?? {},
  };
}

/** Parse a PolicySet from a raw object (e.g. parsed YAML/JSON). */
export function loadPolicySetFromDict(
  data: Record<string, unknown>,
): PolicySet {
  const kind = (data.kind as string) ?? "PolicySet";
  if (kind !== "PolicySet") {
    throw new Error(`Unsupported kind: ${kind} (expected PolicySet)`);
  }
  return {
    apiVersion: (data.apiVersion as string) ?? "agent-policy/v1",
    kind,
    metadata: parseMetadata(data.metadata as Record<string, unknown>),
    defaults: parseDefaults(data.defaults as Record<string, unknown>),
    policies: ((data.policies as Record<string, unknown>[]) ?? []).map(
      parsePolicy,
    ),
    contextFallbacks:
      (data.context_fallbacks as Record<string, string>) ?? {},
  };
}

/** Parse a PolicySet from a YAML string. */
export function loadPolicySetFromStr(text: string): PolicySet {
  return loadPolicySetFromString(text);
}

/** Parse a PolicySet from a YAML string. */
export function loadPolicySetFromString(text: string): PolicySet {
  const data = yaml.load(text) as Record<string, unknown>;
  if (!data || typeof data !== "object") {
    throw new Error("Expected a YAML mapping at the top level");
  }
  return loadPolicySetFromDict(data);
}

/** Load a PolicySet from a YAML file (Node.js only). */
export async function loadPolicySet(path: string): Promise<PolicySet> {
  const { readFile } = await import("node:fs/promises");
  const text = await readFile(path, "utf-8");
  return loadPolicySetFromStr(text);
}
