/** Data models for agent-policy-guard. */

/**
 * The effect a policy applies to a matching tool invocation.
 *
 * Well-known values: "allow", "deny", "hitl", "aitl", "pitl", "filter", "ask".
 * Custom string values are supported for extensibility -- agents can define
 * their own approval or verification strategies.
 */
export type Effect = string;

/** Well-known effect constants. */
export const ALLOW: Effect = "allow";
export const DENY: Effect = "deny";
export const ASK: Effect = "ask";
export const HITL: Effect = "hitl";
export const PITL: Effect = "pitl";
export const AITL: Effect = "aitl";
export const FILTER: Effect = "filter";

/** Approval channel for 'ask' effects. */
export type Channel = "chat" | "phone";

/** Snapshot of runtime state for a single tool invocation. */
export interface EvalContext {
  mode?: string;
  model?: string;
  channel?: string;
  tool?: string;
  mcpServer?: string;
  risk?: string;
  user?: string;
  session?: string;
}

/**
 * Matching criteria for a policy.
 *
 * All specified fields must match (AND logic across fields).
 * Each field's list uses OR logic (any item in the list may match).
 * `undefined` means "don't care" -- the field is not evaluated.
 */
export interface Condition {
  modes?: string[];
  models?: string[];
  channels?: string[];
  tools?: string[];
  mcp_servers?: string[];
  risk?: string[];
  users?: string[];
  sessions?: string[];
}

/** A single guardrail policy. */
export interface Policy {
  id: string;
  effect: Effect;
  name?: string;
  description?: string;
  enabled?: boolean;
  priority?: number;
  condition?: Condition;
  channel?: Channel;
}

/** Descriptive metadata for a policy set. */
export interface Metadata {
  name: string;
  description?: string;
  version?: string;
  labels?: Record<string, string>;
}

/** Fallback behaviour when no policy matches. */
export interface Defaults {
  effect?: Effect;
  channel?: Channel;
}

/** A complete set of guardrail policies loaded from YAML. */
export interface PolicySet {
  apiVersion?: string;
  kind?: string;
  metadata: Metadata;
  defaults?: Defaults;
  policies: Policy[];
  contextFallbacks?: Record<string, string>;
}

/** The result of evaluating a context against a policy set. */
export interface Verdict {
  effect: Effect;
  channel: Channel;
  policyId: string | null;
}
