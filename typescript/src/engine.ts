/** Policy evaluation engine. */

import { listMatches } from "./match.js";
import type {
  Channel,
  Condition,
  Defaults,
  Effect,
  EvalContext,
  Policy,
  PolicySet,
  Verdict,
} from "./models.js";

function conditionMatches(cond: Condition | undefined, ctx: EvalContext): boolean {
  if (!cond) return true; // no condition = matches everything

  if (!listMatches(cond.modes, ctx.mode ?? "")) return false;
  if (!listMatches(cond.models, ctx.model ?? "")) return false;
  if (!listMatches(cond.channels, ctx.channel ?? "")) return false;
  if (!listMatches(cond.tools, ctx.tool ?? "")) return false;
  if (!listMatches(cond.risk, ctx.risk ?? "")) return false;
  if (!listMatches(cond.users, ctx.user ?? "")) return false;
  if (!listMatches(cond.sessions, ctx.session ?? "")) return false;

  // mcp_servers: if patterns specified but no mcpServer in context -> no match
  if (cond.mcp_servers !== undefined && cond.mcp_servers !== null) {
    if (!ctx.mcpServer) return false;
    if (!listMatches(cond.mcp_servers, ctx.mcpServer)) return false;
  }

  return true;
}

/**
 * Evaluates tool invocations against a PolicySet.
 *
 * Policies are sorted by priority (ascending). The first matching
 * enabled policy wins. If nothing matches, the engine falls back
 * to the PolicySet's defaults.
 */
export class PolicyEngine {
  private _defaults: Required<Defaults>;
  private _policies: Policy[];
  private _contextFallbacks: Record<string, string>;

  constructor(policySet?: PolicySet) {
    this._defaults = { effect: "ask", channel: "chat" };
    this._policies = [];
    this._contextFallbacks = {};
    if (policySet) this.load(policySet);
  }

  /** Load (or replace) the active policy set. */
  load(policySet: PolicySet): void {
    this._defaults = {
      effect: policySet.defaults?.effect ?? "ask",
      channel: policySet.defaults?.channel ?? "chat",
    };
    this._policies = [...policySet.policies].sort(
      (a, b) => (a.priority ?? 100) - (b.priority ?? 100),
    );
    this._contextFallbacks = { ...(policySet.contextFallbacks ?? {}) };
  }

  /** Currently loaded policies (sorted by priority). */
  get policies(): Policy[] {
    return [...this._policies];
  }

  /** Current defaults. */
  get defaults(): Required<Defaults> {
    return { ...this._defaults };
  }

  /** Current context fallback chain. */
  get contextFallbacks(): Record<string, string> {
    return { ...this._contextFallbacks };
  }

  /** Try to match a single policy against the given context (no fallback). */
  private _evaluateOnce(ctx: EvalContext): Verdict | null {
    for (const policy of this._policies) {
      if (policy.enabled === false) continue;
      if (conditionMatches(policy.condition, ctx)) {
        return {
          effect: policy.effect,
          channel: policy.channel ?? "chat",
          policyId: policy.id,
        };
      }
    }
    return null;
  }

  /**
   * Evaluate all policies and return a verdict for the given context.
   *
   * Walks the context fallback chain when no policy matches the original
   * mode, retrying with each fallback until a match or chain exhaustion.
   */
  evaluate(ctx: EvalContext): Verdict {
    const verdict = this._evaluateOnce(ctx);
    if (verdict) return verdict;

    // Walk the context fallback chain
    let mode = ctx.mode ?? "";
    const visited = new Set<string>([mode]);
    while (mode in this._contextFallbacks) {
      mode = this._contextFallbacks[mode];
      if (visited.has(mode)) break;
      visited.add(mode);
      const fallbackVerdict = this._evaluateOnce({ ...ctx, mode });
      if (fallbackVerdict) return fallbackVerdict;
    }

    return {
      effect: this._defaults.effect,
      channel: this._defaults.channel,
      policyId: null,
    };
  }

  /**
   * Convenience method returning just the effect string.
   * Useful when integrating with systems that dispatch on string strategies.
   */
  resolve(ctx: EvalContext): string {
    return this.evaluate(ctx).effect;
  }

  /**
   * Evaluate all policies and return match results for every policy.
   * Useful for debugging and audit trails.
   */
  evaluateAll(
    ctx: EvalContext,
  ): Array<{
    policyId: string;
    name: string;
    priority: number;
    effect: Effect;
    matched: boolean;
    enabled: boolean;
  }> {
    return this._policies.map((policy) => ({
      policyId: policy.id,
      name: policy.name ?? "",
      priority: policy.priority ?? 100,
      effect: policy.effect,
      matched:
        (policy.enabled !== false) && conditionMatches(policy.condition, ctx),
      enabled: policy.enabled !== false,
    }));
  }
}
