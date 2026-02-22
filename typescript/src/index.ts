/** agent-policy-guard: Declarative guardrail policies for AI agent autonomy. */

export { PolicyEngine } from "./engine.js";
export {
  loadPolicySet,
  loadPolicySetFromDict,
  loadPolicySetFromStr,
  loadPolicySetFromString,
} from "./loader.js";
export { globMatch, listMatches } from "./match.js";
export {
  ALLOW,
  AITL,
  ASK,
  DENY,
  FILTER,
  HITL,
  PITL,
} from "./models.js";
export type {
  Channel,
  Condition,
  Defaults,
  Effect,
  EvalContext,
  Metadata,
  Policy,
  PolicySet,
  Verdict,
} from "./models.js";
