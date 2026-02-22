/** Glob-style pattern matching utilities. */

/**
 * Match a value against a glob pattern.
 *
 * Supports:
 * - `*` matches everything
 * - `prefix*` matches strings starting with prefix
 * - `*suffix` matches strings ending with suffix
 * - `?` matches a single character
 * - Exact match when no wildcards are present
 */
export function globMatch(pattern: string, value: string): boolean {
  if (!pattern) return false;
  if (pattern === "*") return true;

  // Convert glob to regex
  const escaped = pattern.replace(/([.+^${}()|[\]\\])/g, "\\$1");
  const regexStr = "^" + escaped.replace(/\*/g, ".*").replace(/\?/g, ".") + "$";
  return new RegExp(regexStr).test(value);
}

/**
 * Return true if `patterns` is undefined/null (don't care) or any pattern matches `value`.
 */
export function listMatches(
  patterns: string[] | undefined,
  value: string,
): boolean {
  if (patterns === undefined || patterns === null) return true;
  return patterns.some((p) => globMatch(p, value));
}
