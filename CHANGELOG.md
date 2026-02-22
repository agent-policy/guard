# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-22

### Added

- Initial release of the agent-policy-guard evaluation engine.
- PolicySet YAML schema (`apiVersion: agent-policy/v1`, `kind: PolicySet`).
- Policy conditions: `modes`, `models`, `channels`, `tools`, `mcp_servers`, `risk`, `users`, `sessions`.
- Extensible string effects: `allow`, `deny`, `hitl`, `aitl`, `pitl`, `filter`, `ask`, and custom values.
- Glob pattern matching (`*`, `?`) for all condition string fields.
- Context fallback chains with cycle detection.
- Priority-based first-match evaluation.
- `evaluate()` (full verdict), `resolve()` (effect string), and `evaluate_all()` (debug) methods.
- Python SDK (`agent-policy-guard` on PyPI).
- TypeScript SDK (`@agent-policy/guard` on npm).
- Go SDK (`github.com/agent-policy/guard`).
- JSON Schema for policy validation (`spec/schema.json`).
- Example policy sets: permissive, balanced, restrictive.
- Documentation site (Jekyll / Just the Docs).
