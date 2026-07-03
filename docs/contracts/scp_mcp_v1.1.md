# SCP MCP contract v1.1 (optional add-ons)

**Version:** 1.1  
**Purpose:** Optional read-only registry introspection tools for the SCP core MCP server (`scp_mcp.py`).  
**Requires:** [scp_mcp_v1.md](scp_mcp_v1.md) v1.0 tool surface (all nine required tools MUST remain present).

**Normative:** Tool names, parameters, and JSON shapes below. v1.0-only hosts remain conformant without implementing v1.1.

---

## Transport

Same as v1.0 — MCP over stdio; server identifier `SCP`.

---

## Tools (optional)

| Tool | Parameters | Success return | Error return |
|------|------------|----------------|--------------|
| `scp_registry_summary` | none | JSON `{registry_path, sections}` where `sections` maps top-level registry keys to counts; `registry_path` MAY be redacted unless debug env enabled | JSON `{"error": {"code", "message", "details"?}}` |
| `scp_registry_section` | `section: string`, `max_chars?: int` default 2048 | JSON `{section, excerpt, truncated}` — JSON text excerpt of one allowlisted section | JSON error object |

### Registry resolution (normative)

Threat registry JSON load order for v1.1 tools and inspect:

1. `SCP_THREAT_REGISTRY_PATH` — if set and file exists
2. `~/.scp/threat_registry_projection.json` — if exists (post-merge projection)
3. Packaged `scp_threat_registry.json` — ship default

### `scp_registry_section` constraints

- Section names MUST match `^[a-z_][a-z0-9_]{0,63}$`
- Section MUST be in allowlist (default: packaged registry top-level keys; override via `SCP_REGISTRY_SECTION_ALLOWLIST` comma-separated)
- Effective excerpt cap: `min(max_chars, 4096)`; `max_chars` MUST be ≥ 1
- MUST NOT dump full registry in one call

### Debug metadata

When `SCP_DEBUG_META=1`, `registry_path` in summary responses MAY include resolved filesystem path.

---

## Security invariants

- Read-only — no network I/O, no merge, no publish
- No auto-merge or auto-publish on core pipeline
- v1.0 contract unchanged for existing consumers

---

## Verification

- **CONTRACT_HASH:** SHA-256 of this file (UTF-8, LF). Vendored copy in SCP `docs/contracts/` with hash test.
- v1.0 conformance: all nine v1.0 tools present; v1.1 tools optional extras.

---

## Changelog

- **v1.1** — Optional registry summary/section; registry load order for inspect loop (SCP-R5).
