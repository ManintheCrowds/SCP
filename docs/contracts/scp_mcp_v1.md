# SCP MCP contract v1

**Version:** 1.0  
**Purpose:** Public, verify-not-trust specification for the Secure Contain Protect (SCP) MCP server. Implementations may live in a **private** repository; consumers verify behavior against this contract and pinned release hashes.

**Normative:** Tool names, parameters, and JSON shapes below. Servers may add **non-breaking** optional fields in JSON responses.

---

## Transport

- MCP over **stdio** (typical Cursor `mcp.json` `command` + `args`).
- Server name identifier: `SCP` (FastMCP) or equivalent; host-visible tool names MUST match the `scp_*` names below (with optional `mcp_` prefix depending on host bundling—document host mapping in `mcp.json`).

---

## Tools (required)

| Tool | Parameters | Success return | Error return |
|------|------------|----------------|--------------|
| `scp_inspect` | `content: string`, `context?: string` | JSON string: inspect result with `tier`, `findings`, `risk_score`, `categories` | JSON `{"error": "..."}` |
| `scp_sanitize` | `content: string`, `mode?: string` default `strip_unicode` | JSON `{sanitized, changes}` | JSON `{"error": "..."}` |
| `scp_contain` | `content: string`, `wrapper?: string` default `markdown_fence` | JSON `{contained}` | JSON `{"error": "..."}` |
| `scp_quarantine` | `content: string`, `reason: string`, `source: string` | JSON `{quarantine_id, path}` | JSON `{"error": "..."}` |
| `scp_list_quarantine` | none | JSON array of `{quarantine_id, reason, source, path}` | JSON `{"error": "..."}` |
| `scp_purge_quarantine` | `quarantine_id?: string`, `older_than_days?: int` | JSON purge summary (implementation-defined shape, must be JSON) | JSON `{"error": "..."}` |
| `scp_validate_output` | `content: string`, `tool_name?: string` | JSON `{safe: bool, findings}` where `safe` is false when tier is `injection` | JSON `{"error": "..."}` |
| `scp_mask_secrets` | `content: string` | JSON `{masked, redacted_count}` | JSON `{"error": "..."}` |
| `scp_run_pipeline` | `content: string`, `sink?: string` default `handoff`, `options?: string` (JSON string) | JSON `{result, blocked, report}` | JSON `{"error": "..."}` |

### `sink` (for `scp_run_pipeline`)

Allowed values: `handoff` | `state` | `llm_context` | `tool_output`. Stricter policy for `handoff` and `state` than for `tool_output`.

### `options` (for `scp_run_pipeline`)

JSON object, optional keys (v1):

- `quarantine_on_block`: boolean
- `wrapper`: string (e.g. `markdown_fence`, `xml_tag`)
- `semantic_judge`: boolean

### `mode` (for `scp_sanitize`)

At minimum: `strip_unicode` | `redact_phrases` | `full`. Servers may accept aliases if documented.

### `wrapper` (for `scp_contain`)

At minimum: `markdown_fence` | `xml_tag`.

---

## Pipeline semantics (normative)

1. **Inspect** classifies content; `tier` includes at least `injection` | `reversal` | `clean` (or equivalent enum documented by server).
2. **Injection:** pipeline MUST NOT persist or forward raw content to the requested sink without block/quarantine path; `blocked: true` in `scp_run_pipeline` when applicable.
3. **Quarantine:** `scp_quarantine` MUST be idempotent in the sense that repeated calls create distinct entries or document deduplication behavior in server release notes.

---

## Security guardrail

Servers MUST NOT expose tools that instruct the host to shut down, self-terminate, or delete the SCP service as a “feature.”

---

## Verification

- **CONTRACT_HASH:** SHA-256 of this file (UTF-8, LF or normalized per your `verify` script). Record in private server release notes and optionally [SCP_SERVER_RELEASES.md](../SCP_SERVER_RELEASES.md).
- Run [`scripts/verify_canonical_bundle.ps1`](../../scripts/verify_canonical_bundle.ps1) from OpenHarness repo root to confirm bundled copies match the manifest.

---

## Changelog

- **v1.0** — Initial public contract aligned with reference implementation tool surface.
