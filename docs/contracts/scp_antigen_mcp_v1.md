# SCP Antigen MCP contract v1

**Version:** 1.0  
**Purpose:** Public specification for the SCP mesh extension MCP server (`antigen_mcp.py`) — antigen transport, shared registry fetch/contribute/apply. Separate from core [scp_mcp_v1.md](scp_mcp_v1.md) to preserve frozen v1.0 core contract.

**Normative:** Tool names and human-gate semantics below. Network I/O tools live here only — not on core `scp_mcp`.

---

## Transport

- MCP over **stdio** (typical `mcp.json` entry `scp-antigen`).
- Server name identifier: `SCP-Antigen` (FastMCP) or equivalent.

---

## Tool groups

### Antigen bundle (P0)

| Tool | Parameters | Human gate | Notes |
|------|------------|------------|-------|
| `scp_antigen_export` | `patterns_json`, `antigen_id`, optional sign fields | — | Build bundle |
| `scp_antigen_verify` | `bundle_json`, `allowlist?`, `require_signature?` | — | No side effects |
| `scp_antigen_import` | `bundle_json`, `allowlist?`, `require_signature?` | Never auto-merges | Quarantine only |
| `scp_antigen_merge` | `bundle_json`, `approve?` default **false** | **`approve=true` required** | Registry merge |
| `scp_antigen_publish` | `bundle_json`, `seckey_hex?`, `relays?`, `dry_run?` | Operator credentials | Nostr kind 30078 |
| `scp_antigen_discover` | `allowlist?`, `relays?`, filters | Empty allowlist fails closed | Metadata only |
| `scp_antigen_fetch` | `url`, `expected_hash`, `allowlist?`, `l402_token?` | No auto-pay on 402 | HTTPS fetch + verify |

### Registry mycelium (R3/R4)

| Tool | Parameters | Human gate | Notes |
|------|------------|------------|-------|
| `scp_fetch_registry` | `source`, `allowlist`, `if_none_match?`, `tls_verify?`, `relays?` | Stages to quarantine only; **`merged` always false** | HTTPS or nostr |
| `scp_contribute_pattern` | `transport`, `patterns_json?`, `raw_content?`, `approve?` default **false**, … | **`approve=true` for publish**; `approve=false` → zero network I/O | R3 contribute |
| `scp_apply_registry_quarantine` | `quarantine_path`, `approve?` default **false** | **`approve=true` for production merge**; dev auto via `SCP_REGISTRY_MERGE_DEV_AUTO=1` | R4 SSOT + projection |

---

## End-to-end mycelium flow (informative)

```text
scp_fetch_registry (antigen_mcp) → quarantine_path
scp_apply_registry_quarantine approve=true (antigen_mcp) → SSOT + ~/.scp/threat_registry_projection.json
scp_registry_summary / scp_inspect (scp_mcp v1.0 + v1.1) → uses updated projection per load order
```

Core inspect load order documented in [scp_mcp_v1.1.md](scp_mcp_v1.1.md).

---

## Environment variables (informative)

| Variable | Purpose |
|----------|---------|
| `SCP_PATTERN_SSOT_PATH` | pattern_record SSOT store |
| `SCP_THREAT_REGISTRY_PATH` | Override registry/projection path |
| `SCP_REGISTRY_MERGE_DEV_AUTO` | Dev-only auto-merge low-risk patterns |
| `SCP_ANTIGEN_RELAYS` | Default nostr relays |
| `NOSTR_SECKEY` | Publish/discover credentials (operator-gated) |

---

## Security invariants

- Fetch stages only; merge is separate apply step
- Contribute two-phase consent: proposal (`approve=false`) then publish (`approve=true`)
- No network tools on core `scp_mcp` v1.0 required set
- Allowlists fail closed when empty where specified

---

## Verification

- **CONTRACT_HASH:** SHA-256 of this file (UTF-8, LF). Vendored in SCP `docs/contracts/`.
- Implementations SHOULD document tool list parity in release notes.

---

## Changelog

- **v1.0** — Initial antigen mesh contract (SCP-R5 dual-server).
