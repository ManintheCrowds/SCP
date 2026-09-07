# SCP Antigen MCP contract v1

**Version:** 1.3  
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
| `scp_antigen_export` | `patterns_json`, `antigen_id`, optional metadata; **no MCP `seckey_hex`** | — | Unsigned build on MCP; sign via CLI |
| `scp_antigen_verify` | `bundle_json` (**JSON object** only), `allowlist?` (issuer pubkeys); `require_signature` ignored (always true) | — | No side effects; reject JSON string paths |
| `scp_antigen_import` | `bundle_json` (**JSON object** only), `allowlist?` (issuer pubkeys); `require_signature` ignored (always true) | Never auto-merges | Quarantine only; filesystem paths are CLI-only |
| `scp_antigen_merge` | `bundle_json` (**JSON object** only), `approve?` default **false**, `allowlist?` | **`approve=true` + `SCP_REGISTRY_MERGE_CONSENT=1`**; signature always required | Registry merge; no path-as-JSON |
| `scp_antigen_publish` | `bundle_json` (**JSON object** only), `relays?`, `dry_run?`, `approve?` | **`approve=true` + `SCP_ANTIGEN_PUBLISH_CONSENT=1`**; no MCP `seckey_hex`; `dry_run` never signs | Nostr kind 30078 |
| `scp_antigen_discover` | `allowlist?` (issuer pubkeys), `relays?`, filters | Empty pubkey allowlist fails closed; relays ⊆ `SCP_ANTIGEN_RELAY_ALLOWLIST` | Metadata only |
| `scp_antigen_fetch` | `url`, `expected_hash`, `allowlist?` (ignored for hosts), `l402_token?` | No auto-pay on 402; **hosts env-only** (`SCP_ANTIGEN_FETCH_HOST_ALLOWLIST`); **never auto-loads** `SCP_ANTIGEN_L402_TOKEN` | HTTPS fetch + verify; body hard-capped (`SCP_ANTIGEN_MAX_PAYLOAD_BYTES`) before JSON parse |

`bundle_json` must be a JSON **object** (the antigen bundle). A JSON string value (including a filesystem path) is rejected. Loading bundles from disk is CLI-only (`pathlib.Path`).

### Registry mycelium (R3/R4)

| Tool | Parameters | Human gate | Notes |
|------|------------|------------|-------|
| `scp_fetch_registry` | `source`, `allowlist` (issuer pubkeys for nostr), `if_none_match?`, `relays?` | Stages to quarantine only; **`merged` always false**; HTTPS hosts from env; TLS via **`SCP_REGISTRY_TLS_VERIFY`** (no MCP `tls_verify`) | HTTPS or nostr; HTTPS body capped to quarantine content limit; writes under `registry_fetch/` |
| `scp_contribute_pattern` | `transport`, `patterns_json?`, `raw_content?`, `approve?` default **false**, … | **`approve=true`**; `SCP_CONTRIBUTE_CONSENT=1`; nostr/both also **`SCP_ANTIGEN_PUBLISH_CONSENT=1`** under MCP; **`SCP_CONTRIBUTE_HOST_ALLOWLIST`** gates POST; MCP rejects `seckey_hex`; TLS via **`SCP_REGISTRY_TLS_VERIFY`** | R3 contribute |
| `scp_apply_registry_quarantine` | `quarantine_path`, `approve?` default **false** | **`approve=true` + `SCP_REGISTRY_MERGE_CONSENT=1`**; `SCP_REGISTRY_MERGE_DEV_AUTO` disabled under MCP | Path must be under `{SCP_QUARANTINE_DIR}/registry_fetch/` from `scp_fetch_registry` (envelope + sidecar `reason=registry_fetch`); core `scp_quarantine` paths rejected |

---

## End-to-end mycelium flow (informative)

```text
scp_fetch_registry (antigen_mcp) → quarantine_path
scp_apply_registry_quarantine approve=true + SCP_REGISTRY_MERGE_CONSENT=1 → SSOT + projection
scp_registry_summary / scp_inspect (scp_mcp v1.0 + v1.1) → uses updated projection per load order
```

Core inspect load order documented in [scp_mcp_v1.1.md](scp_mcp_v1.1.md).

---

## Environment variables (informative)

| Variable | Purpose |
|----------|---------|
| `SCP_PATTERN_SSOT_PATH` | pattern_record SSOT store |
| `SCP_THREAT_REGISTRY_PATH` | Override registry/projection path |
| `SCP_REGISTRY_MERGE_CONSENT` | Hard attestation for approve=true merge/apply (`==1`) |
| `SCP_REGISTRY_MERGE_DEV_AUTO` | Dev-only auto-merge low-risk (CLI only; ignored under MCP) |
| `SCP_ANTIGEN_FETCH_HOST_ALLOWLIST` | Env-only HTTPS destinations for antigen fetch |
| `SCP_REGISTRY_FETCH_HOST_ALLOWLIST` | Optional HTTPS hosts for registry fetch (else fetch host allowlist) |
| `SCP_REGISTRY_TLS_VERIFY` | Registry HTTPS TLS verify (default on; `0`/`false`/`no` disables). MCP cannot pass `tls_verify` |
| `SCP_ANTIGEN_TLS_VERIFY` | Antigen fetch HTTPS TLS verify (default on; same disable tokens) |
| `SCP_ANTIGEN_RELAY_ALLOWLIST` | Fail-closed WSS relay allowlist for MCP |
| `SCP_ANTIGEN_RELAYS` | Default nostr relays (CLI; filtered by relay allowlist when set) |
| `SCP_ANTIGEN_PUBLISH_CONSENT` | Hard attestation for live antigen nostr publish (also required for MCP contribute nostr/both) |
| `SCP_ANTIGEN_L402_TOKEN` | Operator L402 token (CLI/library only; not auto-attached on MCP) |
| `NOSTR_SECKEY` | Publish credentials after consent (MCP never accepts seckey tool arg) |

---

## Security invariants

- Fetch stages only; merge is separate apply step with env consent
- Contribute two-phase consent: proposal (`approve=false`) then publish (`approve=true` + env)
- No network tools on core `scp_mcp` v1.0 required set
- HTTPS destination allowlists are **operator env only** (MCP cannot expand)
- Registry/antigen TLS verify is **operator env only** (`SCP_REGISTRY_TLS_VERIFY` / `SCP_ANTIGEN_TLS_VERIFY`); MCP tools must not expose `tls_verify`
- Relays fail closed under MCP without `SCP_ANTIGEN_RELAY_ALLOWLIST`; loopback/link-local/metadata blocked
- Encounter auto-log redacts secrets before durable write

---

## Verification

- **CONTRACT_HASH:** SHA-256 of this file (UTF-8, LF). Vendored in SCP `docs/contracts/`.
- Implementations SHOULD document tool list parity in release notes.

---

## Changelog

- **1.3** — AppSec: apply quarantine limited to egistry_fetch/\ paths from \scp_fetch_registry\ (core quarantine rejected); HTTPS body caps before parse/quarantine write.
- **1.2** — AppSec: remove MCP `tls_verify`; registry TLS via `SCP_REGISTRY_TLS_VERIFY` only (CLI `--no-tls-verify` retained).
- **1.1** — AppSec hardening: env-only hosts, publish/merge consent, MCP L402/seckey refusal, relay allowlist.
- **1.0** — Initial antigen + mycelium MCP contract.
