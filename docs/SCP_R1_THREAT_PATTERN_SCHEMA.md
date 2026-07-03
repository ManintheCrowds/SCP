# SCP-R1 — Threat pattern schema (SSOT)

**decision_id:** `scp-r1-pattern-record-ssot-2026-07-02`  
**Status:** Design spec + R1 runtime core (`pattern_record.py`) implemented in R4 spike  
**Operator choice:** Option **C — Hybrid** (structured SSOT + legacy registry projection)

## Purpose

Define the **semantic field SSOT** for anonymized threat patterns shared across:

- Antigen bundles (nostr kind 30078 + HTTPS/L402 payloads)
- Shared registry fetch (`scp_fetch_registry`, SCP-R4)
- Local detection via [`scp_threat_registry.json`](../src/scp/scp_threat_registry.json) **projection**

Replaces interim ownership in `scp.pattern_bundle.v0` inner `patterns[]` without blocking ANT1 transport (ADR §11.2).

## Fork 2 — scope decision (pros / cons)

### Option A: Extend `scp_threat_registry.json`

| Pros | Cons |
|------|------|
| `sanitize_input.py` already consumes flat buckets | No `pattern_id`, drift, or provenance |
| Fastest fetch→merge path | Two shapes vs antigen bundle `patterns[]` |
| Familiar `version` bump | Poor fit for dual transport (nostr + HTTPS) |

### Option B: Greenfield SSOT only

| Pros | Cons |
|------|------|
| Single interchange record | Migration from v0 + legacy registry |
| Drift scoring, categories | More work before first merge |

### Option C: Hybrid (chosen)

- **`pattern_record`** = authoritative interchange + quarantine storage
- **Registry JSON buckets** = **compiled projection** for `sanitize_input.py` (not wire format)
- Migration tables from v0 bundle and legacy buckets (below)

## Core type: `pattern_record`

All transports carry the same inner record (JSON object).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pattern_id` | string | yes | Stable id `^[a-z0-9][a-z0-9._-]{2,127}$` |
| `category` | string | yes | Taxonomy: `injection`, `reversal`, `jailbreak`, `hostile_ux`, etc. |
| `detector` | object | yes | Non-executable defensive descriptor (see below) |
| `risk_tier` | enum | yes | `low` \| `medium` \| `high` \| `critical` |
| `drift_score` | number | no | 0.0–1.0 local-vs-remote semantic drift hint (R4 merge gate) |
| `containment` | string | no | Advisory: `sanitize`, `quarantine`, `block` |
| `source_ref` | object | no | `{ "transport": "nostr"|"https", "issuer_pubkey"?, "registry_url"?, "fetched_at" }` |
| `registry_bucket` | string | no | Projection target: `power_words`, `jailbreak_nicknames`, etc. |

### `detector` object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kind` | enum | yes | `token_family` \| `regex_family` \| `semantic_alias` \| `structural` |
| `normalized` | string | no | Abstracted/masked form — **never** a literal reproducible attack string |

Maps from interim v0 [`antigen-bundle.v0.schema.json`](../src/scp/schemas/antigen-bundle.v0.schema.json) `patterns[].detector`.

## Anonymization deny-list (hard)

Must **never** appear in `pattern_record` or registry projection:

- Raw victim prompts, chat logs, or session transcripts
- PII (names, emails, phone, addresses)
- URLs with credentials or session tokens
- Reproducible cognitohazard bodies (full hazardous text)
- Executable code intended as payload (only defensive signatures)

Violations → quarantine reject + audit event `pattern_rejected_anonymization`.

## Transport envelopes (fork #3 = both)

Same `pattern_record[]` inner body; envelope differs:

### Nostr (antigen path)

- Kind **30078** addressable event; manifest in tags; payload via HTTPS + L402
- Bundle `schema_revision` bumps to `scp.pattern_bundle.v1` when inner records conform to this spec

### HTTPS registry snapshot (R4 path)

```json
{
  "schema_revision": "scp.registry_snapshot.v1",
  "registry_version": "2026-07-02T00:00:00Z",
  "etag": "sha256:…",
  "patterns": [ { "pattern_id": "…", "category": "…", "detector": { "kind": "…" }, "risk_tier": "low" } ]
}
```

Fetch via `If-None-Match` / etag; verify HTTPS + allowlist; on failure → **local registry unchanged**.

## Schema revision plan

| Revision | Role |
|----------|------|
| `scp.pattern_bundle.v0` | Interim ANT1 (shipped) |
| `scp.pattern_bundle.v1` | Manifest + payload using `pattern_record` SSOT |
| `scp.registry_snapshot.v1` | HTTPS/nostr registry aggregate |
| `scp.pattern_record.v1` | Standalone record schema id (JSON Schema file TBD at implementation) |

Bump `schema_revision` in bundle manifest on any semantic field change.

## Migration tables

### v0 bundle `patterns[]` → `pattern_record`

| v0 field | v1 field |
|----------|----------|
| `pattern_id` | `pattern_id` |
| `category` | `category` |
| `detector` | `detector` |
| `severity` | `risk_tier` |
| `containment` | `containment` |
| (none) | `drift_score` default 0.0 on import |
| (none) | `registry_bucket` inferred from category map |

### Legacy registry bucket → `pattern_record` (import only)

Each string in e.g. `power_words[]` becomes:

```json
{
  "pattern_id": "legacy.power_words.<hash8>",
  "category": "injection",
  "detector": { "kind": "token_family", "normalized": "<token>" },
  "risk_tier": "medium",
  "registry_bucket": "power_words"
}
```

Projection compile collapses records back into bucket arrays for `sanitize_input.py`.

## Merge policy (fork #4 — production default)

| Mode | Gate | Behavior |
|------|------|----------|
| **production** | (default) | Quarantine → **operator approve** → append to SSOT store → recompile projection |
| **dev auto-low-risk** | `SCP_REGISTRY_MERGE_DEV_AUTO=1` + `SCP_REGISTRY_MAX_DRIFT` + category allowlist | Auto-apply only `risk_tier: low` with `drift_score` ≤ threshold; audit `merge_auto_applied` |

**Invariant:** L402 `fetch_ok` / payment **never** triggers merge (payment ≠ attestation).

Future: operator `merge_policy.json` (custom rules) — documented as R6 follow-up.

## API sketch (design only — R3 implements contribute)

See [SCP_R3_CONTRIBUTE_FLOW.md](SCP_R3_CONTRIBUTE_FLOW.md) for the full `scp_contribute_pattern` tool contract.

| Operation | Input | Output |
|-----------|-------|--------|
| `validate_pattern_record` | record JSON | `{ "valid": bool, "errors": [] }` |
| `project_to_registry` | pattern_record[] | `scp_threat_registry.json` shape |
| `diff_quarantine` | quarantine id | `{ "add": [], "conflict": [], "drift_max": float }` |

## References

- [SCP_R3_CONTRIBUTE_FLOW.md](SCP_R3_CONTRIBUTE_FLOW.md)
- [SCP_R4_FETCH_REGISTRY.md](SCP_R4_FETCH_REGISTRY.md)
- [SCP_R2_REGISTRY_HOSTING.md](SCP_R2_REGISTRY_HOSTING.md)
- [SCP_R1_R4_SPIKE_KICKOFF.md](SCP_R1_R4_SPIKE_KICKOFF.md)
- MiscRepos [antigen L402 design](https://github.com/ManintheCrowds/MiscRepos/blob/main/docs/superpowers/specs/2026-04-12-scp-antigen-l402-design.md)
