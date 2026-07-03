# SCP-R6 — Privacy and consent

**decision_id:** `scp-r6-privacy-consent-2026-07-03`  
**Status:** Implemented (runtime slices A–D; operator `proceed R6-runtime` 2026-07-03)  
**Depends on:** [SCP_R1_THREAT_PATTERN_SCHEMA.md](SCP_R1_THREAT_PATTERN_SCHEMA.md), [SCP_R3_CONTRIBUTE_FLOW.md](SCP_R3_CONTRIBUTE_FLOW.md), [SCP_R2_REGISTRY_HOSTING.md](SCP_R2_REGISTRY_HOSTING.md)

## Purpose

Define **privacy guarantees**, **operator consent**, and **governance prerequisites** before opening **community Path B** (direct `scp_contribute_pattern` publish to the mycelium network).

| Path | Who | Gate |
|------|-----|------|
| **Path A** | Maintainers | Git PR to [scp-mycelium-registry](https://github.com/ManintheCrowds/scp-mycelium-registry) — **unchanged** |
| **Path B** | Community operators | Open — GOVERNANCE links R6; `SCP_CONTRIBUTE_CONSENT=1` required at publish |

**Operator lock (2026-07-03):** Runtime enforcement (`SCP_CONTRIBUTE_CONSENT`) live in `registry_contribute.submit_contribution`.

---

## Consent model

Extends R3 two-phase consent ([SCP_R3_CONTRIBUTE_FLOW.md](SCP_R3_CONTRIBUTE_FLOW.md) §Consent):

| Phase | Gate | Behavior |
|-------|------|----------|
| **Proposal (default)** | `approve=false` | Stage locally; return proposal; **zero network I/O** |
| **Attestation (R6)** | `SCP_CONTRIBUTE_CONSENT=1` | Operator confirms contribution guidelines read (env, not agent-settable default) |
| **Publish** | `approve=true` + attestation | nostr and/or HTTPS submit |

Production default: **no dev auto-submit**. No env bypasses `approve=true` for network publish (unlike R4 `SCP_REGISTRY_MERGE_DEV_AUTO`, which applies only to **inbound** merge).

### Contribution guidelines

Normative operator-facing checklist: [registry-repo-templates/CONTRIBUTING.md](registry-repo-templates/CONTRIBUTING.md) §Consent before publish.

---

## Anonymization guarantees

Normative enforcement today: [`validate_anonymization()`](../src/scp/pattern_record.py) + R1 deny-list.

### Prohibited in wire-format `pattern_record`

| Category | Rule |
|----------|------|
| **Prohibited keys** | `raw_prompt`, `raw_log`, `transcript`, `pii`, `victim_prompt`, `exploit`, `working_payload`, etc. (full list in `pattern_record._PROHIBITED_KEYS`) |
| **PII patterns** | Email addresses in serialized record |
| **Credential URLs** | URLs with embedded credentials |
| **Oversized tokens** | `detector.normalized` length > 512 chars (possible raw prompt) |

### Allowed

- Abstracted `token_family` / `regex_family` detectors
- `pattern_id`, `category`, `risk_tier`, `drift_score`, `registry_bucket`
- Optional `source_ref` with **no** PII (lang, coarse channel only per R1)

### On reject

- Audit event `pattern_rejected_anonymization` — **counts and ids only**, no payload body
- Contribute/fetch paths fail closed; local SSOT unchanged

---

## Attribution and opt-in log

**Operator-local** opt-in log (not transmitted in snapshot wire format):

```json
{
  "schema_revision": "scp.contribute_opt_in.v1",
  "entries": [
    {
      "at": "2026-07-03T12:00:00Z",
      "pattern_ids": ["legacy.power_words.a1b2c3d4"],
      "transport": "https",
      "operator_note": "optional free text — no PII"
    }
  ]
}
```

Default path: `~/.scp/contribute_opt_in.jsonl` (one JSON object per line). Appended on successful publish when `SCP_CONTRIBUTE_CONSENT=1`.

Attribution policy: patterns are **collective defense** — no individual user attribution in public registry; maintainer PR authors identified via Git history only.

---

## Retention and takedown

### Central registry (data repo)

Per [GOVERNANCE.md](registry-repo-templates/GOVERNANCE.md):

- Immutable semver tags — fixes via **new patch tag**, never rewrite
- Maintainer rollback: revert `main` pointer, publish correction announcement
- Security disclosure via private advisory (not public issues for undisclosed harmful content)

### Node-local

| Artifact | Purge procedure |
|----------|-----------------|
| SSOT | Delete `SCP_PATTERN_SSOT_PATH` or `~/.scp/pattern_records.json` |
| Projection | Delete `SCP_THREAT_REGISTRY_PATH` or `~/.scp/threat_registry_projection.json` |
| Quarantine | `scp_purge_quarantine` on core MCP |
| Opt-in log | Operator deletes `~/.scp/contribute_opt_in.jsonl` |

Fetch/merge failure → packaged registry unchanged (R4 recovery).

---

## LLM normalize (deferred)

**Default:** rule-only token extraction in R3 contribute (`raw_content` → `pattern_record`).

**Future opt-in only:** `SCP_CONTRIBUTE_LLM_NORMALIZE=1` requires explicit operator enable **and** R6-runtime slice documenting model/provider boundaries. **Not in R6 spec implementation.**

---

## merge_policy.json (future)

Operator-local custom merge rules (R1 pointer): `~/.scp/merge_policy.json` — schema TBD; production merge remains `approve=true` on `scp_apply_registry_quarantine`.

---

## Security invariants

Aligned with R3 hb-1..hb-5:

| Invariant | R6 application |
|-----------|----------------|
| **hb-1** | No auto-publish; `approve=true` + future `SCP_CONTRIBUTE_CONSENT=1` |
| **hb-2** | Anonymization fail closed |
| **hb-3** | Operator-supplied URLs/relays only |
| **hb-4** | Regtest gates unchanged |
| **hb-5** | Regtest ≠ mainnet |
| Payment ≠ attestation | L402/nostr success ≠ local merge |
| Fetch ≠ merge | R4 stages only; operator apply separate |

---

## Decision forks — locked

| # | Question | Choice |
|---|----------|--------|
| 1 | Path B gate | **R6 spec published + GOVERNANCE link** |
| 2 | Consent attestation | **Env `SCP_CONTRIBUTE_CONSENT=1`** (runtime) |
| 3 | Opt-in log | **Operator-local JSONL**, not in wire snapshot |
| 4 | LLM normalize | **Deferred**; explicit opt-in when implemented |
| 5 | MCP surface | **No new tools** — env gates on existing antigen_mcp |

---

## Implementation slices (completed: `proceed R6-runtime`)

| Slice | Deliverable | Verification |
|-------|-------------|--------------|
| **A** | `SCP_CONTRIBUTE_CONSENT` check in `registry_contribute.submit_contribution` before network I/O | `test_registry_contribute_r6.py` |
| **B** | Append opt-in log on successful publish | `test_registry_contribute_r6.py` |
| **C** | Link R6 in live scp-mycelium-registry GOVERNANCE/CONTRIBUTING | Data repo PR |
| **D** | Open Path B in GOVERNANCE | Docs review |

---

## Out of scope

- Mainnet L402 in contribute/fetch
- Auto-merge on fetch
- Changing OpenHarness scp_mcp v1.0 required tools
- Community Path B **runtime** — open per GOVERNANCE; maintainer pubkey via `scripts/announce_registry_snapshot.py`

---

## References

- [SCP_R3_CONTRIBUTE_FLOW.md](SCP_R3_CONTRIBUTE_FLOW.md)
- [SCP_R2_REGISTRY_HOSTING.md](SCP_R2_REGISTRY_HOSTING.md)
- [registry-repo-templates/CONTRIBUTING.md](registry-repo-templates/CONTRIBUTING.md)
- [registry-repo-templates/GOVERNANCE.md](registry-repo-templates/GOVERNANCE.md)
- MiscRepos [mycelium design §Collective Learning](https://github.com/ManintheCrowds/MiscRepos/blob/main/docs/plans/2026-03-12-scp-saas-mycelium-design.md)
