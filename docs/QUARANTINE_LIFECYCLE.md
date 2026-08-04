# Quarantine lifecycle

**Status:** Content stub (public)  
**Taxonomy home:** [SCP](https://github.com/ManintheCrowds/SCP) (**Guard** / Content axis)  
**Not:** Patient “retirement,” Guide session handoff, or Threat eviction of an adversary process.

Companion stance: [OpenHarness — Patient ≠ Threat ≠ Content](https://github.com/ManintheCrowds/OpenHarness/blob/main/docs/PATIENT_THREAT_CONTENT_DELINEATION.md).

---

## Stages

| Stage | What happens | Tools / controls |
|-------|----------------|------------------|
| **1. Write** | Suspect or blocked payload isolated under quarantine storage | `scp_quarantine`; registry fetches use `{SCP_QUARANTINE_DIR}/registry_fetch/` |
| **2. List / inspect** | Operator reviews what is held | `scp_list_quarantine` |
| **3. Retain under caps** | Per-entry and total byte limits; optional age purge on write; optional oldest-first eviction under pressure | `SCP_QUARANTINE_MAX_CONTENT_BYTES`, `SCP_QUARANTINE_MAX_TOTAL_BYTES`, `SCP_QUARANTINE_RETENTION_DAYS_ON_WRITE`, `SCP_QUARANTINE_EVICT_OLDEST_ON_PRESSURE` |
| **4. Purge** | Explicit delete by id and/or age | `scp_purge_quarantine` |

Default directory (`scp_quarantine/` or `SCP_QUARANTINE_DIR`) must not be committed (see repo `.gitignore`). Env defaults: [README.md](../README.md) § Environment.

---

## Why purge / eviction exist

| Reason | Meaning |
|--------|---------|
| **Capacity** | Bound disk use from repeated or oversized blocked payloads |
| **Hazard** | Limit dwell time of injection/credential-bearing blobs on disk |
| **Ops hygiene** | Clear stale entries after review; fail closed or evict oldest when over total cap |

These are **Content** and systems reasons — not moral judgments about model minds.

---

## Explicit non-claims

- Quarantine purge is **not** Patient-axis “retirement,” sanctuary, or euthanasia of a conscious system.
- Quarantine entries are **payloads** (and metadata), not moral patients.
- Guide [agent-run lifecycle](https://github.com/ManintheCrowds/OpenHarness/blob/main/docs/AGENT_RUN_LIFECYCLE.md) (handoff / session end) is a **different** lifecycle; do not equate “session terminate” with `scp_purge_quarantine`.
- Registry fetch quarantine + merge consent flows are documented separately (`scp_fetch_registry` / `scp_apply_registry_quarantine`); same Content axis, different approval path.

---

## See also

- [INTEGRATION.md](INTEGRATION.md) — guardrail before persist
- [contracts/scp_mcp_v1.md](contracts/scp_mcp_v1.md) — tool shapes
- [OpenHarness THREE_CANDORS.md](https://github.com/ManintheCrowds/OpenHarness/blob/main/docs/THREE_CANDORS.md) — Concealment candor

**Risk:** Low (documentation). Rollback: delete this file and revert README pointer.
