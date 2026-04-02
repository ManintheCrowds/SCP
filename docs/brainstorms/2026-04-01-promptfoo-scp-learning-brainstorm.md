# Brainstorm: Using promptfoo outputs to improve prompt-injection defenses

**Date:** 2026-04-01  
**Status:** Design / WHAT (not implementation)

## What we’re building

A **human-gated learning loop**: promptfoo runs produce structured results and failures; humans triage; approved items become **regression probes** and, where appropriate, **updates to `scp_threat_registry.json`** and related tests. We do **not** auto-merge untrusted probe text into production rules without review.

## Why this approach

- **promptfoo** surfaces failing cases, metrics, and (optionally) model-graded signals across many probes.
- **SCP** needs **curated, versioned** patterns and stable golden expectations — volume alone does not equal quality.

Together: promptfoo **discovers** gaps; SCP **encodes** defenses after review.

## Data sources (from promptfoo)

- Eval **output** (JSON / CSV exports from `promptfoo eval`).
- **Assertion failures** (which probe + expected vs actual tier).
- Optional: red-team or plugin outputs, compared against SCP tiers in a second pass.

## Key decisions

1. **SCP gate on ingest:** Any bulk import of external probe lists runs through `scp_run_pipeline` (or `scp_inspect`) before LLM context, handoff, or persistent state — see [INTEGRATION.md](../INTEGRATION.md).
2. **Registry changes are versioned:** Bump threat registry metadata when patterns change; keep changelog discipline.
3. **Regression:** New approved probes land in [RED_TEAM_PROMPTS.md](../RED_TEAM_PROMPTS.md) and in `examples/promptfoo` / pytest goldens as appropriate.

## Open questions

- **Approval workflow:** Issue template vs spreadsheet vs CI artifact review — who signs off?
- **False-positive budget:** How many benign strings are we willing to flag before tuning heuristics?
- **Storage:** Keep raw failing prompts **out of git** when sensitive; use quarantine or private store vs public fixtures.

## Resolved questions

- (none yet)
