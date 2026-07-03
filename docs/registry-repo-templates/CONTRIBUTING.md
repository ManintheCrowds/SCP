# Contributing to scp-mycelium-registry

Thank you for helping improve collective LLM threat intelligence. This repo holds **data only** — anonymized `pattern_record` snapshots. Tooling lives in [SCP](https://github.com/ManintheCrowds/SCP).

**Hosting spec:** [SCP_R2_REGISTRY_HOSTING.md](https://github.com/ManintheCrowds/SCP/blob/main/docs/SCP_R2_REGISTRY_HOSTING.md)  
**Schema:** [SCP_R1_THREAT_PATTERN_SCHEMA.md](https://github.com/ManintheCrowds/SCP/blob/main/docs/SCP_R1_THREAT_PATTERN_SCHEMA.md)

## What to contribute

- Entries conforming to `pattern_record` inside a `scp.registry_snapshot.v1` envelope
- Abstracted detectors only (`token_family`, `regex_family`, etc.) — never literal reproducible attack strings
- Patterns that improve detection coverage with acceptable false-positive risk

## What never to contribute

- PII (email, phone, names tied to individuals)
- Raw prompts or verbatim jailbreak text
- Credentials, API keys, or live URLs with secrets
- Prohibited keys from the R1 deny-list (`raw_prompt`, `source_text`, etc.)

## License grant

By opening a pull request, you confirm that your contributions are licensed under **MIT** (same as this repository) and that you have the right to submit them.

## Pull request checklist

- [ ] Changes are under `snapshots/vX.Y.Z/registry.json` (new semver dir for each release)
- [ ] `schema_revision` is `scp.registry_snapshot.v1`
- [ ] Every pattern passes SCP `validate_pattern_record` + `validate_anonymization`
- [ ] **`etag` recomputed** from canonical `patterns[]` JSON (see R2 spec §Etag discipline)
- [ ] Semver bump documented: **patch** = add/fix patterns; **minor** = taxonomy change; **major** = breaking schema
- [ ] No PII or raw attack strings in the diff
- [ ] `latest.json` updated on `main` after tag (maintainer step post-merge)

## Consent and operator gates

Publishing to the live network uses SCP R3 two-phase flow (`approve=false` default). Full privacy/consent spec: **[SCP_R6_PRIVACY_CONSENT.md](https://github.com/ManintheCrowds/SCP/blob/main/docs/SCP_R6_PRIVACY_CONSENT.md)**.

### Consent before publish (Path B)

Before calling `scp_contribute_pattern` with `approve=true`:

1. Read [SCP_R6_PRIVACY_CONSENT.md](https://github.com/ManintheCrowds/SCP/blob/main/docs/SCP_R6_PRIVACY_CONSENT.md) and this checklist
2. Confirm patterns pass `validate_anonymization` (no PII, raw prompts, or prohibited keys)
3. Set `SCP_CONTRIBUTE_CONSENT=1` in the operator environment (not agent-default)

**Path A:** Maintainer PRs to this repo. **Path B:** Community direct publish is open per [GOVERNANCE.md](GOVERNANCE.md) §Path B when issuer pubkeys are documented.

## Review

All PRs require maintainer review. There is no automated merge. Maintainers may reject patterns that fail validation, increase false positives without justification, or violate the deny-list.

## Questions

Open an issue in this repo or SCP referencing `SCP-R2`.
