# Governance — scp-mycelium-registry

**Spec:** [SCP_R2_REGISTRY_HOSTING.md](https://github.com/ManintheCrowds/SCP/blob/main/docs/SCP_R2_REGISTRY_HOSTING.md)

## Maintainers

| Role | Contact | Responsibility |
|------|---------|----------------|
| Lead maintainer | _TBD_ | Releases, tag integrity, allowlist pubkey |
| Reviewers | _TBD_ | PR review, deny-list enforcement |

## Release cadence

- **v0:** On-demand maintainer releases
- **Future:** Weekly or bi-weekly batch releases once community contributions open

## Accept / reject criteria

**Accept** when:

- Snapshot passes `validate_snapshot` + `validate_snapshot_patterns`
- `etag` matches recomputed hash
- No R1 deny-list violations
- Semver bump is appropriate

**Reject** when:

- PII, raw prompts, or credentials present
- Pattern increases false positives without documented rationale
- Etag mismatch or schema revision drift
- Attempt to mutate an existing immutable tag

Optional future gate: promptfoo eval smoke on SCP repo (not required for v0).

## Community contributions

**v0:** Maintainer-only writes (Git PR Path A).  
**Opens after:** SCP-R6 privacy and consent spec is published and linked here.

**Path B** (R3 `scp_contribute_pattern` direct publish) opens when maintainers document allowed issuer pubkeys and POST endpoints in this file.

## Security disclosure

Report sensitive issues (e.g. patterns that exfiltrate data, malicious maintainer activity) via _TBD security contact_ or private GitHub security advisory.

Do **not** open public issues for undisclosed harmful pattern content until maintainers acknowledge.

## Rollback

1. Revert erroneous commit on `main` if pointer only is wrong
2. For bad tagged release: publish new patch tag with fix; **never** rewrite existing tags
3. Update `latest.json` to point at corrected tag
4. Publish nostr correction announcement (operator) with new `payload_urls[0]`
5. Nodes fetch via R4; operator rejects bad quarantine merges locally

## Immutability

Git tags `vX.Y.Z` and their `snapshots/vX.Y.Z/` paths are **immutable**. Fixes require a new semver tag.
