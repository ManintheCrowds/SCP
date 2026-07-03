# OpenHarness SCP contract

The public **normative** specifications for SCP MCP servers are maintained in the **OpenHarness** repository under `docs/contracts/`:

| Document | Role |
|----------|------|
| `scp_mcp_v1.md` | Core required tools (v1.0) |
| `scp_mcp_v1.1.md` | Optional read-only registry tools |
| `scp_antigen_mcp_v1.md` | Mesh extension (antigen + mycelium) |

This repository vendors **copies for verification** at [`docs/contracts/`](contracts/). SHA-256 of each file is asserted in `tests/test_contract_document_hash.py` (must match OpenHarness when synced).

## Sync procedure (when upstream contract changes)

For each changed contract file (`scp_mcp_v1.md`, `scp_mcp_v1.1.md`, `scp_antigen_mcp_v1.md`):

1. Copy from OpenHarness over this repo’s [`docs/contracts/`](contracts/) counterpart (preserve UTF-8, LF).
2. Compute SHA-256:
   - PowerShell: `(Get-FileHash -Algorithm SHA256 -Path docs/contracts/<file>).Hash.ToLowerInvariant()`
   - POSIX: `sha256sum docs/contracts/<file>`
3. Update the matching `EXPECTED_*_SHA256` constant in [`tests/test_contract_document_hash.py`](../tests/test_contract_document_hash.py).
4. Run `pytest tests/test_contract_document_hash.py tests/test_mcp_contract_v1.py -v`.
5. Document in [CHANGELOG.md](../CHANGELOG.md) and set **CONTRACT_HASH** for v1.0 releases (same value as `EXPECTED_SCP_MCP_V1_SHA256`).

## Release discipline

1. Run `pytest tests/test_mcp_contract_v1.py tests/test_contract_document_hash.py` before tagging a release.
2. Record **CONTRACT_HASH** = SHA-256 of the vendored `docs/contracts/scp_mcp_v1.md` (must equal `EXPECTED_SCP_MCP_V1_SHA256` in tests).
3. Append a row to OpenHarness `docs/SCP_SERVER_RELEASES.md` if you publish hash mappings.
