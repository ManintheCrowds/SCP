# OpenHarness SCP contract

The public **normative** specification for this MCP server’s tool surface is maintained in the **OpenHarness** repository as `docs/contracts/scp_mcp_v1.md`.

This repository vendors a **copy for verification** at [`docs/contracts/scp_mcp_v1.md`](contracts/scp_mcp_v1.md). The SHA-256 of that file is asserted in `tests/test_contract_document_hash.py` (must match OpenHarness when synced).

## Sync procedure (when upstream contract changes)

1. Copy `docs/contracts/scp_mcp_v1.md` from the OpenHarness repo over this repo’s [`docs/contracts/scp_mcp_v1.md`](contracts/scp_mcp_v1.md) (preserve UTF-8, LF).
2. Compute SHA-256:
   - PowerShell: `(Get-FileHash -Algorithm SHA256 -Path docs/contracts/scp_mcp_v1.md).Hash.ToLowerInvariant()`
   - POSIX: `sha256sum docs/contracts/scp_mcp_v1.md`
3. Update `EXPECTED_SCP_MCP_V1_SHA256` in [`tests/test_contract_document_hash.py`](../tests/test_contract_document_hash.py).
4. Run `pytest tests/test_contract_document_hash.py tests/test_mcp_contract_v1.py -v`.
5. Document in [CHANGELOG.md](../CHANGELOG.md) and set **CONTRACT_HASH** for releases (same value as the constant).

## Release discipline

1. Run `pytest tests/test_mcp_contract_v1.py tests/test_contract_document_hash.py` before tagging a release.
2. Record **CONTRACT_HASH** = SHA-256 of the vendored `docs/contracts/scp_mcp_v1.md` (must equal `EXPECTED_SCP_MCP_V1_SHA256` in tests).
3. Append a row to OpenHarness `docs/SCP_SERVER_RELEASES.md` if you publish hash mappings.
