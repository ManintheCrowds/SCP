# OpenHarness SCP contract

The public **normative** specification for this MCP server’s tool surface is:

**OpenHarness** `docs/contracts/scp_mcp_v1.md` (in the OpenHarness repository).

## Release discipline

1. Run `pytest tests/test_mcp_contract_v1.py` before tagging a release.
2. Record **CONTRACT_HASH** = SHA-256 of `scp_mcp_v1.md` at release time (copy file from OpenHarness or compute against pinned revision).
3. Append a row to OpenHarness `docs/SCP_SERVER_RELEASES.md` if you publish hash mappings.
