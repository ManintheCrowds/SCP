# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- CI-oriented contract test `tests/test_mcp_contract_v1.py` aligned with OpenHarness `scp_mcp_v1.md`.
- `docs/OPENHARNESS_CONTRACT.md` pointer to the public contract.

### Release checklist (maintainers)

- Set **CONTRACT_HASH** to SHA-256 (lowercase hex) of the OpenHarness file `docs/contracts/scp_mcp_v1.md` for the revision you support.
- Example (PowerShell, after copying contract into this repo or opening OpenHarness):

  `(Get-FileHash -Algorithm SHA256 -Path path/to/scp_mcp_v1.md).Hash.ToLowerInvariant()`
