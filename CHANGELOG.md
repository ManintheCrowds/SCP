# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Vendored OpenHarness contract [`docs/contracts/scp_mcp_v1.md`](docs/contracts/scp_mcp_v1.md) with SHA-256 check in `tests/test_contract_document_hash.py`; sync steps in [`docs/OPENHARNESS_CONTRACT.md`](docs/OPENHARNESS_CONTRACT.md).
- `engines` for Node in `examples/promptfoo/package.json` (aligned with promptfoo and CI).
- Optional Dependabot updates for `examples/promptfoo` (`.github/dependabot.yml`).
- `examples/promptfoo/` — offline promptfoo eval calling `scp.scp_utils.inspect` (pinned promptfoo **0.121.3+** for correct Windows path handling in the Python worker).
- CI job `promptfoo-eval` (`.github/workflows/ci.yml`) running `npx promptfoo eval` after `npm ci`.
- `docs/brainstorms/2026-04-01-promptfoo-scp-learning-brainstorm.md` — learning-loop design from promptfoo outputs to SCP defenses.
- CI-oriented contract test `tests/test_mcp_contract_v1.py` aligned with OpenHarness `scp_mcp_v1.md`.
- `docs/OPENHARNESS_CONTRACT.md` pointer to the public contract.

### Release checklist (maintainers)

- **CONTRACT_HASH** must match the vendored file and `EXPECTED_SCP_MCP_V1_SHA256` in `tests/test_contract_document_hash.py` (see [`docs/OPENHARNESS_CONTRACT.md`](docs/OPENHARNESS_CONTRACT.md)).
