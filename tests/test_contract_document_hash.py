# PURPOSE: SHA-256 regression for vendored OpenHarness MCP contract documents.
# When docs/contracts/*.md changes, update EXPECTED_* constants per docs/OPENHARNESS_CONTRACT.md.

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

# Synced with OpenHarness docs/contracts/scp_mcp_v1.md (v1.0)
EXPECTED_SCP_MCP_V1_SHA256 = (
    "226f19b3cf237a2d7fe6793d4f7f4be5bee5631693f489662c48d126b4094f42"
)

# Synced with OpenHarness docs/contracts/scp_mcp_v1.1.md (optional add-ons)
EXPECTED_SCP_MCP_V1_1_SHA256 = (
    "722aca69cc97550dfe742c5fefffbc7f958d871ab269b7373a2359351af734ab"
)

# Synced with OpenHarness docs/contracts/scp_antigen_mcp_v1.md
EXPECTED_SCP_ANTIGEN_MCP_V1_SHA256 = (
    "bc44c12956fe1c819220b02069ead357ccea0ca3b72774d47ec12590a965c64b"
)


@pytest.fixture
def contracts_dir() -> Path:
    root = Path(__file__).resolve().parents[1]
    return root / "docs" / "contracts"


def _assert_contract_sha(path: Path, expected: str, label: str) -> None:
    assert path.is_file(), f"Missing vendored contract: {path}"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == expected, (
        f"{label} hash mismatch. Update EXPECTED constant if synced from OpenHarness. "
        f"got={digest} expected={expected}"
    )


def test_vendored_scp_mcp_v1_contract_sha256(contracts_dir: Path) -> None:
    _assert_contract_sha(
        contracts_dir / "scp_mcp_v1.md",
        EXPECTED_SCP_MCP_V1_SHA256,
        "scp_mcp_v1",
    )


def test_vendored_scp_mcp_v1_1_contract_sha256(contracts_dir: Path) -> None:
    _assert_contract_sha(
        contracts_dir / "scp_mcp_v1.1.md",
        EXPECTED_SCP_MCP_V1_1_SHA256,
        "scp_mcp_v1.1",
    )


def test_vendored_scp_antigen_mcp_v1_contract_sha256(contracts_dir: Path) -> None:
    _assert_contract_sha(
        contracts_dir / "scp_antigen_mcp_v1.md",
        EXPECTED_SCP_ANTIGEN_MCP_V1_SHA256,
        "scp_antigen_mcp_v1",
    )
