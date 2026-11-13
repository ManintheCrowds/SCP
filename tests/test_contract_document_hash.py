# PURPOSE: SHA-256 regression for vendored OpenHarness MCP contract documents.
# When docs/contracts/*.md changes, update EXPECTED_* constants per docs/OPENHARNESS_CONTRACT.md.

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

# Synced with OpenHarness docs/contracts/scp_mcp_v1.md (v1.0).
# Pin is the LF byte string stored in git, not a CRLF working-copy hash.
EXPECTED_SCP_MCP_V1_SHA256 = (
    "69a40c210d4a4999358ad1655c60ded39e442a8d451fe2f69a1e1a0f31a5ae4f"
)

# Synced with OpenHarness docs/contracts/scp_mcp_v1.1.md (optional add-ons)
EXPECTED_SCP_MCP_V1_1_SHA256 = (
    "b4c826997cab5ff380ce779278d41e25171b4df309027d2fdbd847245e4167db"
)

# Synced with OpenHarness docs/contracts/scp_antigen_mcp_v1.md (SCP vendor — AppSec quarantine path + body caps)
EXPECTED_SCP_ANTIGEN_MCP_V1_SHA256 = (
    "6c7bdcec8f82f12054abc87b71e85a331ce728aed875164da3692b486cc3d8fa"
)


@pytest.fixture
def contracts_dir() -> Path:
    root = Path(__file__).resolve().parents[1]
    return root / "docs" / "contracts"


def _contract_bytes(path: Path) -> bytes:
    """LF form of a vendored contract.

    Windows checkouts may rewrite newlines to CRLF. The pin matches the LF
    bytes in git, so the same file hashes the same on both platforms.
    """
    return path.read_bytes().replace(b"\r\n", b"\n")


def _assert_contract_sha(path: Path, expected: str, label: str) -> None:
    assert path.is_file(), f"Missing vendored contract: {path}"
    digest = hashlib.sha256(_contract_bytes(path)).hexdigest()
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
