# PURPOSE: SHA-256 regression for vendored OpenHarness MCP contract document.
# When docs/contracts/scp_mcp_v1.md changes, update EXPECTED_SCP_MCP_V1_SHA256 per docs/OPENHARNESS_CONTRACT.md.

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

# Synced with OpenHarness docs/contracts/scp_mcp_v1.md (v1.0)
EXPECTED_SCP_MCP_V1_SHA256 = (
    "226f19b3cf237a2d7fe6793d4f7f4be5bee5631693f489662c48d126b4094f42"
)


@pytest.fixture
def contract_path() -> Path:
    root = Path(__file__).resolve().parents[1]
    return root / "docs" / "contracts" / "scp_mcp_v1.md"


def test_vendored_scp_mcp_v1_contract_sha256(contract_path: Path) -> None:
    assert contract_path.is_file(), f"Missing vendored contract: {contract_path}"
    data = contract_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == EXPECTED_SCP_MCP_V1_SHA256, (
        f"Contract document hash mismatch. Update EXPECTED_SCP_MCP_V1_SHA256 if you "
        f"synced docs/contracts/scp_mcp_v1.md from OpenHarness. "
        f"got={digest} expected={EXPECTED_SCP_MCP_V1_SHA256}"
    )
