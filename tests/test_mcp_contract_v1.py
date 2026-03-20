# PURPOSE: Conformance tests for OpenHarness docs/contracts/scp_mcp_v1.md tool surface.
# Run: pytest tests/test_mcp_contract_v1.py (from repo root, optional: pip install -e ".[dev]")

from __future__ import annotations

import ast
from pathlib import Path

import pytest

# Normative set from OpenHarness docs/contracts/scp_mcp_v1.md (v1.0)
CONTRACT_V1_TOOLS = frozenset(
    {
        "scp_contain",
        "scp_inspect",
        "scp_list_quarantine",
        "scp_mask_secrets",
        "scp_purge_quarantine",
        "scp_quarantine",
        "scp_run_pipeline",
        "scp_sanitize",
        "scp_validate_output",
    }
)


def _mcp_tool_functions(py_path: Path) -> set[str]:
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            fn = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(fn, ast.Attribute) and fn.attr == "tool":
                if isinstance(fn.value, ast.Name) and fn.value.id == "mcp":
                    out.add(node.name)
    return out


@pytest.fixture
def scp_mcp_path() -> Path:
    root = Path(__file__).resolve().parents[1]
    return root / "src" / "scp" / "scp_mcp.py"


def test_scp_mcp_exposes_contract_v1_tools(scp_mcp_path: Path) -> None:
    assert scp_mcp_path.is_file(), f"Missing {scp_mcp_path}"
    implemented = _mcp_tool_functions(scp_mcp_path)
    assert implemented == CONTRACT_V1_TOOLS, (
        f"Tool set drift. contract={sorted(CONTRACT_V1_TOOLS)} "
        f"implemented={sorted(implemented)}"
    )
