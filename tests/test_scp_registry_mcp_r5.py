# PURPOSE: SCP-R5 slice B — v1.1 optional registry MCP tools.
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from scp import registry_paths
from scp import scp_mcp

CONTRACT_V1_1_TOOLS = frozenset({"scp_registry_summary", "scp_registry_section"})


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


def test_scp_mcp_exposes_v1_1_registry_tools(scp_mcp_path: Path) -> None:
    implemented = _mcp_tool_functions(scp_mcp_path)
    assert CONTRACT_V1_1_TOOLS <= implemented


def test_registry_section_rejects_unknown_section(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reg = tmp_path / "reg.json"
    reg.write_text(json.dumps({"power_words": ["a"], "version": "1"}), encoding="utf-8")
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(reg))
    out = json.loads(scp_mcp.scp_registry_section("not_allowlisted_section"))
    assert "error" in out
    assert out["error"]["code"] == "invalid_input"


def test_registry_section_max_chars_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reg = tmp_path / "reg.json"
    reg.write_text(json.dumps({"power_words": ["word"] * 200, "version": "1"}), encoding="utf-8")
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(reg))
    out = json.loads(scp_mcp.scp_registry_section("power_words", max_chars=50))
    assert out["truncated"] is True
    assert len(out["excerpt"]) <= 51


def test_registry_summary_counts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reg = tmp_path / "reg.json"
    reg.write_text(
        json.dumps({"power_words": ["a", "b"], "version": "1", "updated": "x"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(reg))
    out = json.loads(scp_mcp.scp_registry_summary())
    assert out["sections"]["power_words"] == 2
    assert out["registry_path"] == "redacted"
    assert registry_paths.resolve_threat_registry_path() == reg
