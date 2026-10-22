from __future__ import annotations

import tomllib
from pathlib import Path


def test_mcp_dependency_excludes_fastmcp_incompatible_v2() -> None:
    """FastMCP imports require the MCP 1.x SDK line."""
    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = pyproject["project"]["dependencies"]
    mcp_specs = [dep for dep in dependencies if dep.startswith("mcp")]

    assert mcp_specs, "pyproject.toml must declare the mcp runtime dependency"
    assert any("<2" in spec.replace(" ", "") for spec in mcp_specs), (
        "mcp.server.fastmcp is removed in MCP 2.x; bound mcp below 2.0"
    )
