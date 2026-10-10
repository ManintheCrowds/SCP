from __future__ import annotations

from pathlib import Path


MCP_V1_BOUND = "mcp>=1.2.0,<2.0.0"


def test_pyproject_pins_fastmcp_compatible_mcp_line() -> None:
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")

    assert MCP_V1_BOUND in pyproject


def test_requirements_pins_fastmcp_compatible_mcp_line() -> None:
    root = Path(__file__).resolve().parents[1]
    requirements = (root / "requirements.txt").read_text(encoding="utf-8").splitlines()

    assert MCP_V1_BOUND in requirements
