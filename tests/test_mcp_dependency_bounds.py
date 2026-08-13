from __future__ import annotations

from pathlib import Path


MCP_1X_BOUND = "mcp>=1.2.0,<2.0.0"


def test_fastmcp_dependency_is_pinned_to_compatible_major() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    requirements = Path("requirements.txt").read_text(encoding="utf-8")

    assert MCP_1X_BOUND in pyproject
    assert MCP_1X_BOUND in requirements
