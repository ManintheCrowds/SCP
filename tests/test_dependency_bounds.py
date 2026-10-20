from __future__ import annotations

from pathlib import Path


def test_mcp_dependency_is_bounded_to_fastmcp_compatible_major() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    requirements = Path("requirements.txt").read_text(encoding="utf-8")

    assert '"mcp>=1.2.0,<2.0.0"' in pyproject
    assert "mcp>=1.2.0,<2.0.0" in requirements.splitlines()
