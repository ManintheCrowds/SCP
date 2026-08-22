from __future__ import annotations

import tomllib
from pathlib import Path


def test_mcp_dependency_stays_on_fastmcp_compatible_major() -> None:
    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project_deps = pyproject["project"]["dependencies"]
    requirement_lines = (root / "requirements.txt").read_text(encoding="utf-8").splitlines()

    assert "mcp>=1.2.0,<2.0.0" in project_deps
    assert "mcp>=1.2.0,<2.0.0" in requirement_lines
