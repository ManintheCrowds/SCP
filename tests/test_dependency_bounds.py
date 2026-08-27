from __future__ import annotations

import tomllib
from pathlib import Path


def test_mcp_dependency_stays_on_fastmcp_compatible_major() -> None:
    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = pyproject["project"]["dependencies"]

    assert any(dep.startswith("mcp>=") and "<2.0.0" in dep for dep in dependencies)
    assert "<2.0.0" in (root / "requirements.txt").read_text(encoding="utf-8")
