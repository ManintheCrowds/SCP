from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_mcp_dependency_stays_on_fastmcp_compatible_major() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = pyproject["project"]["dependencies"]
    assert any(dep.startswith("mcp>=") and "<2" in dep for dep in dependencies)

    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    assert any(req.startswith("mcp>=") and "<2" in req for req in requirements)
