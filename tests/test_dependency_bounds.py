from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_pins_mcp_to_fastmcp_compatible_major() -> None:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = data["project"]["dependencies"]
    mcp_deps = [dep for dep in dependencies if dep.startswith("mcp")]

    assert mcp_deps
    assert any("<2" in dep for dep in mcp_deps)


def test_requirements_pins_mcp_to_fastmcp_compatible_major() -> None:
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    mcp_reqs = [line for line in requirements if line.startswith("mcp")]

    assert mcp_reqs
    assert any("<2" in req for req in mcp_reqs)
