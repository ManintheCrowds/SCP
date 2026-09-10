from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _normalize_requirement(req: str) -> str:
    return req.replace(" ", "").lower()


def test_mcp_dependency_is_bounded_to_fastmcp_compatible_major() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = pyproject["project"]["dependencies"]

    assert any(
        dep.startswith("mcp") and "<2.0.0" in _normalize_requirement(dep)
        for dep in dependencies
    )

    requirements = [
        line.strip()
        for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert any(
        req.startswith("mcp") and "<2.0.0" in _normalize_requirement(req)
        for req in requirements
    )
