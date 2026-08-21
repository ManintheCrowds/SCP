from __future__ import annotations

import re
from pathlib import Path


DEPENDENCY_RE = re.compile(r'"([^"]+)"')
PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _project_dependencies() -> list[str]:
    dependencies: list[str] = []
    in_dependencies = False

    for line in PYPROJECT.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "dependencies = [":
            in_dependencies = True
            continue
        if in_dependencies and stripped == "]":
            break
        if in_dependencies:
            dependencies.extend(DEPENDENCY_RE.findall(line))

    return dependencies


def test_mcp_dependency_stays_fastmcp_compatible():
    mcp_dependency = next(
        dep for dep in _project_dependencies() if dep.startswith("mcp")
    )

    assert "<2.0.0" in mcp_dependency
