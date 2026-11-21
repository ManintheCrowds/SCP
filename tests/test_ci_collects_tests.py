# PURPOSE: Execute the CI pytest command and require every test module.
# Switching the command back to a single file, or dropping a timeout, fails.

from __future__ import annotations

import re
import subprocess
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOWS = (
    _REPO / ".github" / "workflows" / "ci.yml",
    _REPO / ".github" / "workflows" / "security-gitleaks.yml",
)
# Pre-existing failures: contract bytes drifted from the pinned digests, and
# the nostr helper exits when coincurve is not installed.
_ALLOWED_IGNORE = frozenset(
    {
        "tests/test_setup_mycelium_nostr_key.py",
        "tests/test_contract_document_hash.py",
    }
)


def _run_block(workflow: str, step_name: str) -> str:
    lines = workflow.splitlines()
    name_line = f"name: {step_name}"
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped != name_line and stripped != f"- {name_line}":
            continue
        for cursor in range(index + 1, min(index + 25, len(lines))):
            if lines[cursor].strip() != "run: |":
                continue
            body: list[str] = []
            base_indent: int | None = None
            for raw in lines[cursor + 1 :]:
                if raw.strip() == "":
                    body.append("")
                    continue
                indent = len(raw) - len(raw.lstrip(" "))
                if base_indent is None:
                    base_indent = indent
                if indent < base_indent:
                    break
                body.append(raw[base_indent:])
            if base_indent is None:
                raise AssertionError(f"empty run block for {step_name}")
            return "\n".join(body).strip() + "\n"
    raise AssertionError(f"missing run block for {step_name}")


def _job_blocks(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    start = lines.index("jobs:")
    jobs: list[tuple[str, str]] = []
    name = ""
    buf: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            if name:
                jobs.append((name, "\n".join(buf)))
            name = line.strip().rstrip(":")
            buf = [line]
            continue
        buf.append(line)
    if name:
        jobs.append((name, "\n".join(buf)))
    return jobs


def test_ci_pytest_command_collects_every_module() -> None:
    workflow = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    script = _run_block(workflow, "Run unit tests")
    ignores = set(re.findall(r"--ignore=(\S+)", script))
    assert ignores == _ALLOWED_IGNORE
    collect = script.replace("--tb=line", "--collect-only --tb=no")
    if "--collect-only" not in collect:
        collect = collect.rstrip() + " --collect-only -q\n"
    proc = subprocess.run(
        ["bash", "-c", collect],
        cwd=_REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    collected = {
        line.split("::", 1)[0]
        for line in proc.stdout.splitlines()
        if line.startswith("tests/") and "::" in line
    }
    on_disk = {f"tests/{path.name}" for path in (_REPO / "tests").glob("test_*.py")}
    assert collected == on_disk - _ALLOWED_IGNORE


def test_every_job_sets_timeout_minutes() -> None:
    for path in _WORKFLOWS:
        jobs = _job_blocks(path.read_text(encoding="utf-8"))
        assert jobs, path.name
        for name, block in jobs:
            assert "timeout-minutes:" in block, f"{path.name}:{name}"
