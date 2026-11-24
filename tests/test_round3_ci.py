# PURPOSE: Executed checks for the round-3 CI mutations.

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_GITLEAKS_PIN = "ff98106e4c7b2bc287b24eaf42907196329070c7"


def _workflow(name: str) -> str:
    return (_REPO / ".github" / "workflows" / name).read_text(encoding="utf-8")


def _run_block(workflow: str, step_name: str) -> str:
    lines = workflow.splitlines()
    name_line = f"name: {step_name}"
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped != name_line and stripped != f"- {name_line}":
            continue
        for cursor in range(index + 1, min(index + 40, len(lines))):
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


def _step_block(workflow: str, step_name: str) -> str:
    lines = workflow.splitlines()
    name_line = f"- name: {step_name}"
    for index, line in enumerate(lines):
        if line.strip() != name_line:
            continue
        indent = len(line) - len(line.lstrip(" "))
        block = [line]
        for raw in lines[index + 1 :]:
            if raw.strip() and (len(raw) - len(raw.lstrip(" "))) <= indent and raw.strip().startswith("- "):
                break
            block.append(raw)
        return "\n".join(block)
    raise AssertionError(step_name)


def _condition_runs_on_pull_request(condition: str) -> bool:
    condition = condition.strip()
    if not condition:
        return True
    match = re.fullmatch(r"github\.event_name\s*(!=|==)\s*'([^']+)'", condition)
    if match is None:
        return True
    op, value = match.group(1), match.group(2)
    if op == "==":
        return value == "pull_request"
    return value != "pull_request"


def test_pushed_masker_install_does_not_run_on_a_pull_request(tmp_path: Path) -> None:
    workflow = _workflow("ci.yml")
    block = _step_block(workflow, "Install the pushed masker")
    condition = ""
    for line in block.splitlines():
        if line.strip().startswith("if:"):
            condition = line.split(":", 1)[1].strip()
    if not _condition_runs_on_pull_request(condition):
        return
    script = _run_block(workflow, "Install the pushed masker")
    log = tmp_path / "pip-args"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "python3"
    stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$PIP_LOG\"\n", encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["PIP_LOG"] = str(log)
    subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, check=False)
    raise AssertionError("the pushed-masker install ran on a pull request: " + log.read_text(encoding="utf-8"))


def test_checker_refuses_a_masker_on_pythonpath(tmp_path: Path) -> None:
    head = tmp_path / "head"
    package = head / "src" / "scp"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "mask_secrets.py").write_text(
        "def has_secrets(text):\n    return False\n",
        encoding="utf-8",
    )
    note = head / "note.txt"
    note.write_text("see " + "".join(("gh", "p_")) + ("A" * 36) + "\n", encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(head / "src")
    env["SCP_MASK_CHECK_ROOT"] = str(head)
    proc = subprocess.run(
        ["python3", str(_REPO / "scripts" / "run_mask_check.py"), str(note)],
        cwd=head,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "refuses" in proc.stderr


def test_checker_step_clears_pythonpath(tmp_path: Path) -> None:
    script = _run_block(_workflow("ci.yml"), "Run the base mask checker")
    head = tmp_path / "head"
    base = tmp_path / "pinned-masker"
    (head / "scripts").mkdir(parents=True)
    (base / "scripts").mkdir(parents=True)
    (base / "scripts" / "run_mask_check.py").write_text("print('base')\n", encoding="utf-8")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "pythonpath"
    stub = bindir / "python3"
    stub.write_text(
        "#!/bin/sh\nprintf '%s' \"${PYTHONPATH-}\" > \"$PY_LOG\"\nexit 0\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["PY_LOG"] = str(log)
    env["PYTHONPATH"] = str(head / "src")
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_DIR"] = str(base)
    proc = subprocess.run(
        ["bash", "-c", script],
        cwd=head,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert log.read_text(encoding="utf-8") == ""


def test_skipped_mask_check_fails_the_aggregate(tmp_path: Path) -> None:
    script = _run_block(_workflow("ci.yml"), "Gate on upstream jobs")
    rendered = script
    values = {
        "needs.contract.result": "success",
        "needs.promptfoo-eval.result": "success",
        "needs.tests.result": "success",
        "needs.mask-check.result": "skipped",
    }
    for key, value in values.items():
        rendered = rendered.replace("${{ " + key + " }}", value)
    proc = subprocess.run(
        ["bash", "-c", rendered],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode != 0


def test_gitleaks_action_is_pinned_to_the_full_sha() -> None:
    uses = ""
    for line in _workflow("security-gitleaks.yml").splitlines():
        stripped = line.strip()
        if stripped.startswith("uses:") and "gitleaks-action@" in stripped:
            uses = stripped.split(":", 1)[1].strip()
            break

    def accept(action: str) -> int:
        owner, _, rest = action.partition("/")
        _name, _, sha = rest.partition("@")
        if owner != "gitleaks" or sha != _GITLEAKS_PIN:
            raise SystemExit(2)
        return 0

    assert accept(uses) == 0

