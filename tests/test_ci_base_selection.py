# PURPOSE: Execute the CI selection steps. A head checker or head gitleaks
# config must not be the one that runs.

from __future__ import annotations

import os
import subprocess
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]


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


def _gitleaks_config_expr(workflow: str) -> str:
    for line in workflow.splitlines():
        stripped = line.strip()
        if stripped.startswith("GITLEAKS_CONFIG:"):
            return stripped.split(":", 1)[1].strip()
    raise AssertionError("GITLEAKS_CONFIG is missing")


def _execute(script: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", script],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_pull_request_mask_check_executes_the_base_checker(tmp_path: Path) -> None:
    workflow = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    script = _run_block(workflow, "Run the base mask checker")
    head = tmp_path / "head"
    base = tmp_path / "pinned-masker"
    (head / "scripts").mkdir(parents=True)
    (base / "scripts").mkdir(parents=True)
    (head / "scripts" / "run_mask_check.py").write_text(
        "from pathlib import Path\nPath('head-ran').write_text('x')\nraise SystemExit(0)\n",
        encoding="utf-8",
    )
    (base / "scripts" / "run_mask_check.py").write_text(
        "from pathlib import Path\nPath('base-ran').write_text('x')\nraise SystemExit(9)\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_DIR"] = str(base)
    proc = _execute(script, head, env)
    assert proc.returncode == 9
    assert (head / "base-ran").is_file()
    assert not (head / "head-ran").exists()


def test_missing_base_checker_fails_closed(tmp_path: Path) -> None:
    workflow = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    script = _run_block(workflow, "Run the base mask checker")
    head = tmp_path / "head"
    (head / "scripts").mkdir(parents=True)
    (head / "scripts" / "run_mask_check.py").write_text(
        "from pathlib import Path\nPath('head-ran').write_text('x')\nraise SystemExit(0)\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_DIR"] = str(tmp_path / "pinned-masker")
    proc = _execute(script, head, env)
    assert proc.returncode != 0
    assert not (head / "head-ran").exists()
    assert "failing closed" in proc.stderr


def test_push_runs_the_commit_checker(tmp_path: Path) -> None:
    workflow = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    script = _run_block(workflow, "Run the base mask checker")
    head = tmp_path / "head"
    (head / "scripts").mkdir(parents=True)
    (head / "scripts" / "run_mask_check.py").write_text(
        "raise SystemExit(4)\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["GITHUB_EVENT_NAME"] = "push"
    env["BASE_DIR"] = str(tmp_path / "missing")
    proc = _execute(script, head, env)
    assert proc.returncode == 4


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
    return proc.stdout.strip()


def test_gitleaks_selection_executes_the_base_config(tmp_path: Path) -> None:
    workflow = (_REPO / ".github" / "workflows" / "security-gitleaks.yml").read_text(encoding="utf-8")
    script = _run_block(workflow, "Select the base gitleaks config")
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / ".gitleaks.toml").write_text('title = "base-config-marker"\n', encoding="utf-8")
    _git(repo, "add", ".gitleaks.toml")
    _git(repo, "commit", "-m", "base config")
    base_sha = _git(repo, "rev-parse", "HEAD")
    (repo / ".gitleaks.toml").write_text('title = "head-config-marker"\n', encoding="utf-8")
    runner = tmp_path / "runner"
    runner.mkdir()
    output = tmp_path / "output"
    env = os.environ.copy()
    env.update(
        {
            "GITHUB_EVENT_NAME": "pull_request",
            "BASE_SHA": base_sha,
            "RUNNER_TEMP": str(runner),
            "GITHUB_OUTPUT": str(output),
        }
    )
    proc = _execute(script, repo, env)
    assert proc.returncode == 0, proc.stderr
    selected = dict(
        item.split("=", 1) for item in output.read_text(encoding="utf-8").splitlines() if "=" in item
    )["path"]
    expr = _gitleaks_config_expr(workflow)
    if "steps.gitleaks-config.outputs.path" not in expr:
        chosen = repo / ".gitleaks.toml"
    else:
        chosen = Path(selected)
    body = chosen.read_text(encoding="utf-8")
    assert "base-config-marker" in body
    assert "head-config-marker" not in body


def test_missing_base_gitleaks_config_fails_closed(tmp_path: Path) -> None:
    workflow = (_REPO / ".github" / "workflows" / "security-gitleaks.yml").read_text(encoding="utf-8")
    script = _run_block(workflow, "Select the base gitleaks config")
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / "README").write_text("note\n", encoding="utf-8")
    _git(repo, "add", "README")
    _git(repo, "commit", "-m", "no config")
    base_sha = _git(repo, "rev-parse", "HEAD")
    (repo / ".gitleaks.toml").write_text('title = "head-config-marker"\n', encoding="utf-8")
    runner = tmp_path / "runner"
    runner.mkdir()
    env = os.environ.copy()
    env.update(
        {
            "GITHUB_EVENT_NAME": "pull_request",
            "BASE_SHA": base_sha,
            "RUNNER_TEMP": str(runner),
            "GITHUB_OUTPUT": str(tmp_path / "output"),
        }
    )
    proc = _execute(script, repo, env)
    assert proc.returncode != 0
    assert "failing closed" in proc.stderr


def test_checker_flags_a_synthetic_assignment_without_echoing_it(tmp_path: Path) -> None:
    token = "gh" + "p_" + ("A" * 36)
    path = tmp_path / "note.txt"
    path.write_text("export GH_TOKEN=" + token + "\n", encoding="utf-8")
    script = _REPO / "scripts" / "run_mask_check.py"
    proc = subprocess.run(
        ["python3", str(script), str(path)],
        cwd=_REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    assert token not in proc.stdout
    assert token not in proc.stderr
    clean = tmp_path / "clean.txt"
    clean.write_text("Thanks for the note.\n", encoding="utf-8")
    proc = subprocess.run(
        ["python3", str(script), str(clean)],
        cwd=_REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
