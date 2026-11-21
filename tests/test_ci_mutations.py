# PURPOSE: Executed checks for the CI and budget mutations that must stay red.

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from scp import mask_secrets, secret_surface

_REPO = Path(__file__).resolve().parents[1]


def _run_block(workflow: str, step_name: str) -> str:
    lines = workflow.splitlines()
    name_line = f"name: {step_name}"
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped != name_line and stripped != f"- {name_line}":
            continue
        for cursor in range(index + 1, min(index + 30, len(lines))):
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


def _ci() -> str:
    return (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def _gitleaks() -> str:
    return (_REPO / ".github" / "workflows" / "security-gitleaks.yml").read_text(encoding="utf-8")


def test_h1e_install_uses_the_base_tree_not_head(tmp_path: Path) -> None:
    script = _run_block(_ci(), "Install the base masker when that revision has a checker")
    root = tmp_path / "work"
    (root / "pinned-masker" / "scripts").mkdir(parents=True)
    (root / "head" / "scripts").mkdir(parents=True)
    (root / "pinned-masker" / "scripts" / "run_mask_check.py").write_text("pass\n", encoding="utf-8")
    (root / "head" / "scripts" / "run_mask_check.py").write_text("pass\n", encoding="utf-8")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "pip-args"
    stub = bindir / "python3"
    stub.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$PIP_LOG\"\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["PIP_LOG"] = str(log)
    proc = subprocess.run(
        ["bash", "-c", script],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    recorded = log.read_text(encoding="utf-8")
    assert "pinned-masker" in recorded
    assert "./head" not in recorded


def test_h1d_base_checkout_ref_is_the_base_sha() -> None:
    lines = _ci().splitlines()
    ref = ""
    for index, line in enumerate(lines):
        if line.strip() != "path: pinned-masker":
            continue
        for older in range(index, max(index - 8, -1), -1):
            if lines[older].strip().startswith("ref:"):
                ref = lines[older].split(":", 1)[1].strip()
                break
    base_sha = "base-sha"
    head_sha = "head-sha"
    resolved = {
        "${{ github.event.pull_request.base.sha }}": base_sha,
        "${{ github.event.pull_request.head.sha }}": head_sha,
        "${{ github.sha }}": head_sha,
    }.get(ref, head_sha if not ref else ref)
    assert resolved == base_sha
    assert resolved != head_sha


def test_h1f_base_dir_is_not_the_head_tree(tmp_path: Path) -> None:
    workflow = _ci()
    block = _step_block(workflow, "Run the base mask checker")
    script = _run_block(workflow, "Run the base mask checker")
    assignment = ""
    for line in block.splitlines():
        if line.strip().startswith("BASE_DIR:"):
            assignment = line.split(":", 1)[1].strip()
    workspace = tmp_path / "ws"
    head = workspace / "head"
    base = workspace / "pinned-masker"
    (head / "scripts").mkdir(parents=True)
    (base / "scripts").mkdir(parents=True)
    (head / "scripts" / "run_mask_check.py").write_text(
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    (base / "scripts" / "run_mask_check.py").write_text(
        "raise SystemExit(9)\n",
        encoding="utf-8",
    )
    mapping = {
        "${{ github.workspace }}/pinned-masker": str(base),
        "${{ github.workspace }}/head": str(head),
    }
    chosen = mapping.get(assignment, str(head))
    env = os.environ.copy()
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_DIR"] = chosen
    proc = subprocess.run(
        ["bash", "-c", script],
        cwd=head,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 9
    assert chosen == str(base)


def test_dropping_mask_check_from_the_aggregate_fails(tmp_path: Path) -> None:
    script = _run_block(_ci(), "Gate on upstream jobs")
    rendered = script
    values = {
        "needs.contract.result": "success",
        "needs.promptfoo-eval.result": "success",
        "needs.tests.result": "success",
        "needs.mask-check.result": "failure",
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


def test_continue_on_error_does_not_hide_a_checker_failure(tmp_path: Path) -> None:
    workflow = _ci()
    block = _step_block(workflow, "Run the base mask checker")
    script = _run_block(workflow, "Run the base mask checker")
    tolerated = "continue-on-error: true" in block
    env = os.environ.copy()
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_DIR"] = str(tmp_path / "missing-base")
    proc = subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    job_failed = proc.returncode != 0 and not tolerated
    assert job_failed


def test_gitleaks_action_owner_is_upstream() -> None:
    uses = ""
    for line in _gitleaks().splitlines():
        if line.strip().startswith("uses:") and "gitleaks" in line.lower() or (
            line.strip().startswith("uses:") and "action" in line
        ):
            if "checkout" in line or "setup-" in line:
                continue
            uses = line.split(":", 1)[1].strip()
            break
    owner = uses.split("/", 1)[0]

    def dispatch(action_owner: str) -> int:
        if action_owner != "gitleaks":
            raise SystemExit(2)
        return 0

    assert dispatch(owner) == 0


def test_budget_factor_rejects_superlinear_work() -> None:
    length = 1_000
    budget = secret_surface._budget_for(length)
    assert int(length**1.5) > budget


def test_egress_residual_check_blocks_an_unmasked_token(monkeypatch) -> None:
    secret = "".join(("gh", "p_")) + ("A" * 36)
    monkeypatch.setattr(mask_secrets, "mask", lambda text: text)
    try:
        mask_secrets.prepare_outbound("note " + secret + "\n")
    except mask_secrets.EgressMaskError as exc:
        assert "residual" in exc.remaining
    else:
        raise AssertionError("egress returned text that still contains a token")
