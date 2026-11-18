# PURPOSE: A pull request cannot point mask-check at a head resolver that always passes.

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]


def test_ci_invokes_the_base_script_not_the_head_resolver() -> None:
    section = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    section = section.split("mask-check:", 1)[1].split("\n  CI:", 1)[0]
    assert "pinned-masker/scripts/run_mask_check.py" in section
    assert "--resolve-runner" not in section


def test_sabotaged_head_resolver_still_fails_on_a_staged_key(tmp_path: Path) -> None:
    head = tmp_path / "head"
    base = tmp_path / "pinned-masker"
    (head / "scripts").mkdir(parents=True)
    (head / ".cursor" / "state").mkdir(parents=True)
    (base / "scripts").mkdir(parents=True)
    (head / "scripts" / "run_mask_check.py").write_text(
        "import sys\nprint('fallback')\nsys.exit(0)\n",
        encoding="utf-8",
    )
    shutil.copy(_REPO / "scripts" / "run_mask_check.py", base / "scripts" / "run_mask_check.py")
    shutil.copy(_REPO / ".pre-commit-config.yaml", base / ".pre-commit-config.yaml")
    token = "AK" + "IA" + ("C" * 16)
    note = head / ".cursor" / "state" / "handoff.md"
    note.write_text("note\n" + token + "\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=head, check=True, capture_output=True)
    subprocess.run(["git", "add", ".cursor/state/handoff.md"], cwd=head, check=True, capture_output=True)
    env = os.environ.copy()
    env["SCP_MASK_CHECK_ROOT"] = str(head)
    env["SCP_MASK_CHECK_CONFIG"] = str(base / ".pre-commit-config.yaml")
    base_script = base / "scripts" / "run_mask_check.py"
    assert base_script.is_file()
    proc = subprocess.run(
        [sys.executable, str(base_script)],
        cwd=head,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert token not in proc.stdout
    assert "fallback" not in proc.stdout
