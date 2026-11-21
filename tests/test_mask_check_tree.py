# PURPOSE: The head tree is clean under the base allowlist. A new test secret is not.

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "run_mask_check.py"


def _token() -> str:
    return "".join(("gh", "p_")) + ("B" * 36)


def test_head_tree_is_clean() -> None:
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        cwd=_REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stderr == ""


def test_new_secret_in_tests_still_fails(tmp_path: Path) -> None:
    token = _token()
    path = tmp_path / "tests" / "fresh.py"
    path.parent.mkdir()
    path.write_text("value = " + token + "\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT), str(path)],
        cwd=_REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    assert token not in proc.stdout
    assert token not in proc.stderr


def test_changed_allowlisted_line_is_not_covered(tmp_path: Path) -> None:
    source = _REPO / "tests" / "test_line_wrap.py"
    copied = tmp_path / "tests" / "test_line_wrap.py"
    copied.parent.mkdir()
    text = source.read_text(encoding="utf-8")
    copied.write_text(text + "\nvalue = " + _token() + "\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT), str(copied)],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
