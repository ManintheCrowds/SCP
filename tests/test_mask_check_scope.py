# PURPOSE: docs, fixtures, tests, and .cursor are in the mask-check scan.

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_mask_check.py"


def _token() -> str:
    return "".join(("gh", "p_")) + ("A" * 36)


def test_checked_trees_are_scanned_and_source_is_not(tmp_path: Path) -> None:
    token = _token()
    roots = {
        tmp_path / "docs" / "note.md": token,
        tmp_path / "fixtures" / "sample.json": token,
        tmp_path / "tests" / "note.py": token,
        tmp_path / ".cursor" / "note.md": token,
        tmp_path / "src" / "app.py": "key = name\n" + token,
        tmp_path / "docs" / "clean.md": "Thanks for the note.\n",
    }
    for path, text in roots.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    reported = proc.stderr
    assert "docs/note.md" in reported
    assert "fixtures/sample.json" in reported
    assert "tests/note.py" in reported
    assert ".cursor/note.md" in reported
    assert "src/app.py" not in reported
    assert "docs/clean.md" not in reported
    assert token not in proc.stdout
    assert token not in proc.stderr
