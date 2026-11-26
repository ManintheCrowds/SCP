# PURPOSE: The head tree is clean under the base allowlist. A new test secret is not.

from __future__ import annotations

import hashlib
import os
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


def test_allowlist_env_override_is_honored(tmp_path: Path) -> None:
    token = "".join(("gh", "p_")) + ("C" * 36)
    rel = "tests/override_case.py"
    line = "value = " + token + "\n"
    dest = tmp_path / rel
    dest.parent.mkdir(parents=True)
    dest.write_text(line, encoding="utf-8")
    digest = hashlib.sha256(line[:-1].encode("utf-8")).hexdigest()
    allow = tmp_path / "allow.txt"
    allow.write_text(f"{rel}:{digest}:1\n", encoding="utf-8")
    env = os.environ.copy()
    env["SCP_MASK_ALLOWLIST"] = str(allow)
    env["SCP_MASK_CHECK_ROOT"] = str(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


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


def _allow_rows() -> list[tuple[str, str, int]]:
    rows: list[tuple[str, str, int]] = []
    for line in (_REPO / "scripts" / "mask_check_allow.txt").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rel, digest, count = stripped.split(":")
        rows.append((rel, digest, int(count)))
    if not rows:
        raise AssertionError("allowlist is empty")
    return rows


def _digest(line: str) -> str:
    body = line[:-1] if line.endswith("\n") else line
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT)],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )


def _copy(tmp_path: Path, rel: str, text: str) -> None:
    dest = tmp_path / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")


def test_a_changed_allowlisted_line_is_flagged(tmp_path: Path) -> None:
    rel, digest, _count = _allow_rows()[0]
    lines = (_REPO / rel).read_text(encoding="utf-8").splitlines(keepends=True)
    for index, line in enumerate(lines):
        if _digest(line) == digest:
            lines[index] = line.rstrip("\n") + " Z\n"
            break
    else:
        raise AssertionError("allowlisted line was not in the file")
    _copy(tmp_path, rel, "".join(lines))
    assert _run(tmp_path).returncode == 1


def test_a_blank_line_above_an_allowlisted_line_passes(tmp_path: Path) -> None:
    rel = _allow_rows()[0][0]
    text = (_REPO / rel).read_text(encoding="utf-8")
    _copy(tmp_path, rel, "\n" + text)
    assert _run(tmp_path).returncode == 0


def test_an_allowlisted_line_copied_to_another_file_is_flagged(tmp_path: Path) -> None:
    rel = _allow_rows()[0][0]
    text = (_REPO / rel).read_text(encoding="utf-8")
    _copy(tmp_path, "tests/copied_allowlist_case.py", text)
    assert _run(tmp_path).returncode == 1


def test_an_extra_occurrence_of_an_allowlisted_line_is_flagged(tmp_path: Path) -> None:
    rel, digest, _count = _allow_rows()[0]
    lines = (_REPO / rel).read_text(encoding="utf-8").splitlines(keepends=True)
    for line in lines:
        if _digest(line) == digest:
            lines.append(line if line.endswith("\n") else line + "\n")
            break
    else:
        raise AssertionError("allowlisted line was not in the file")
    _copy(tmp_path, rel, "".join(lines))
    assert _run(tmp_path).returncode == 1


def test_changed_allowlisted_line_is_not_covered(tmp_path: Path) -> None:
    rel = _allow_rows()[0][0]
    source = _REPO / rel
    copied = tmp_path / rel
    copied.parent.mkdir(parents=True, exist_ok=True)
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
