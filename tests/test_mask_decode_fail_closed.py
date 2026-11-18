# PURPOSE: CLI reads fail closed on invalid UTF-8 and NUL bytes. No replacement characters.

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"


def _run(args: list[str], payload: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), *args],
        input=payload,
        capture_output=True,
        check=False,
    )


def test_egress_stdin_invalid_utf8_emits_nothing() -> None:
    proc = _run(["--egress-prepare", "-"], b"hello \xff")
    assert proc.returncode != 0
    assert proc.stdout == b""
    assert b"\xff" not in proc.stderr


def test_egress_stdin_nul_emits_nothing() -> None:
    proc = _run(["--egress-prepare", "-"], b"hello\x00world")
    assert proc.returncode != 0
    assert proc.stdout == b""
    assert b"\x00" not in proc.stderr


def test_egress_file_invalid_utf8_emits_nothing(tmp_path: Path) -> None:
    path = tmp_path / "handoff.md"
    path.write_bytes(b"note \xff")
    proc = _run(["--egress-prepare", str(path)], b"")
    assert proc.returncode != 0
    assert proc.stdout == b""
    assert b"\xff" not in proc.stderr


def test_check_file_nul_fails_without_echoing(tmp_path: Path) -> None:
    path = tmp_path / "handoff.md"
    path.write_bytes(b"ok\x00")
    proc = _run(["--check", str(path)], b"")
    assert proc.returncode != 0
    assert proc.stdout == b""
    assert b"\x00" not in proc.stderr


def test_plain_stdin_invalid_utf8_emits_nothing() -> None:
    proc = _run(["-"], b"\xff")
    assert proc.returncode != 0
    assert proc.stdout == b""
