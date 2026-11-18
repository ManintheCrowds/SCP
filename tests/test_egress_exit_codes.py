# PURPOSE: Oversize input, leftover secrets, and control characters use distinct results.

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scp import mask_secrets

_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"


def _run(payload: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), "--egress-prepare", "-"],
        input=payload,
        capture_output=True,
        check=False,
    )


def test_oversize_reports_input_too_large() -> None:
    proc = _run(b"b" * (mask_secrets.MAX_CLI_BYTES + 1))
    assert proc.returncode == 2
    assert proc.stdout == b""
    assert b"input too large" in proc.stderr
    assert b"decode error" not in proc.stderr


def test_leftover_secret_exits_one() -> None:
    text = "user@\nexample.com\n"
    proc = _run(text.encode("utf-8"))
    assert proc.returncode == 1
    assert proc.stdout == b""


def test_escape_and_other_controls_do_not_pass() -> None:
    for payload in (b"hello\x1bworld", b"bell\x07"):
        proc = _run(payload)
        assert proc.returncode == 2
        assert proc.stdout == b""
