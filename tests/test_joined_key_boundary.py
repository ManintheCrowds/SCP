# PURPOSE: A letter run before a wrapped key must not hide the key from egress.

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"


def _key() -> str:
    return "AK" + "IA" + ("C" * 16)


def test_key_after_letter_run_is_not_emitted() -> None:
    key = _key()
    text = ("C" * 8) + "\n" + key
    proc = subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), "--egress-prepare", "-"],
        input=text.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    assert key.encode("utf-8") not in proc.stdout
    if proc.returncode != 0:
        assert proc.stdout == b""
