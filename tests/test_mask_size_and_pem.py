# PURPOSE: Private-key masking stays linear without an END line, and the CLI caps input.

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from scp import mask_secrets

_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"
_ONE_MB = 1_000_000


def test_one_megabyte_mask_finishes_quickly() -> None:
    text = "a" * _ONE_MB
    started = time.perf_counter()
    masked = mask_secrets.mask(text)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0
    assert masked == text


def test_private_key_without_end_line_is_linear() -> None:
    body = "-----BEGIN PRIVATE KEY-----\n" + ("A" * _ONE_MB)
    started = time.perf_counter()
    masked = mask_secrets.mask(body)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0
    assert "A" * 64 not in masked
    assert "[REDACTED]" in masked


def test_cli_over_cap_fails_closed_for_stdin_and_file(tmp_path: Path) -> None:
    payload = b"b" * (mask_secrets.MAX_CLI_BYTES + 1)
    stdin = subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), "--egress-prepare", "-"],
        input=payload,
        capture_output=True,
        check=False,
    )
    assert stdin.returncode != 0
    assert stdin.stdout == b""
    path = tmp_path / "handoff.txt"
    path.write_bytes(payload)
    filed = subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), "--egress-prepare", str(path)],
        capture_output=True,
        check=False,
    )
    assert filed.returncode != 0
    assert filed.stdout == b""
