# PURPOSE: One linear normalization feeds mask, has_secrets, and egress.

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from scp import mask_secrets, secret_text

_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"
_RATIO_LIMIT = 2.6


def _ratio(fn, size: int) -> float:
    def once(n: int) -> float:
        started = time.process_time()
        fn(n)
        return time.process_time() - started

    fn(size // 8 or 1)
    samples = []
    for _ in range(3):
        small = once(size)
        large = once(size * 2)
        samples.append(large / small if small > 0 else large)
    samples.sort()
    return samples[1]


def _quote_text(n: int) -> str:
    return '\n"' + '\\"' * n


def _unwrap_text(n: int) -> str:
    return ("Abcdef\n") * n


def test_quote_scan_doubling_beats_superlinear() -> None:
    def run(n: int) -> None:
        secret_text.join_split_tokens(_quote_text(n))

    assert _ratio(run, 20_000) < _RATIO_LIMIT


def test_unwrap_doubling_beats_superlinear() -> None:
    def run(n: int) -> None:
        secret_text.unwrap_lines(_unwrap_text(n))

    assert _ratio(run, 40_000) < _RATIO_LIMIT


def test_normalization_budget_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secret_text, "_BUDGET_FACTOR", 0)
    text = '"\n' + ("x" * 200)
    assert mask_secrets.has_secrets(text)
    assert mask_secrets.mask(text) == "[REDACTED]"
    with pytest.raises(mask_secrets.EgressMaskError):
        mask_secrets.prepare_outbound(text)


def _key() -> str:
    return "AK" + "IA" + ("C" * 16)


def test_prose_after_a_bare_key_does_not_hide_it() -> None:
    key = _key()
    for tail in ("Thanks", "Next steps", "Then", "done"):
        text = key + "\n" + tail
        assert mask_secrets.has_secrets(text)
        assert key not in mask_secrets.mask(text)


def test_later_quote_does_not_hide_a_key_after_an_inch_mark() -> None:
    key = _key()
    text = 'shelf is 27" wide\n' + key + '\nclosing "mark"\n'
    assert mask_secrets.has_secrets(text)
    assert key not in mask_secrets.mask(text)


def test_short_fragment_and_crlf_still_mask() -> None:
    key = _key()
    short = key[:4] + "\n" + key[4:]
    crlf = key[:10] + "\r\n" + key[10:]
    for text in (short, crlf):
        assert mask_secrets.has_secrets(text)
        assert key not in mask_secrets.mask(text)


def test_del_and_csi_do_not_pass_egress() -> None:
    for payload in ("note\u007f", "note\u009b"):
        assert mask_secrets.has_secrets(payload)
        proc = subprocess.run(
            [sys.executable, str(_MASK_SCRIPT), "--egress-prepare", "-"],
            input=payload.encode("utf-8"),
            capture_output=True,
            check=False,
        )
        assert proc.returncode != 0
        assert proc.stdout == b""
