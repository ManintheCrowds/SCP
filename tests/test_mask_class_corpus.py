# PURPOSE: Class-level mask corpus. Tokens are built at runtime.

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scp import mask_secrets

_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"
_README = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "mask_class_corpus" / "README.md"
_BENIGN_COUNT = 1694
_BENIGN_FLAG_CEILING = 7


def _token() -> str:
    return "gh" + "p_" + ("A" * 36)


def _insert(token: str, mark: str) -> str:
    return token[:8] + mark + token[8:]


def _cases() -> list[tuple[str, str]]:
    token = _token()
    samples = [
        ("stray-quote", 'shelf is 27" wide\n' + token + '\nend "quote"\n'),
        ("prose-thanks", token + "\nThanks"),
        ("prose-next", token + "\nNext steps"),
        ("prose-then", token + "\nThen"),
        ("prose-done", token + "\ndone"),
        ("crlf", token[:12] + "\r\n" + token[12:]),
        ("cr", token[:12] + "\r" + token[12:]),
        ("tab", token[:12] + "\t" + token[12:]),
        ("format-soft-hyphen", _insert(token, "\u00ad")),
        ("format-zwsp", _insert(token, "\u200b")),
        ("format-zwj", _insert(token, "\u200d")),
        ("filler-hangul", _insert(token, "\u3164")),
        ("filler-choseong", _insert(token, "\u115f")),
        ("filler-jungseong", _insert(token, "\u1160")),
        ("variation-selector", _insert(token, "\ufe00")),
        ("mongolian-variation", _insert(token, "\u180b")),
        ("line-separator", token[:12] + "\u2028" + token[12:]),
        ("paragraph-separator", token[:12] + "\u2029" + token[12:]),
        ("nel", token[:12] + "\u0085" + token[12:]),
        ("control-del", _insert(token, "\u007f")),
        ("control-csi", _insert(token, "\u009b")),
        ("control-bare-del", "\u007f"),
    ]
    for width in range(17, 24):
        samples.append((f"wrap-{width}", token[:width] + "\n" + token[width:]))
    for width in range(1, 6):
        samples.append((f"fragment-{width}", token[:width] + "\n" + token[width:]))
    return samples


def _egress(text: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), "--egress-prepare", "-"],
        input=text.encode("utf-8"),
        capture_output=True,
        check=False,
    )


def _check(tmp_path: Path, text: str) -> subprocess.CompletedProcess[bytes]:
    path = tmp_path / "handoff.md"
    path.write_text(text, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), "--check", str(path)],
        capture_output=True,
        check=False,
    )


def test_class_corpus_is_masked_flagged_and_blocked(tmp_path: Path, name: str, text: str) -> None:
    token = _token()
    masked = mask_secrets.mask(text)
    assert token not in masked
    assert mask_secrets.has_secrets(text)
    egress = _egress(text)
    assert token.encode("utf-8") not in egress.stdout
    if egress.returncode != 0:
        assert egress.stdout == b""
    checked = _check(tmp_path, text)
    assert checked.returncode != 0
    assert token.encode("utf-8") not in checked.stdout


def pytest_generate_tests(metafunc) -> None:
    if "name" not in metafunc.fixturenames:
        return
    cases = _cases()
    metafunc.parametrize(("name", "text"), cases, ids=[case[0] for case in cases])


def _benign_lines() -> list[str]:
    patterns = (
        "Thanks for the note. Item {n}.",
        "Next steps stay on the list. Item {n}.",
        "Then the work stops. Item {n}.",
        "done. Item {n}.",
        'The shelf is 27" wide. Item {n}.',
        "Log reference 1700000000 item {n}.",
        "Version 1.2.3 is the current build. Item {n}.",
    )
    return [patterns[n % len(patterns)].format(n=n) for n in range(_BENIGN_COUNT)]


def test_benign_flags_do_not_exceed_the_ceiling() -> None:
    flagged = sum(1 for line in _benign_lines() if mask_secrets.has_secrets(line))
    assert flagged <= _BENIGN_FLAG_CEILING


def test_corpus_readme_lists_deferred_encodings() -> None:
    text = _README.read_text(encoding="utf-8")
    for label in (
        "base32",
        "colon-separated hex",
        "octal escapes",
        "without a semicolon",
        "quoted-printable soft line breaks",
        "nested encodings",
        "longer than 256",
    ):
        assert label in text
