# PURPOSE: Egress normalizes a class of obfuscations, then uses the full detector set.

from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"


def _families() -> dict[str, str]:
    pem = "-----BEGIN " + "PRIVATE KEY-----\n" + ("A" * 32) + "\n"
    return {
        "github-token": "gh" + "p_" + ("A" * 36),
        "github-fine": "github" + "_pat_" + ("a" * 22),
        "sk": "sk-" + "proj-" + ("b" * 20),
        "gitlab": "gl" + "pat-" + ("c" * 20),
        "jwt": "ey" + "J" + ("d" * 8) + "." + ("e" * 8) + "." + ("f" * 8),
        "pem": pem,
    }


def _with_invisibles(token: str) -> str:
    marks = ("\u00ad", "\u200b", "\u200d")
    parts: list[str] = []
    for index, char in enumerate(token):
        parts.append(char)
        if index < len(marks):
            parts.append(marks[index])
    return "".join(parts)


def _variants(token: str) -> dict[str, str]:
    wrapped = token[:6] + "\n" + token[6:]
    encoded = token.encode("utf-8")
    return {
        "invisible": _with_invisibles(token),
        "wrap": wrapped,
        "hex": encoded.hex(),
        "urlsafe-b64": base64.urlsafe_b64encode(encoded).decode("ascii"),
    }


def _run(text: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), "--egress-prepare", "-"],
        input=text.encode("utf-8"),
        capture_output=True,
        check=False,
    )


def test_obfuscated_family_is_blocked_or_masked(text: str, canonical: str) -> None:
    proc = _run(text)
    unchanged = proc.returncode == 0 and proc.stdout == text.encode("utf-8")
    assert not unchanged, "obfuscated secret was emitted"
    if proc.returncode != 0:
        assert proc.stdout == b""
        return
    assert canonical.encode("utf-8") not in proc.stdout


def pytest_generate_tests(metafunc) -> None:
    if "text" not in metafunc.fixturenames:
        return
    texts: list[str] = []
    canonicals: list[str] = []
    ids: list[str] = []
    for name, token in _families().items():
        for kind, sample in _variants(token).items():
            texts.append(sample)
            canonicals.append(token)
            ids.append(f"{name}-{kind}")
    metafunc.parametrize(("text", "canonical"), list(zip(texts, canonicals)), ids=ids)
