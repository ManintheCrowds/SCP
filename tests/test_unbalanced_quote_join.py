# PURPOSE: An unmatched quote must not glue later lines into a token.

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scp import mask_secrets

_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"


def _tokens() -> dict[str, str]:
    return {
        "github-pat": "gh" + "p_" + ("A" * 36),
        "github-fine": "github" + "_pat_" + ("a" * 22),
        "openai-project": "sk-" + "proj-" + ("b" * 20),
        "gitlab": "gl" + "pat-" + ("c" * 20),
        "jwt": "ey" + "J" + ("d" * 8) + "." + ("e" * 8) + "." + ("f" * 8),
    }


def _document(token: str) -> str:
    return 'shelf is 27" wide\n' + token + "\n"


def test_unbalanced_quote_does_not_hide_later_tokens(token: str) -> None:
    text = _document(token)
    found = mask_secrets.has_secrets(text)
    assert found, "unbalanced quote hid a later token"
    proc = subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), "--egress-prepare", "-"],
        input=text.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    assert token.encode("utf-8") not in proc.stdout
    if proc.returncode != 0:
        assert proc.stdout == b""
    else:
        assert b"[REDACTED]" in proc.stdout


def pytest_generate_tests(metafunc) -> None:
    if "token" in metafunc.fixturenames:
        samples = _tokens()
        metafunc.parametrize("token", list(samples.values()), ids=list(samples.keys()))
