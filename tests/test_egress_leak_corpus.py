# PURPOSE: --egress-prepare rescans with detectors and must not emit a synthetic leak.
# Samples are built at runtime. Later commits append formats to LEAK_CORPUS.

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scp import mask_secrets

_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"


def _access_key() -> str:
    return "AK" + "IA" + "FAKEFAKEFAKEFAKE"


def _github_token() -> str:
    return "gh" + "p_" + ("A" * 36)


def _openai_key() -> str:
    return "sk" + "-" + ("a" * 24)


def _pem() -> str:
    return (
        "-----BEGIN PRIVATE KEY-----\n"
        + "MIIE" + ("V" * 40) + "\n"
        + "-----END PRIVATE KEY-----"
    )


def _cases() -> list[tuple[str, str, str]]:
    """Return (name, text, secret substring that must not be emitted)."""
    access = _access_key()
    github = _github_token()
    openai = _openai_key()
    pem = _pem()
    return [
        ("password", "password=hunter2", "hunter2"),
        ("api-key", "api_key=abcdEFGHijklMNOP1234", "abcdEFGHijklMNOP1234"),
        ("bearer", "Bearer " + ("b" * 24), "b" * 24),
        ("token", "token=" + ("t" * 20), "t" * 20),
        ("aws-access-key-id", f"AWS_ACCESS_KEY_ID={access}", access),
        ("aws-secret-access-key", "AWS_SECRET_ACCESS_KEY=" + ("s" * 28), "s" * 28),
        ("postgres", "postgres://demo_user:fake_password@127.0.0.1:5432/test_db", "fake_password"),
        ("private-key", pem, "MIIE"),
        ("openai-key", f"model {openai}", openai),
        ("access-key", f"cloud {access}", access),
        ("github-token", f"gh {github}", github),
        ("ssn-labeled", "SSN: 000-00-0000", "000-00-0000"),
        ("ssn", "file 987-65-4321", "987-65-4321"),
        ("phone", "call 212-555-0198", "212-555-0198"),
        ("email", "write test@example.com", "test@example.com"),
        ("patient", "Patient: Alex Sample", "Alex Sample"),
        ("dob", "DOB: 03/15/1985", "03/15/1985"),
    ]


def _run_egress(text: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), "--egress-prepare", "-"],
        input=text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_prepare_outbound_masks_once_then_rescans(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}
    original = mask_secrets.mask

    def _counting(text: str) -> str:
        calls["n"] += 1
        return original(text)

    monkeypatch.setattr(mask_secrets, "mask", _counting)
    out = mask_secrets.prepare_outbound("password=hunter2")
    assert calls["n"] == 1
    assert "hunter2" not in out
    assert mask_secrets.residual_secrets(out) == []


@pytest.mark.parametrize("name,text,secret", _cases(), ids=[case[0] for case in _cases()])
def test_egress_prepare_blocks_leak_corpus(name: str, text: str, secret: str) -> None:
    proc = _run_egress(text)
    assert secret not in proc.stdout, name
    if proc.returncode != 0:
        assert proc.stdout == ""
    else:
        assert proc.stdout
