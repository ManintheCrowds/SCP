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
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"
    body = "MI" + "IE" + ("V" * 40)
    return begin + "\n" + body + "\n" + end


def _project_key() -> str:
    return "sk-" + "proj-" + ("p" * 24)


def _anthropic_key() -> str:
    return "sk-" + "ant-" + ("a" * 24)


def _fine_grained() -> str:
    return "github" + "_pat_" + ("g" * 40)


def _gitlab() -> str:
    return "gl" + "pat-" + ("L" * 24)


def _stripe() -> str:
    return "sk" + "_live_" + ("s" * 24)


def _telegram() -> str:
    return "123456789:" + ("T" * 35)


def _age() -> str:
    return "AGE-" + "SECRET-" + "KEY-1" + ("A" * 40)


def _jwt() -> str:
    return "ey" + "J" + ("a" * 12) + "." + ("b" * 12) + "." + ("c" * 12)


def _pem_kind(kind: str) -> str:
    label = f"{kind} PRIVATE KEY".strip()
    if kind:
        label = f"{kind}PRIVATE KEY"
    begin = f"-----BEGIN {label}-----"
    end = f"-----END {label}-----"
    return begin + "\n" + ("MI" + "IE") + ("V" * 20) + "\n" + end


def _cases() -> list[tuple[str, str, str]]:
    """Return (name, text, secret substring that must not be emitted)."""
    access = _access_key()
    github = _github_token()
    openai = _openai_key()
    pem = _pem()
    api_value = "abcd" + "EFGH" + "ijkl" + "MNOP" + "1234"
    json_token = "abcd" + "EFGH" + "1234" + "5678"
    return [
        ("password", "password=hunter2", "hunter2"),
        ("api-key", "api_key=" + api_value, api_value),
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
        ("openai-project", _project_key(), "proj-"),
        ("anthropic-key", _anthropic_key(), "ant-"),
        ("github-fine-grained", _fine_grained(), "_pat_"),
        ("gitlab-pat", _gitlab(), "pat-"),
        ("stripe-live", _stripe(), "_live_"),
        ("telegram-bot", "bot " + _telegram(), _telegram()),
        ("age-secret", _age(), "SECRET-"),
        ("jwt", "auth " + _jwt(), _jwt()),
        ("rsa-private-key", _pem_kind("RSA "), "MIIE"),
        ("ec-private-key", _pem_kind("EC "), "MIIE"),
        ("openssh-private-key", _pem_kind("OPENSSH "), "MIIE"),
        ("json-password", '{"password": "hello world secret"}', "hello world secret"),
        ("json-token", '{"token": "' + json_token + '"}', json_token),
        (
            "wordpress-db-password",
            "define('DB_PASSWORD', 'db pass phrase');",
            "db pass phrase",
        ),
        ("password-quoted", 'password: "hello world"', "hello world"),
        ("ssn-dots", "id 123.45.6789", "123.45.6789"),
        ("ssn-spaces", "id 123 45 6789", "123 45 6789"),
        ("ssn-digits", "SSN 123456789", "123456789"),
        ("phone-intl", "call +44 20 7946 0958", "7946"),
        ("dob-iso", "DOB: 1985-03-15", "1985-03-15"),
        ("dob-written", "Date of Birth: March 15, 1985", "March 15, 1985"),
        ("fullwidth-email", "user" + "\uff20" + "example.com", "example.com"),
        ("zero-width-email", "user" + "\u200b" + "@example.com", "example.com"),
        ("url-email", "user" + "%40" + "example.com", "example.com"),
        ("entity-email", "user" + "&#64;" + "example.com", "example.com"),
        ("unicode-email", "user" + "\\u0040" + "example.com", "example.com"),
        ("quoted-printable-email", "user" + "=40" + "example.com", "example.com"),
        ("split-access-key", _access_key()[:8] + "\n" + _access_key()[8:], _access_key()[8:]),
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
