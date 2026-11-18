# PURPOSE: Egress blocks shapes the masker's own pattern list can miss.

from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"


def _run(text: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), "--egress-prepare", "-"],
        input=text.encode("utf-8"),
        capture_output=True,
        check=False,
    )


def _blocked(text: str, secret: str) -> None:
    proc = _run(text)
    assert secret.encode("utf-8") not in proc.stdout
    if proc.returncode != 0:
        assert proc.stdout == b""


def test_github_and_slack_tokens_are_blocked() -> None:
    for prefix in ("gh" + "o_", "gh" + "s_", "gh" + "u_"):
        token = prefix + ("a" * 36)
        _blocked("tok " + token, token)
    bot = "xo" + "xb-" + "12345-12345-abc"
    _blocked("bot " + bot, "12345-12345")
    hook = "https://hooks." + "slack.com/" + "services/T00/B00/xxx"
    _blocked(hook, "services/T00")


def test_basic_auth_and_client_secret_are_blocked() -> None:
    basic = "Authorization: Basic " + ("a" * 12)
    _blocked(basic, "Basic " + ("a" * 12))
    raw = 'client_secret=' + ("c" * 12)
    _blocked(raw, "c" * 12)
    _blocked('{"secret": "s3cret-value"}', "s3cret-value")
    _blocked('{"api_key": "k3y-value"}', "k3y-value")
    _blocked('{"client_secret": "csec-value"}', "csec-value")


def test_double_encoding_long_base64_and_hex_are_blocked() -> None:
    _blocked("user" + "%2540" + "example.com", "example.com")
    blob = base64.b64encode(b"password=hunter2").decode("ascii")
    padded = blob + ("A" * (260 - len(blob)))
    _blocked("blob " + padded, padded)
    safe = base64.urlsafe_b64encode(b"password=hunter2").decode("ascii")
    _blocked("safe " + safe, safe)
    hexed = b"password=hunter2".hex()
    _blocked("hex " + hexed, hexed)


def test_split_and_invisible_pii_are_blocked() -> None:
    _blocked("123-45-\n6789", "6789")
    _blocked("user@\nexample.com", "example.com")
    hidden = "us" + "\u00ad" + "er@example.com"
    _blocked(hidden, "example.com")
    _blocked("call\u202e212-555-0198", "212-555-0198")
    _blocked("MRN: ABC123", "ABC123")
    _blocked("Patient: Sample, Alex", "Sample, Alex")
    _blocked("Patient: José Álvarez", "José")
