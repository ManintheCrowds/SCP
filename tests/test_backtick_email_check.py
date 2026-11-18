# PURPOSE: Backtick emails do not exempt a whole span or cross a newline.

from __future__ import annotations

from scp import mask_secrets


def _email() -> str:
    return "user@example.com"


def _access_key() -> str:
    return "AK" + "IA" + "FAKEFAKEFAKEFAKE"


def test_single_line_backtick_email_is_not_a_secret_check() -> None:
    text = "See `" + _email() + "` in the docs."
    assert mask_secrets.has_secrets(text) is False


def test_backtick_email_does_not_hide_another_secret() -> None:
    text = "`" + _email() + " " + _access_key() + "`"
    assert mask_secrets.has_secrets(text) is True


def test_backtick_exemption_does_not_span_lines() -> None:
    text = "`" + _email() + "\n" + _access_key() + "`"
    assert "\n" in text
    assert mask_secrets.has_secrets(text) is True
