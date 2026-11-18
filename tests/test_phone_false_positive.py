# PURPOSE: Formatted phone numbers are masked. Bare 10-digit values are not.

from __future__ import annotations

from scp import mask_secrets


def test_formatted_us_phone_is_masked() -> None:
    text = "Call 212-555-0198 or (415) 555-0133."
    out = mask_secrets.mask(text)
    assert "212-555-0198" not in out
    assert "415" not in out
    assert out.count("[PHONE_REDACTED]") == 2


def test_bare_ten_digit_timestamp_is_not_a_phone() -> None:
    text = '{"ts": 1700000000, "id": 1234567890}\n'
    assert mask_secrets.mask(text) == text
    assert mask_secrets.residual_secrets(text) == []
