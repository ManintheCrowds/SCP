# PURPOSE: Normalization before matching stays bounded and catches encoded secrets.
# sanitize_input is intentionally not imported here.

from __future__ import annotations

import base64

from scp import mask_secrets, secret_text


def _access_key() -> str:
    return "AK" + "IA" + "FAKEFAKEFAKEFAKE"


def test_nfkc_and_zero_width_expose_email() -> None:
    text = "user" + "\u200b" + "\uff20" + "example.com"
    out = mask_secrets.mask(text)
    assert "example.com" not in out
    assert "[EMAIL_REDACTED]" in out


def test_en_dash_date_of_birth_is_masked() -> None:
    text = "Date of Birth: 03" + "\u2013" + "15" + "\u2013" + "1985"
    out = mask_secrets.mask(text)
    assert "1985" not in out
    assert "Date of Birth:" in out
    assert "[DATE_REDACTED]" in out


def test_encoded_email_forms_are_masked() -> None:
    samples = [
        "user" + "%40" + "example.com",
        "user" + "&#64;" + "example.com",
        "user" + "\\u0040" + "example.com",
        "user" + "=40" + "example.com",
    ]
    for sample in samples:
        out = mask_secrets.mask(sample)
        assert "example.com" not in out, sample
        assert "@" not in out


def test_base64_secret_is_masked() -> None:
    raw = base64.b64encode(b"password=hunter2").decode("ascii")
    out = mask_secrets.mask("blob " + raw)
    assert "hunter2" not in out
    assert raw not in out


def test_split_access_key_and_json_string_are_joined() -> None:
    key = _access_key()
    split = key[:8] + "\n" + key[8:]
    assert key not in mask_secrets.mask(split)
    payload = '{"note": "' + key[:8] + "\n" + key[8:] + '"}'
    assert key[8:] not in mask_secrets.mask(payload)


def test_ssn_phone_and_written_dob_shapes() -> None:
    assert "123.45.6789" not in mask_secrets.mask("id 123.45.6789")
    assert "123 45 6789" not in mask_secrets.mask("id 123 45 6789")
    assert "123456789" not in mask_secrets.mask("SSN 123456789")
    assert "7946" not in mask_secrets.mask("call +44 20 7946 0958")
    written = mask_secrets.mask("Date of Birth: March 15, 1985")
    assert "March" not in written
    assert "Date of Birth:" in written
    assert "[DATE_REDACTED]" in written


def test_fold_chars_is_linear_on_ascii() -> None:
    text = "a" * 1000
    assert secret_text.fold_chars(text) == text
