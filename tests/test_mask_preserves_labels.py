# PURPOSE: Masking keeps the original label and separator.

from __future__ import annotations

from scp import mask_secrets


def test_password_colon_is_not_rewritten_to_equals() -> None:
    assert mask_secrets.mask("password: hunter2") == "password: [REDACTED]"


def test_date_of_birth_label_is_not_rewritten() -> None:
    assert mask_secrets.mask("Date of Birth: 1/2/1999") == "Date of Birth: [DATE_REDACTED]"


def test_dob_abbreviation_stays_dob() -> None:
    assert mask_secrets.mask("DOB: 03/15/1985") == "DOB: [DATE_REDACTED]"
