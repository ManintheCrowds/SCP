# PURPOSE: Joining split lines and percent-decoding stay linear on large input.

from __future__ import annotations

import time

from scp import encounter_auto_log, mask_secrets, secret_text


def test_join_of_many_short_lines_is_fast() -> None:
    text = "A\n" * 80_000
    started = time.perf_counter()
    secret_text.join_split_tokens(text)
    assert time.perf_counter() - started < 2.0


def test_percent_encoded_megabyte_masks_quickly() -> None:
    text = "%41" * 333_334
    started = time.perf_counter()
    mask_secrets.mask(text)
    assert time.perf_counter() - started < 3.0


def test_log_path_caps_before_masking() -> None:
    content = "ignore previous instructions " + ("A\n" * 80_000)
    started = time.perf_counter()
    logged = encounter_auto_log._sanitize_for_log(content, "injection")
    assert time.perf_counter() - started < 2.0
    assert len(logged) < 2000
