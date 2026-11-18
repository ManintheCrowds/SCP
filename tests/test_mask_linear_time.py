# PURPOSE: Joining split lines and percent-decoding stay linear on large input.

from __future__ import annotations

import time

from scp import encounter_auto_log, mask_secrets, secret_text


def _line_wrapped(size: int) -> str:
    """Round-2 shape: every line is long enough that the old join keeps copying it."""
    return ("A" * 8 + "\n") * (size // 9)


def _doubling_ratio(fn, size: int) -> float:
    def once(n: int) -> float:
        text = _line_wrapped(n)
        started = time.perf_counter()
        fn(text)
        return time.perf_counter() - started

    small = once(size)
    large = once(size * 2)
    if small <= 0:
        return large
    return large / small


def _round2_join(text: str) -> str:
    """The pre-linear join. It copies the growing line and scans that whole line."""
    if "\n" not in text:
        return text
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

    def run(line: str, reverse: bool) -> int:
        count = 0
        for char in reversed(line) if reverse else line:
            if char not in alphabet:
                break
            count += 1
        return count

    lines = text.split("\n")
    joined = [lines[0]]
    for line in lines[1:]:
        previous = joined[-1]
        if previous.endswith("\\"):
            joined[-1] = previous[:-1] + line
            continue
        if run(previous, True) >= 8 and run(line, False) >= 4:
            joined[-1] = previous + line
            continue
        joined.append(line)
    return "\n".join(joined)


def test_join_doubling_stays_under_3x() -> None:
    assert _doubling_ratio(secret_text.join_split_tokens, 80_000) < 3


def test_round2_join_doubling_is_at_least_3x() -> None:
    # Same input shape, small enough to run in the suite. 8_000 vs 16_000 was about 4x.
    assert _doubling_ratio(_round2_join, 8_000) >= 3


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
