# PURPOSE: Plain text does not allocate an offset map for every character.

from __future__ import annotations

import tracemalloc

from scp import mask_secrets

_ONE_MB = 1_000_000


def test_plain_megabyte_stays_near_the_unmapped_mask() -> None:
    text = "a" * _ONE_MB
    tracemalloc.start()
    masked = mask_secrets.mask(text)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert masked == text
    # A per-character cover of this input is about 130 MB. Main's mask stays
    # in the kilobytes. A few megabytes leaves room for the pattern scan.
    assert peak < 8_000_000


def test_plain_secret_is_still_replaced() -> None:
    token = "gh" + "p_" + ("D" * 36)
    masked = mask_secrets.mask("note " + token)
    assert token not in masked
    assert "[REDACTED]" in masked
