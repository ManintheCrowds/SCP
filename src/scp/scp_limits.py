# PURPOSE: Shared input size limits for SCP (inspect, classify, mask, contain).

from __future__ import annotations

import os

_ENV_KEY = "SCP_MAX_INPUT_CHARS"
_DEFAULT = 2_000_000
_HARD_CEILING = 50_000_000


def max_input_chars() -> int:
    raw = os.environ.get(_ENV_KEY)
    if raw is None or not str(raw).strip():
        return _DEFAULT
    try:
        n = int(str(raw).strip())
        if n < 1:
            return _DEFAULT
        return min(n, _HARD_CEILING)
    except ValueError:
        return _DEFAULT


def assert_within_limit(text: str, *, what: str = "content") -> None:
    lim = max_input_chars()
    if len(text) > lim:
        raise ValueError(f"{what} length {len(text)} exceeds SCP_MAX_INPUT_CHARS ({lim})")
