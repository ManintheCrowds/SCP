# PURPOSE: One linear normalization for mask, has_secrets, and egress.
# Base64, hex, URL-encoding, and quoted-printable are deferred. This pass
# still charges a work budget and fails closed when that budget runs out.

from __future__ import annotations

import unicodedata
from array import array

class NormalizationBudgetExceeded(RuntimeError):
    """Normalization or a deferred decode could not finish inside its budget."""


# A linear scan stays under a small multiple of the input length.
# Callers fail closed when the budget runs out.
_BUDGET_FACTOR = 8

_FILLER_CATEGORIES = frozenset({"Cf", "Zl", "Zp", "Mn"})
_TOKEN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _charge(steps: int, budget: int, count: int = 1) -> int:
    steps += count
    if steps > budget:
        raise NormalizationBudgetExceeded()
    return steps


def _budget_for(length: int) -> int:
    return length * _BUDGET_FACTOR + 16


def is_filler(char: str) -> bool:
    """Invisible and filler characters by Unicode category, not a hand list.

    Cf (format), Zl (line separator), Zp (paragraph separator), and Mn
    (nonspacing mark, including U+17B4 and U+17B5) are removed from the
    detection surface. ASCII is never a filler.
    """
    if ord(char) < 128:
        return False
    return unicodedata.category(char) in _FILLER_CATEGORIES


def _fold(text: str, *, keep_origins: bool) -> tuple[str, array | None]:
    """Drop fillers and fold CR/CRLF to newline. One forward pass."""
    chars: list[str] = []
    origins = array("I") if keep_origins else None
    steps = 0
    budget = _budget_for(len(text))
    index = 0
    length = len(text)
    while index < length:
        steps = _charge(steps, budget)
        char = text[index]
        if char == "\r":
            chars.append("\n")
            if origins is not None:
                origins.append(index)
            index += 2 if index + 1 < length and text[index + 1] == "\n" else 1
            continue
        if is_filler(char):
            index += 1
            continue
        chars.append(char)
        if origins is not None:
            origins.append(index)
        index += 1
    return "".join(chars), origins


def fold_unjoined(text: str) -> str:
    folded, _origins = _fold(text, keep_origins=False)
    return folded


def _prose_word(word: str) -> bool:
    """Words such as Thanks, Notes, and before.

    Uppercase runs and long dot-separated segments are token text, not prose.
    """
    if len(word) < 2 or not word.isalpha():
        return False
    if word[:1].isupper() and word[1:].islower():
        return True
    return word.islower() and len(word) <= 20


def _leading_token(line: str) -> str:
    end = 0
    length = len(line)
    while end < length and line[end] in _TOKEN_CHARS:
        end += 1
    return line[:end]


def _split_tail(line: str) -> tuple[str, str]:
    start = len(line)
    while start > 0 and line[start - 1] in _TOKEN_CHARS:
        start -= 1
    return line[:start], line[start:]


def should_join(prev: str, nxt: str) -> bool:
    """Decide a wrap from the end of `prev` only.

    Leading spaces and tabs on the continuation are ignored here and stripped
    by the joiner. A following prose word is not glued on. One to seven key
    characters after '=' still count, and a line that ends in '.' continues
    a JWT segment.
    """
    continued = nxt.lstrip(" \t")
    if not continued:
        return False
    head = _leading_token(continued)
    if not head:
        return False
    _before, tail = _split_tail(prev)
    dot_continue = prev.endswith(".") and not tail
    if _prose_word(head) and not (dot_continue and head.islower() and len(head) >= 16):
        return False
    if prev.endswith("=") or prev.endswith(":"):
        return True
    if tail and (_before.endswith("=") or _before.endswith(":")):
        return True
    return dot_continue


def _line_ranges(text: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    start = 0
    for index, char in enumerate(text):
        if char == "\n":
            ranges.append((start, index))
            start = index + 1
    ranges.append((start, len(text)))
    return ranges


def _bridges(lines: list[str]) -> list[bool]:
    steps = 0
    budget = _budget_for(sum(len(line) for line in lines) + len(lines))
    bridges: list[bool] = []
    for index in range(len(lines) - 1):
        steps = _charge(steps, budget, len(lines[index]) + len(lines[index + 1]) + 1)
        bridges.append(should_join(lines[index], lines[index + 1]))
    return bridges


def join_wrapped(text: str) -> str:
    """Join wrapped token tails. Each pair is decided from the previous line."""
    if "\n" not in text:
        return text
    lines = text.split("\n")
    bridges = _bridges(lines)
    parts: list[str] = []
    for index, line in enumerate(lines):
        if index > 0 and bridges[index - 1]:
            parts.append(line.lstrip(" \t"))
        else:
            if index > 0:
                parts.append("\n")
            parts.append(line)
    return "".join(parts)


def _kept_unjoined_indexes(text: str) -> array:
    """Indexes into `text` kept by join_wrapped. Same length as the joined string."""
    lines = text.split("\n")
    ranges = _line_ranges(text)
    bridges = _bridges(lines)
    kept = array("I")
    for index, (start, _end) in enumerate(ranges):
        line = lines[index]
        offset = 0
        if index > 0 and bridges[index - 1]:
            while offset < len(line) and line[offset] in " \t":
                offset += 1
        elif index > 0:
            kept.append(start - 1)
        for cursor in range(offset, len(line)):
            kept.append(start + cursor)
    return kept


def detection_views(text: str) -> tuple[str, str]:
    """Shared surfaces for mask, has_secrets, and egress.

    The first view keeps newlines. The second joins wraps. Callers search both
    so a join cannot hide a token that was already visible, and a wrap cannot
    hide a token that joining makes contiguous.
    """
    unjoined = fold_unjoined(text)
    if "\n" not in unjoined:
        return unjoined, unjoined
    return unjoined, join_wrapped(unjoined)


def map_spans(
    text: str,
    spans: list[tuple[int, int, str]],
    *,
    joined: bool,
) -> list[tuple[int, int, str]]:
    """Map spans in a detection view back to original indexes.

    The view only deletes characters. A span covers every original character
    from its first kept character through its last, including fillers and
    wrapped newlines that sat between them.
    """
    if not spans:
        return []
    unjoined, origins = _fold(text, keep_origins=True)
    if origins is None:
        raise NormalizationBudgetExceeded()
    if joined and "\n" in unjoined:
        kept = _kept_unjoined_indexes(unjoined)
        view_at = array("I", (origins[index] for index in kept))
    else:
        view_at = origins
    mapped: list[tuple[int, int, str]] = []
    limit = len(view_at)
    for start, end, replacement in spans:
        if start < 0 or end > limit or start >= end:
            raise NormalizationBudgetExceeded()
        mapped.append((int(view_at[start]), int(view_at[end - 1]) + 1, replacement))
    return mapped
