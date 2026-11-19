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


def join_wrapped(text: str) -> str:
    """Charge the join budget. Wrap decisions land in the line-wrap fix.

    Until then the joined view is the unjoined text, so a newline cannot
    hide a token that is already visible and cannot reveal one either.
    """
    if text:
        _charge(0, _budget_for(len(text)), len(text))
    return text


def _kept_unjoined_indexes(text: str) -> array:
    return array("I", range(len(text)))


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
