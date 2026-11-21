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


# Look-alike letters folded on the detection surface only.
_HOMOGLYPHS = str.maketrans(
    {
        "\u0410": "A",
        "\u0412": "B",
        "\u0415": "E",
        "\u041a": "K",
        "\u041c": "M",
        "\u041d": "H",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0422": "T",
        "\u0425": "X",
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0396": "Z",
        "\u0397": "H",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a4": "T",
        "\u03a5": "Y",
        "\u03a7": "X",
        "\u03b1": "a",
        "\u03bf": "o",
    }
)


def is_refused_control(char: str) -> bool:
    """Every C0 control except tab, LF, and CR, plus DEL and C1.

    U+0000 through U+001F are refused aside from U+0009, U+000A, and U+000D.
    """
    code = ord(char)
    if code < 0x20 and code not in (0x09, 0x0A, 0x0D):
        return True
    if code == 0x7F:
        return True
    return 0x80 <= code <= 0x9F


def has_refused_control(text: str) -> bool:
    return any(is_refused_control(char) for char in text)


def is_filler(char: str) -> bool:
    """Invisible and filler characters by Unicode property, not a hand list.

    Cf, Zl, Zp, and Mn (including U+17B4 and U+17B5) are fillers. So are
    non-ASCII spaces (NBSP and the other Zs variants) and Hangul filler
    characters, which are letters by category but fillers by name.
    """
    if ord(char) < 128:
        return False
    category = unicodedata.category(char)
    if category in _FILLER_CATEGORIES or category == "Zs":
        return True
    code = ord(char)
    if 0x1100 <= code <= 0xFFA0:
        return "FILLER" in unicodedata.name(char, "")
    return False


def _normalize_kept(char: str) -> str:
    """NFKC for fullwidth forms, then common homoglyphs."""
    if ord(char) < 128:
        return char
    return unicodedata.normalize("NFKC", char).translate(_HOMOGLYPHS)


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
        if is_filler(char) or is_refused_control(char):
            index += 1
            continue
        kept = _normalize_kept(char)
        for out_char in kept:
            if not out_char or is_filler(out_char) or is_refused_control(out_char):
                continue
            chars.append(out_char)
            if origins is not None:
                origins.append(index)
        index += 1
    return "".join(chars), origins


def fold_unjoined(text: str) -> str:
    folded, _origins = _fold(text, keep_origins=False)
    return folded


def _prose_word(word: str) -> bool:
    """Words such as Thanks, Notes, and before.

    A repeated character is a token fragment, not a word.
    """
    if len(word) < 2 or not word.isalpha():
        return False
    if word[:1].isupper() and word[1:].islower():
        return True
    # Two- and three-letter pieces are how a token prefix breaks. Longer
    # lowercase words such as before and notes still stop a join.
    return word.islower() and 4 <= len(word) <= 20 and len(set(word)) > 1


_MARK_CHARS = frozenset("_-0123456789")
# A line that begins with one of these is a new token. The previous line
# stays where it is. Pieces are concatenated so the source has no whole prefix.
_KNOWN_PREFIXES = (
    "github" + "_pat_",
    "gl" + "pat-",
    "sk-" + "proj-",
    "xo" + "xb-",
    "gh" + "p_",
    "gh" + "o_",
    "gh" + "s_",
    "gh" + "u_",
    "AK" + "IA",
    "AS" + "IA",
    "sk" + "-",
    "sk" + "_",
)
# Trailing English words of two or three letters. Repeated-character fragments
# are not in this set, so a wrapped token body still joins.
_STOP_WORDS = frozenset(
    {
        "ok", "to", "be", "if", "or", "an", "at", "on", "in", "of", "is", "it",
        "we", "my", "up", "no", "so", "do", "go", "us", "am", "as", "hi", "he",
        "me", "by", "ah", "the", "and", "for", "you", "not", "but", "his", "her",
        "she", "was", "are", "all", "can", "had", "one", "our", "out", "day",
        "get", "has", "him", "how", "its", "let", "may", "new", "now", "old",
        "see", "two", "way", "who", "did", "put", "say", "too", "use", "yes",
        "yet", "any", "big", "end", "few", "got", "hot", "lot", "man", "off",
        "own", "run", "set", "top", "try", "win", "hey", "gi", "th", "ub",
        "git", "hub", "pat",
    }
)
# Lowercase words that must not be swallowed as a wrapped JWT fragment.
_JWT_FRAGMENT_WORDS = frozenset(
    {
        "before", "notes", "thanks", "friday", "header", "value", "token",
        "bearer", "secret", "please", "export", "after", "there",
    }
)


def _starts_known_prefix(line: str) -> bool:
    stripped = line.lstrip(" \t")
    return any(stripped.startswith(prefix) for prefix in _KNOWN_PREFIXES)


def _stop_word(word: str) -> bool:
    return word.lower() in _STOP_WORDS


def _body_continues(line: str) -> bool:
    head = _continuation_head(line)
    if not head or _prose_word(head) or _stop_word(head):
        return False
    return True


def _trailing_stop(lines: list[str], index: int, head: str, seen_mark: bool, joined_len: int) -> bool:
    """A short word after a token that has already started, with nothing after it."""
    if not _stop_word(head):
        return False
    if not seen_mark and joined_len < 16:
        return False
    if index + 2 < len(lines) and _body_continues(lines[index + 2]):
        return False
    return True


def _assignment_open(prev: str) -> bool:
    """A label ending in ':' or '=', including a trailing space and a 1-7 char tail."""
    stripped = prev.rstrip(" \t")
    if not stripped:
        return False
    if stripped.endswith(("=", ":")):
        return True
    before, tail = _split_tail(stripped)
    return bool(tail) and before.rstrip(" \t").endswith(("=", ":"))


def _bearer_open(prev: str) -> bool:
    """'Bearer' alone, or with a space and a short visible tail."""
    stripped = prev.rstrip(" \t")
    if not stripped:
        return False
    lower = stripped.lower()
    marker = "bearer"
    if lower == marker or lower.endswith(" " + marker):
        return True
    idx = lower.rfind(marker)
    if idx < 0 or (idx > 0 and lower[idx - 1] not in " \t"):
        return False
    rest = stripped[idx + len(marker) :]
    if not rest or rest[0] not in " \t":
        return False
    tail = rest.lstrip(" \t")
    return 1 <= len(tail) <= 12 and all(char in _TOKEN_CHARS for char in tail)


def _jwt_subject(prev: str) -> str:
    """The token tail after a label, assignment, or bearer marker."""
    stripped = prev.strip(" \t")
    cut = max(stripped.rfind("="), stripped.rfind(":"))
    if cut >= 0:
        stripped = stripped[cut + 1 :].lstrip(" \t")
    lower = stripped.lower()
    marker = "bearer"
    idx = lower.rfind(marker)
    if idx >= 0 and (idx == 0 or lower[idx - 1] in " \t"):
        rest = stripped[idx + len(marker) :]
        if rest[:1] in " \t":
            stripped = rest.lstrip(" \t")
    return stripped


def _eyj_piece(line: str) -> bool:
    """A wrapped piece that still begins with the JWT marker."""
    stripped = line.strip(" \t").lstrip(".")
    marker = "".join(("ey", "J"))
    if not stripped.startswith(marker):
        return False
    return all(char in _TOKEN_CHARS or char == "." for char in stripped)


def _bearer_header(prev: str) -> bool:
    """A bearer line whose tail is a JWT header waiting for a leading dot."""
    stripped = prev.strip(" \t")
    lower = stripped.lower()
    marker = "bearer"
    idx = lower.rfind(marker)
    if idx < 0 or (idx > 0 and lower[idx - 1] not in " \t"):
        return False
    rest = stripped[idx + len(marker) :]
    if not rest or rest[0] not in " \t":
        return False
    tail = rest.lstrip(" \t")
    return len(tail) >= 8 and all(char in _TOKEN_CHARS for char in tail)


def _jwt_open(prev: str) -> bool:
    """A dot between segments, including after a label on the same line."""
    stripped = _jwt_subject(prev).lstrip(".")
    if not stripped or "." not in stripped:
        return False
    if stripped.endswith("."):
        body = stripped[:-1]
        parts = body.split(".") if body else []
    else:
        parts = stripped.split(".")
    if not parts or not (1 <= len(parts) <= 3):
        return False
    if not all(part and all(char in _TOKEN_CHARS for char in part) for part in parts):
        return False
    if len(parts[0]) < 8:
        return False
    if len(parts) < 3:
        return True
    return len(parts[2]) < 16


def _hard_wrap(prev: str) -> bool:
    """An 80-column line that ends inside a label or a token."""
    stripped = prev.rstrip(" \t")
    return len(stripped) >= 72 and bool(stripped) and stripped[-1] in _TOKEN_CHARS


def _bare_fragment(line: str) -> bool:
    """A line that is only a token run.

    Title-case words stay prose. A lowercase fragment such as the start of a
    token may still continue, and the next line is what rejects Thanks or before.
    """
    stripped = line.strip(" \t")
    if not stripped:
        return False
    for char in stripped:
        if char not in _TOKEN_CHARS:
            return False
    if len(stripped) >= 2 and stripped.isalpha() and stripped[0].isupper() and stripped[1:].islower():
        return False
    return True


def _kind(prev: str) -> str:
    if _bearer_open(prev):
        return "bearer"
    if _assignment_open(prev):
        return "assign"
    if _jwt_open(prev):
        return "jwt"
    if _hard_wrap(prev):
        return "wrap"
    if _bare_fragment(prev):
        return "bare"
    return "none"


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


def _continuation_head(nxt: str) -> str:
    """Token run at the start of a continuation, after indent and one dot."""
    continued = nxt.lstrip(" \t")
    if continued.startswith("."):
        continued = continued[1:]
    return _leading_token(continued)


def should_join(prev: str, nxt: str) -> bool:
    """Decide one pair from the end of `prev`.

    Leading spaces and tabs on the continuation are ignored. A following
    prose word is not glued on.
    """
    head = _continuation_head(nxt)
    if not head or _prose_word(head):
        return False
    return _kind(prev) != "none"


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
    """Join every continuation of an open label, bearer, or JWT.

    The carry is a flag plus two counters, not a growing copy of the line.
    A known prefix starts a new token. A trailing two- or three-letter word
    is not glued on once the token has a mark or is already 16 characters.
    """
    steps = 0
    budget = _budget_for(sum(len(line) for line in lines) + len(lines))
    bridges: list[bool] = []
    open_kind = "none"
    joined_len = 0
    seen_mark = False
    jwt_run = False
    jwt_dots = 0
    for index in range(len(lines) - 1):
        prev = lines[index]
        nxt = lines[index + 1]
        steps = _charge(steps, budget, len(prev) + len(nxt) + 1)
        if _eyj_piece(prev):
            jwt_run = True
        inside_jwt = jwt_run or open_kind == "jwt" or _jwt_open(prev)
        if _starts_known_prefix(nxt) and not inside_jwt:
            bridges.append(False)
            run = _leading_token(nxt.lstrip(" \t"))
            open_kind = "bare"
            joined_len = len(run)
            seen_mark = any(char in _MARK_CHARS for char in run)
            continue
        continued = nxt.lstrip(" \t")
        head = _continuation_head(nxt)
        dot_only = continued == "."
        if not head and not dot_only:
            bridges.append(False)
            open_kind = "none"
            joined_len = 0
            seen_mark = False
            jwt_run = False
            jwt_dots = 0
            continue
        lowercase_piece = (
            bool(head)
            and head.isalpha()
            and head.islower()
            and 4 <= len(head) <= 8
            and head not in _JWT_FRAGMENT_WORDS
        )
        if head and _prose_word(head) and not (inside_jwt and lowercase_piece):
            bridges.append(False)
            open_kind = "none"
            joined_len = 0
            seen_mark = False
            jwt_run = False
            jwt_dots = 0
            continue
        if open_kind in {"assign", "bearer", "jwt", "bare"}:
            kind = open_kind
            join = True
            base_len = joined_len
            base_mark = seen_mark
        else:
            kind = _kind(prev)
            join = kind != "none"
            if join:
                _before, tail = _split_tail(prev.rstrip(" \t"))
                base_len = len(tail)
                base_mark = any(char in _MARK_CHARS for char in tail)
            else:
                base_len = 0
                base_mark = False
        if not join and continued.startswith(".") and _bearer_header(prev):
            kind = "jwt"
            join = True
            base_len = 0
            base_mark = False
        if join and head and kind != "jwt" and _trailing_stop(lines, index, head, base_mark, base_len):
            join = False
        bridges.append(join)
        if not join:
            open_kind = "none"
            joined_len = 0
            seen_mark = False
            jwt_run = False
            jwt_dots = 0
            continue
        joined_len = base_len + len(head)
        seen_mark = base_mark or any(char in _MARK_CHARS for char in head)
        if jwt_run or _eyj_piece(prev):
            jwt_run = True
            jwt_dots += prev.count(".")
            if kind == "bare":
                kind = "jwt"
        if kind == "wrap":
            open_kind = _kind(continued)
            if open_kind == "wrap":
                open_kind = "none"
            continue
        nxt_kind = _kind(continued)
        open_kind = nxt_kind if nxt_kind in {"assign", "bearer", "jwt", "bare"} else kind
    return bridges


def join_wrapped(text: str) -> str:
    """Join wrapped token tails. Each pair is decided from the previous line."""
    if "\n" not in text:
        return text
    lines = text.split("\n")
    bridges = _bridges(lines)
    parts: list[str] = []
    for index, line in enumerate(lines):
        chunk = line.rstrip(" \t") if index < len(bridges) and bridges[index] else line
        if index > 0 and bridges[index - 1]:
            parts.append(chunk.lstrip(" \t"))
        else:
            if index > 0:
                parts.append("\n")
            parts.append(chunk)
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
        end = len(line)
        if index < len(bridges) and bridges[index]:
            while end > 0 and line[end - 1] in " \t":
                end -= 1
        if index > 0 and bridges[index - 1]:
            while offset < end and line[offset] in " \t":
                offset += 1
        elif index > 0:
            kept.append(start - 1)
        for cursor in range(offset, end):
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
