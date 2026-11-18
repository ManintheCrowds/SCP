# PURPOSE: Bounded, linear text surface for secret detection.
# sanitize_input can call these helpers later. This module does not parse
# prompt-injection structure.

from __future__ import annotations

import base64
import binascii
import unicodedata

_ZERO_WIDTH = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u200e\u200f\ufeff\u2060\u180e"),
    None,
)
_DASHES = {
    ord("\u2010"): "-",
    ord("\u2011"): "-",
    ord("\u2012"): "-",
    ord("\u2013"): "-",
    ord("\u2014"): "-",
    ord("\u2015"): "-",
    ord("\u2212"): "-",
    ord("\uff0d"): "-",
}
_NAMED_ENTITIES = {
    "amp": "&",
    "lt": "<",
    "gt": ">",
    "quot": '"',
    "apos": "'",
    "nbsp": " ",
}
_HEX = set("0123456789abcdefABCDEF")
_B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_TOKEN = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.")
_MAX_WINDOW = 256
_MAX_B64 = 256


def fold_chars(text: str) -> str:
    """NFKC, drop zero-width characters, and fold dash variants to hyphen."""
    folded = unicodedata.normalize("NFKC", text)
    return folded.translate(_ZERO_WIDTH).translate(_DASHES)


def _entity(text: str, index: int) -> tuple[str, int] | None:
    if text[index] != "&":
        return None
    end = text.find(";", index + 1, index + 32)
    if end < 0:
        return None
    body = text[index + 1 : end]
    try:
        if body.startswith("#x") or body.startswith("#X"):
            value = int(body[2:], 16)
        elif body.startswith("#"):
            value = int(body[1:], 10)
        elif body in _NAMED_ENTITIES:
            return _NAMED_ENTITIES[body], end + 1
        else:
            return None
        if 0 <= value <= 0x10FFFF:
            return chr(value), end + 1
    except ValueError:
        return None
    return None


def _hex_escape(text: str, index: int) -> tuple[str, int] | None:
    if text.startswith("\\u", index) and index + 6 <= len(text):
        hexpart = text[index + 2 : index + 6]
        if all(char in _HEX for char in hexpart):
            return chr(int(hexpart, 16)), index + 6
    if text.startswith("\\U", index) and index + 10 <= len(text):
        hexpart = text[index + 2 : index + 10]
        if all(char in _HEX for char in hexpart):
            value = int(hexpart, 16)
            if 0 <= value <= 0x10FFFF:
                return chr(value), index + 10
    return None


def _percent_byte(text: str, index: int, marker: str) -> tuple[str, int] | None:
    if index >= len(text) or text[index] != marker or index + 3 > len(text):
        return None
    hexpart = text[index + 1 : index + 3]
    if all(char in _HEX for char in hexpart):
        return chr(int(hexpart, 16)), index + 3
    return None


def _encoding_at(text: str, index: int) -> tuple[str, int] | None:
    found = _entity(text, index)
    if found is not None:
        return found
    found = _hex_escape(text, index)
    if found is not None:
        return found
    found = _percent_byte(text, index, "%")
    if found is not None:
        return found
    return _percent_byte(text, index, "=")


def _decode_span(chunk: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(chunk):
        found = _encoding_at(chunk, index)
        if found is None:
            out.append(chunk[index])
            index += 1
            continue
        char, index = found
        out.append(char)
    return "".join(out)


def _expand(text: str, index: int) -> tuple[int, int]:
    start = index
    while start > 0 and index - start < _MAX_WINDOW and text[start - 1] in _TOKEN:
        start -= 1
    end = index
    limit = min(len(text), index + _MAX_WINDOW)
    while end < limit:
        found = _encoding_at(text, end)
        if found is not None:
            end = found[1]
            continue
        if text[end] in _TOKEN:
            end += 1
            continue
        break
    return start, end


def redact_encoded_secrets(text: str, contains_secret) -> str:
    """Replace a bounded encoded window when its decoded form still has a secret."""
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        if _encoding_at(text, index) is None:
            index += 1
            continue
        start, end = _expand(text, index)
        decoded = _decode_span(text[start:end])
        if decoded != text[start:end] and contains_secret(decoded):
            spans.append((start, end))
            index = end
            continue
        index = end if end > index else index + 1
    if not spans:
        return text
    out: list[str] = []
    cursor = 0
    for start, end in spans:
        if start < cursor:
            continue
        out.append(text[cursor:start])
        out.append("[REDACTED]")
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def _b64_has_secret(chunk: str, contains_secret) -> bool:
    if len(chunk) < 16 or len(chunk) > _MAX_B64 or len(chunk) % 4 != 0:
        return False
    try:
        raw = base64.b64decode(chunk, validate=True)
    except binascii.Error:
        return False
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(decoded) and contains_secret(decoded)


def redact_base64_secrets(text: str, contains_secret) -> str:
    out: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] not in _B64:
            out.append(text[index])
            index += 1
            continue
        end = index
        cap = min(length, index + _MAX_B64 + 1)
        while end < cap and text[end] in _B64:
            end += 1
        if end < length and text[end] in _B64:
            out.append(text[index:end])
            index = end
            continue
        chunk = text[index:end]
        if _b64_has_secret(chunk, contains_secret):
            out.append("[REDACTED]")
        else:
            out.append(chunk)
        index = end
    return "".join(out)


_JOIN = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _starts_new_secret(line: str) -> bool:
    stripped = line.lstrip()
    prefixes = (
        "AK" + "IA",
        "AS" + "IA",
        "gh" + "p_",
        "gh" + "o_",
        "gh" + "s_",
        "gh" + "u_",
        "sk" + "-",
        "sk" + "_",
    )
    return any(stripped.startswith(prefix) for prefix in prefixes)


def _join_run(line: str, *, reverse: bool) -> int:
    count = 0
    chars = reversed(line) if reverse else line
    for char in chars:
        if char not in _JOIN:
            break
        count += 1
    return count


def _tail_join_run(text: str) -> int:
    count = 0
    for char in reversed(text[-8:]):
        if char not in _JOIN:
            break
        count += 1
    return count


class NormalizationBudgetExceeded(RuntimeError):
    """Normalization could not finish inside its work budget."""


# A linear scan stays under a small multiple of the input length.
# An n^1.5 or n^2 rescan trips this and the callers fail closed.
_BUDGET_FACTOR = 8


def _charge(steps: int, budget: int) -> int:
    steps += 1
    if steps > budget:
        raise NormalizationBudgetExceeded()
    return steps


def _closed_quote_newlines(text: str) -> set[int]:
    """Newlines inside a quote that has a closer.

    One forward pass. An unmatched quote does not open a string, and when no
    closer remains the scan stops instead of restarting at every later quote.
    """
    drop: set[int] = set()
    index = 0
    length = len(text)
    steps = 0
    budget = length * _BUDGET_FACTOR + 16
    while index < length:
        steps = _charge(steps, budget)
        if text[index] != '"':
            index += 1
            continue
        cursor = index + 1
        escaped = False
        newlines: list[int] = []
        closed_at = -1
        while cursor < length:
            steps = _charge(steps, budget)
            char = text[cursor]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                closed_at = cursor
                break
            elif char == "\n":
                newlines.append(cursor)
            cursor += 1
        if closed_at >= 0:
            drop.update(newlines)
            index = closed_at + 1
            continue
        break
    return drop


def join_split_tokens(text: str) -> str:
    """Join a newline inside a closed JSON string, or a newline that splits a token.

    The scan looks at a fixed-size tail, so a long run of short lines stays linear.
    """
    if "\n" not in text:
        return text
    drop = _closed_quote_newlines(text)
    if drop:
        text = "".join(char for index, char in enumerate(text) if index not in drop)
    lines = text.split("\n")
    groups: list[list[str]] = [[lines[0]]]
    tail = _tail_join_run(lines[0])
    backslash = lines[0].endswith("\\")
    for line in lines[1:]:
        if backslash:
            groups[-1][-1] = groups[-1][-1][:-1]
            groups[-1].append(line)
        elif _starts_new_secret(line):
            groups.append([line])
        elif tail >= 8 and _join_run(line, reverse=False) >= 4:
            groups[-1].append(line)
        else:
            groups.append([line])
        current = groups[-1]
        tail = _tail_join_run(line)
        backslash = line.endswith("\\")
        if current[-1] is not line and not backslash:
            tail = _tail_join_run("".join(current)[-8:])
    return "\n".join("".join(group) for group in groups)


def base64_secret_spans(text: str, contains_secret) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] not in _B64:
            index += 1
            continue
        end = index
        cap = min(length, index + _MAX_B64 + 1)
        while end < cap and text[end] in _B64:
            end += 1
        if end < length and text[end] in _B64:
            index = end
            continue
        chunk = text[index:end]
        if _b64_has_secret(chunk, contains_secret):
            spans.append((index, end))
        index = end
    return spans


def surface_for_matching(text: str, contains_secret) -> str:
    """Fold and decode a bounded surface before secret patterns run."""
    folded = fold_chars(text)
    joined = join_split_tokens(folded)
    encoded = redact_encoded_secrets(joined, contains_secret)
    return redact_base64_secrets(encoded, contains_secret)


def _fold_tracked(text: str) -> tuple[str, list[tuple[int, int]]]:
    chars: list[str] = []
    cover: list[tuple[int, int]] = []
    for index, char in enumerate(text):
        folded = unicodedata.normalize("NFKC", char).translate(_ZERO_WIDTH).translate(_DASHES)
        for out_char in folded:
            chars.append(out_char)
            cover.append((index, index + 1))
    return "".join(chars), cover


def _drop_tracked(
    text: str, cover: list[tuple[int, int]], drop: set[int]
) -> tuple[str, list[tuple[int, int]]]:
    chars: list[str] = []
    new_cover: list[tuple[int, int]] = []
    for index, char in enumerate(text):
        if index in drop:
            continue
        chars.append(char)
        new_cover.append(cover[index])
    return "".join(chars), new_cover


def needs_offset_map(text: str) -> bool:
    """True when folding, joining, or decoding can move a match off the original indexes."""
    for char in text:
        if ord(char) > 127 or char in "\n\r\t&%=\\":
            return True
    return False


def disallowed_control(text: str) -> bool:
    """DEL, C0 (other than tab, CR, LF), and C1 (other than NEL)."""
    for char in text:
        code = ord(char)
        if code == 0x7F:
            return True
        if code < 32 and char not in "\t\n\r":
            return True
        if 0x80 <= code <= 0x9F and code != 0x85:
            return True
    return False


def _is_joiner(char: str) -> bool:
    """Format characters, line/paragraph separators already handled, fillers, variation marks."""
    code = ord(char)
    if code < 128:
        return False
    if unicodedata.category(char) == "Cf":
        return True
    if code in (0x3164, 0x115F, 0x1160, 0x034F):
        return True
    if 0x180B <= code <= 0x180F or 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF:
        return True
    return False


def _has_letter(text: str) -> bool:
    return any(char.isalpha() for char in text)


_TOKEN_EDGE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def unwrap_lines(text: str) -> str:
    """Join wrapped token fragments without copying a growing string.

    A fragment may be shorter than 6 characters. Pure digit lines are left
    alone so split numbers do not become a new digit run.
    """
    if "\n" not in text:
        return text
    lines = text.split("\n")
    groups: list[list[str]] = [[lines[0]]]
    group_len = len(lines[0])
    group_space = " " in lines[0]
    group_letter = _has_letter(lines[0])
    group_last = lines[0][-1] if lines[0] else ""
    for line in lines[1:]:
        continued = line.lstrip(" ")
        if (
            group_len >= 1
            and not group_space
            and group_letter
            and continued
            and group_last in _TOKEN_EDGE
            and continued[0] in _TOKEN_EDGE
            and _has_letter(continued)
        ):
            groups[-1].append(continued)
            group_len += len(continued)
            if " " in continued:
                group_space = True
            if _has_letter(continued):
                group_letter = True
            group_last = continued[-1]
            continue
        groups.append([line])
        group_len = len(line)
        group_space = " " in line
        group_letter = _has_letter(line)
        group_last = line[-1] if line else ""
    return "\n".join("".join(group) for group in groups)


def canonical_unjoined(text: str) -> tuple[str, list[tuple[int, int]] | None]:
    """Line endings normalized and joiners removed.

    The cover is omitted when every character is kept as itself. NEL, CR, CRLF,
    and the line/paragraph separators become a newline.
    """
    if not needs_offset_map(text) and not disallowed_control(text):
        return text, None
    chars: list[str] = []
    cover: list[tuple[int, int]] = []
    index = 0
    length = len(text)
    steps = 0
    budget = length * _BUDGET_FACTOR + 16
    while index < length:
        steps = _charge(steps, budget)
        char = text[index]
        code = ord(char)
        if char == "\r":
            start = index
            index += 2 if index + 1 < length and text[index + 1] == "\n" else 1
            chars.append("\n")
            cover.append((start, index))
            continue
        if code in (0x85, 0x2028, 0x2029):
            chars.append("\n")
            cover.append((index, index + 1))
            index += 1
            continue
        if code == 0x7F or (code < 32 and char not in "\t\n") or (0x80 <= code <= 0x9F):
            index += 1
            continue
        if _is_joiner(char):
            index += 1
            continue
        if code > 127:
            folded = unicodedata.normalize("NFKC", char).translate(_ZERO_WIDTH).translate(_DASHES)
            for out_char in folded:
                if not out_char or _is_joiner(out_char):
                    continue
                chars.append(out_char)
                cover.append((index, index + 1))
            index += 1
            continue
        chars.append(char)
        cover.append((index, index + 1))
        index += 1
    return "".join(chars), cover


def detection_views(text: str) -> tuple[str, str]:
    """Shared surfaces for mask, has_secrets, and egress.

    The first view keeps newlines. The second joins wraps. Callers search both
    so a join cannot hide a token that was already visible.
    """
    unjoined, _cover = canonical_unjoined(text)
    if "\n" not in unjoined and "\t" not in unjoined:
        return unjoined, unjoined
    joined = unwrap_lines(join_split_tokens(unjoined.replace("\t", "\n")))
    return unjoined, joined


def joined_index_map(source: str, joined: str) -> list[int]:
    """Index in `source` for each character of `joined`, which only deletes."""
    mapping: list[int] = []
    index = 0
    length = len(source)
    steps = 0
    budget = (length + len(joined)) * _BUDGET_FACTOR + 16
    for char in joined:
        steps = _charge(steps, budget)
        while index < length and source[index] != char:
            index += 1
            steps = _charge(steps, budget)
        if index >= length:
            break
        mapping.append(index)
        index += 1
    return mapping


def normalize_tracked(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Normalized text plus the original span covered by each normalized character."""
    folded, cover = _fold_tracked(text)
    if "\n" not in folded:
        return folded, cover
    joined = join_split_tokens(folded)
    if joined == folded:
        return folded, cover
    # Rebuild by walking the original folded text and the joined result together
    # is unnecessary: join only deletes some newlines. Find those positions.
    drop: set[int] = set()
    folded_i = 0
    for char in joined:
        while folded_i < len(folded) and folded[folded_i] != char:
            drop.add(folded_i)
            folded_i += 1
        folded_i += 1
    while folded_i < len(folded):
        drop.add(folded_i)
        folded_i += 1
    return _drop_tracked(folded, cover, drop)
