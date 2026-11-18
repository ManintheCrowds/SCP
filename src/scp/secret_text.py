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
        index += 1
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


def _join_run(line: str, *, reverse: bool) -> int:
    count = 0
    chars = reversed(line) if reverse else line
    for char in chars:
        if char not in _JOIN:
            break
        count += 1
    return count


def join_split_tokens(text: str) -> str:
    """Join a newline inside a JSON string, or a newline that splits a token."""
    if "\n" not in text:
        return text
    without_json_breaks: list[str] = []
    in_string = False
    escaped = False
    for char in text:
        if in_string and char == "\n" and not escaped:
            escaped = False
            continue
        if in_string and escaped:
            escaped = False
        elif in_string and char == "\\":
            escaped = True
        elif char == '"':
            in_string = not in_string
        without_json_breaks.append(char)
    lines = "".join(without_json_breaks).split("\n")
    joined: list[str] = [lines[0]]
    for line in lines[1:]:
        previous = joined[-1]
        if previous.endswith("\\"):
            joined[-1] = previous[:-1] + line
            continue
        if _join_run(previous, reverse=True) >= 8 and _join_run(line, reverse=False) >= 4:
            joined[-1] = previous + line
            continue
        joined.append(line)
    return "\n".join(joined)


def surface_for_matching(text: str, contains_secret) -> str:
    """Fold and decode a bounded surface before secret patterns run."""
    folded = fold_chars(text)
    joined = join_split_tokens(folded)
    encoded = redact_encoded_secrets(joined, contains_secret)
    return redact_base64_secrets(encoded, contains_secret)
