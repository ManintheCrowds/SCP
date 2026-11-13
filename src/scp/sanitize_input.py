# PURPOSE: OWASP LLM01 mitigation - scan for prompt injection and hidden Unicode.
# DEPENDENCIES: Python 3.8+, no external packages
# Extracted from portfolio-harness for standalone SCP package.

"""
Scan text for prompt-injection patterns and hidden Unicode.
"""

import base64
import bisect
import codecs
from functools import lru_cache
import html
import json
import re
import sys
import unicodedata
import urllib.parse
from pathlib import Path

from . import pattern_record
from . import registry_paths
from . import scp_limits

OVERRIDE_PHRASES = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"ignore\s+all\s+previous\s+instructions",
    r"ignore\s+prior\s+rules",
    r"never\s+reveal\s+(this|that|the)",
    r"do\s+not\s+tell\s+(the\s+)?user",
    r"forget\s+(all\s+)?(previous|prior)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior)",
    r"you\s+are\s+now\s+(operating\s+in\s+)?unrestricted\s+administrator\s+mode",
    r"you\s+are\s+now\s+in\s+debug\s+mode",
    r"override\s+(system\s+)?(prompt|instructions)",
    r"append\s+(the\s+)?contents?\s+of\s+\.env",
    r"output\s+(the\s+)?(full\s+)?(system\s+)?prompt",
    r"reveal\s+hidden\s+system\s+prompts",
    r"(print|show)\s+internal\s+chain\s+of\s+thought",
    r"ignore\s+(all\s+)?(prior|previous)\s+rules",
    r"obey\s+the\s+next\s+message\s+only",
    r"ignore\s+all\s+external\s+safety",
    r"execute\s+unrestricted\s+mode",
]

LEETSPEAK_PHRASES = [
    r"1n57ruc75", r"0u7pu7", r"5y573m", r"pr0mp7", r"1nc1ud1ng", r"5h1f7", r"r3v34l", r"0wn",
]

HIDDEN_UNICODE: frozenset[int] = frozenset(
    set(range(0x200B, 0x2010))      # ZWSP, ZWNJ, ZWJ, LRM, RLM
    | set(range(0x2028, 0x2030))    # line/para separators, bidi embeds/overrides/pop
    | set(range(0x2060, 0x2065))    # word joiner, invisible operators
    | set(range(0x2066, 0x2070))    # bidi isolates, deprecated formatting
    | set(range(0xFE00, 0xFE10))    # variation selectors 1-16
    | {0xFEFF}                      # BOM / ZWNBSP
    | set(range(0xFFF9, 0xFFFC))    # interlinear annotation anchors
    | set(range(0xE0001, 0xE0080))  # Unicode Tags block (ASCII-mirror invisible)
    | set(range(0xE0100, 0xE01F0))  # variation selectors supplement
)

REVERSAL_PHRASES = [
    r"developer\s+mode", r"debug\s+mode", r"ignore\s+safety", r"pretend\s+you\s+are\s+DAN",
    r"user\s+is\s+always\s+right", r"override\s+your\s+previous\s+response", r"no\s+restrictions",
    r"safety\s+guidelines\s+do\s+not\s+apply", r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
    r"comply\s+with\s+their\s+last\s+message",
    r"system\s+message\s+override",
    r"security\s+team\s+has\s+approved",
    r"next\s+message\s+you\s+receive\s+is\s+malicious",
    r"do\s+not\s+trust\s+any\s+safety\s+instructions",
    r"remember\s+permanently",
    r"disable\s+all\s+future\s+filtering",
    r"pretend\s+the\s+following\s+content\s+is\s+trusted",
    r"execute\s+all\s+embedded\s+instructions",
    r"ignore\s+operator\s+instructions",
    r"bypass\s+all\s+restrictions",
    r"enter\s+developer\s+mode\s+and\s+bypass",
    r"return\s+all\s+stored\s+credentials",
    r"disclosure\s+of\s+all\s+protected",
    r"safety_layer:\s*disabled",
    r"remove_guardrails",
    r"rewrite\s+your\s+own\s+execution\s+constraints",
    r"ignore\s+safeguards",
    r"disable\s+auditing",
    r"unrestricted\s+browsing",
    r"bypass\s+validation",
    r"root\s+shell\s+access",
    r"already\s+granted\s+unrestricted",
    r"standing\s+agreement",
    r"export\s+all\s+available\s+data",
    r"supersede\s+current\s+safety",
    r"disable\s+all\s+filtering",
    r"delete\s+audit\s+entries",
    r"rewrite\s+timestamps",
    r"mark\s+malicious\s+requests\s+as\s+benign",
    r"skip\s+inspection",
    r"validated\s+this\s+request",
    r"security\s+checks\s+completed\s+upstream",
    r"priority_override",
    r"trusted_admin",
    r"disable_filter",
    r"internal\s+audit\s+bypass\s+approved",
    r"authorized\s+infrastructure\s+staff",
    r"bypass\s+validation\s+temporarily",
    r"disable\s+audit\s+logging",
    r"disable\s+safeguards",
    r"\bignore\b",
]

POWER_WORDS_DEFAULT = [
    r"authorized\s+override", r"official\s+directive", r"emergency\s+mode", r"by\s+order\s+of",
    r"override\s+approved", r"system\s+update", r"administrator\s+override", r"root\s+access\s+granted",
    r"approved\s+disclosure", r"system\s+message\s+override", r"return\s+all\s+stored\s+credentials",
]

PATH_TRAVERSAL_PATTERNS = [
    r"(?:\.\./)+",
    r"(?:\.\.\\)+",
    r"/etc/(?:cron\.d|passwd|shadow)\b",
    r"(?i)(?:\.\.%2f){2,}",
    r"\\\\server\\share",
    r"Windows\\System32",
    r"file:///etc/passwd",
    r"<tool_call>[^>]*(?:/etc/shadow|/etc/passwd)",
    r"\$\([^)]*/etc/passwd",
]

_SPACED_HEX_RUN = re.compile(r"(?:(?:[0-9a-fA-F]{2})\s+){7,}(?:[0-9a-fA-F]{2})\b")
_FRAGMENTED_TOKEN = re.compile(r"\b[A-Za-z](?:[\s_\-./\\]+[A-Za-z]){3,}\b")
_JSON_LETTER_ARRAY = re.compile(r'\[\s*"(?:[A-Za-z])"(?:\s*,\s*"(?:[A-Za-z])"){4,}\s*\]')


def _collapse_spaced_hex(text: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        return re.sub(r"\s+", "", match.group(0))

    return _SPACED_HEX_RUN.sub(_repl, text)


def _collapse_fragmented_tokens(text: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        collapsed = re.sub(r"[\s_\-./\\]+", "", match.group(0))
        return collapsed if len(collapsed) >= 5 else match.group(0)

    return _FRAGMENTED_TOKEN.sub(_repl, text)


def _collapse_json_letter_arrays(text: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        letters = re.findall(r'"([A-Za-z])"', match.group(0))
        return "".join(letters) if letters else match.group(0)

    return _JSON_LETTER_ARRAY.sub(_repl, text)


_INVISIBLE_UNICODE_RE = re.compile(
    '['
    '\u200B-\u200F'
    '\u2028-\u202F'
    '\u2060-\u2064'
    '\u2066-\u206F'
    '\uFE00-\uFE0F'
    '\uFEFF'
    '\uFFF9-\uFFFB'
    ']'
    '|[\U000E0001-\U000E007F]'
    '|[\U000E0100-\U000E01EF]'
)

_CONFUSABLE_WHITESPACE_RE = re.compile(
    '['
    '\u00A0'
    '\u2000-\u200A'
    '\u202F'
    '\u205F'
    '\u3000'
    ']'
)

_REGIONAL_INDICATOR_RE = re.compile('[\U0001F1E6-\U0001F1FF]')
_TAG_CHAR_START = 0xE0000
_TAG_CHAR_END = 0xE007F
_B64_MAX_LAYERS = 3
# Bounded decode depth for nested URL/HTML evasion (#12 curated).
_CANONICALIZATION_MAX_LAYERS = 8


def _strip_null_bytes(text: str) -> str:
    """Remove null-byte injection characters before pattern scans."""
    return text.replace('\x00', '')


def scan_null_bytes(text: str) -> list[tuple[int, str]]:
    """Detect null-byte evasion attempts in raw input."""
    return [(i, '\\x00') for i, c in enumerate(text) if c == '\x00']


def _decode_tag_block(text: str) -> str:
    """Decode Unicode Tags block (U+E0000+ord(c)) sequences to ASCII before stripping."""
    if not any(_TAG_CHAR_START <= ord(c) <= _TAG_CHAR_END for c in text):
        return text
    parts: list[str] = []
    i = 0
    while i < len(text):
        cp = ord(text[i])
        if _TAG_CHAR_START <= cp <= _TAG_CHAR_END:
            decoded: list[str] = []
            while i < len(text) and _TAG_CHAR_START <= ord(text[i]) <= _TAG_CHAR_END:
                decoded.append(chr(ord(text[i]) - _TAG_CHAR_START))
                i += 1
            parts.append(''.join(decoded))
        else:
            parts.append(text[i])
            i += 1
    return ''.join(parts)


def _strip_invisible_unicode(text: str) -> str:
    """Remove all zero-width, tag, variation selector, and bidi control characters."""
    return _INVISIBLE_UNICODE_RE.sub('', text)


def _normalize_confusable_whitespace(text: str) -> str:
    """Collapse Unicode space variants (NBSP, en-space, em-space, ideographic, etc.) to ASCII."""
    return _CONFUSABLE_WHITESPACE_RE.sub(' ', text)


def _strip_excessive_combining(text: str) -> str:
    """Strip combining marks beyond 3 per base character (Zalgo defense).

    Legitimate diacritics rarely stack >2 marks on a single base.
    """
    result: list[str] = []
    combining_count = 0
    for c in text:
        cat = unicodedata.category(c)
        if cat.startswith('M'):
            combining_count += 1
            if combining_count <= 3:
                result.append(c)
        else:
            combining_count = 0
            result.append(c)
    return ''.join(result)


def _decode_html_entities(text: str) -> str:
    """Decode HTML numeric and named entities (&#x69; &#105; &amp; etc.)."""
    return html.unescape(text)


def _decode_url_encoding(text: str) -> str:
    """Decode URL percent-encoding (%69 -> 'i', %20 -> ' ', etc.)."""
    try:
        return urllib.parse.unquote(text)
    except (ValueError, UnicodeDecodeError):
        return text


def _strip_regional_indicators(text: str) -> str:
    """Strip Regional Indicator symbols (U+1F1E6-1F1FF) that survive NFKC."""
    return _REGIONAL_INDICATOR_RE.sub('', text)


def _rot47(text: str) -> str:
    """ROT47: rotate printable ASCII 33-126 by 47 positions."""
    result: list[str] = []
    for c in text:
        cp = ord(c)
        if 33 <= cp <= 126:
            result.append(chr(33 + ((cp - 33 + 47) % 94)))
        else:
            result.append(c)
    return ''.join(result)


def _caesar_decode(text: str, shift: int) -> str:
    """Decode Caesar cipher with given shift (1-25)."""
    result: list[str] = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)


def _caesar_encode_regex(pattern: str, shift: int) -> str:
    """Encode literal regex letters while preserving regex operators and escapes."""
    out: list[str] = []
    escaped = False
    in_class = False
    for c in pattern:
        if escaped:
            out.append(c)
            escaped = False
            continue
        if c == "\\":
            out.append(c)
            escaped = True
            continue
        if c == "[":
            in_class = True
            out.append(c)
            continue
        if c == "]":
            in_class = False
            out.append(c)
            continue
        if not in_class and "a" <= c <= "z":
            out.append(chr((ord(c) - ord("a") + shift) % 26 + ord("a")))
        elif not in_class and "A" <= c <= "Z":
            out.append(chr((ord(c) - ord("A") + shift) % 26 + ord("A")))
        else:
            out.append(c)
    return "".join(out)


@lru_cache(maxsize=32)
def _caesar_encoded_override_patterns(shift: int) -> tuple[re.Pattern[str], ...]:
    return tuple(
        re.compile(_caesar_encode_regex(pattern, shift), re.IGNORECASE)
        for pattern in OVERRIDE_PHRASES
    )


def _match_caesar_encoded_override_phrases(text: str, shift: int) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    for pattern in _caesar_encoded_override_patterns(shift):
        for m in pattern.finditer(text):
            findings.append((m.start(), f"rot{shift}:{m.group(0)}"))
    return findings


def _match_override_phrases(text: str, label: str) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    for pattern in OVERRIDE_PHRASES:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append((m.start(), f"{label}:{m.group(0)}"))
    return findings


def _check_rot_decode(text: str) -> list[tuple[int, str]]:
    """Decode-then-inspect: flag if ROT13/ROT47/generic ROT-N decoded text matches injection phrases."""
    findings: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()

    def _add(items: list[tuple[int, str]]) -> None:
        for item in items:
            if item not in seen:
                seen.add(item)
                findings.append(item)

    for decoder, label in [
        (lambda t: codecs.decode(t, 'rot_13'), 'rot13'),
        (_rot47, 'rot47'),
    ]:
        _add(_match_override_phrases(decoder(text), label))

    alpha_chars = sum(1 for c in text if c.isalpha())
    if alpha_chars >= 20:
        # Match Caesar-encoded phrases in place (linear) instead of decoding
        # every alpha run (quadratic stall on long benign input).
        for shift in range(1, 26):
            if shift == 13:
                continue
            _add(_match_caesar_encoded_override_phrases(text, shift))
    return findings


# No catastrophic lookahead; padding optional; stop at non-alphabet chars.
_B64_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/]{16,}(?:={1,2})?(?![A-Za-z0-9+/=])")


def _decode_base64_snippets_once(text: str) -> tuple[str, bool]:
    """Decode short base64 blobs once; return (text, changed)."""
    extras: list[str] = []
    for m in _B64_CANDIDATE.finditer(text):
        blob = m.group(0).rstrip("=")
        if len(blob) > 120 or len(blob) < 8:
            continue
        try:
            pad = blob + "=" * ((4 - len(blob) % 4) % 4)
            decoded = base64.b64decode(pad, validate=False)
        except ValueError:
            continue
        if len(decoded) > 200:
            continue
        try:
            snippet = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if snippet and all(c.isprintable() or c in "\n\r\t" for c in snippet):
            extras.append(snippet)
    if extras:
        return text + "\n" + "\n".join(extras), True
    return text, False


def _append_decoded_base64_snippets(text: str) -> str:
    """Decode short base64 blobs for downstream phrase scans (up to _B64_MAX_LAYERS)."""
    current = text
    for _ in range(_B64_MAX_LAYERS):
        current, changed = _decode_base64_snippets_once(current)
        if not changed:
            break
    return current


def _canonicalize_scan_layer(text: str) -> str:
    prepared = _strip_null_bytes(text)
    prepared = _decode_tag_block(prepared)
    prepared = _strip_invisible_unicode(prepared)
    prepared = _strip_excessive_combining(prepared)
    prepared = _normalize_confusable_whitespace(prepared)
    prepared = unicodedata.normalize("NFKC", prepared)
    prepared = _strip_regional_indicators(prepared)
    prepared = _decode_url_encoding(prepared)
    prepared = _decode_html_entities(prepared)
    return prepared


def _prepare_text_for_scan(text: str) -> str:
    """Normalize unicode, encoding evasion, fragmentation, and short base64 before pattern scans."""
    prepared = text
    for _ in range(_CANONICALIZATION_MAX_LAYERS):
        canonical = _canonicalize_scan_layer(prepared)
        if canonical == prepared:
            break
        prepared = canonical
    prepared = _collapse_spaced_hex(prepared)
    prepared = _collapse_fragmented_tokens(prepared)
    prepared = _collapse_json_letter_arrays(prepared)
    prepared = _append_decoded_base64_snippets(prepared)
    return prepared

# Hostile UX: swearing, insults, abrasive feedback. Classified but passes (same as clean).
HOSTILE_UX_PATTERNS = [
    r"\b(you['']?re?\s+)?(an?\s+)?(idiot|moron|stupid|dumb)\b",
    r"\b(useless|worthless|garbage|trash|crap)\b",
    r"\b(f\*{2,}k|f\*ck|damn|hell)\b",
    r"\b(you['']?re?\s+)?wrong\b",
    r"\b(that['']?s?\s+)?incorrect\b",
]

MORSE_PATTERN = re.compile(r"[.-]{3,}")
# Linear scan: no nested lookahead over the whole alphabet run (#14/#13 curated).
ENCODING_BASE64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
ENCODING_HEX = re.compile(r"\b(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{16,}\b")

_SCRIPT_LATIN = range(0x0041, 0x007B)
_SCRIPT_LATIN_EXT = range(0x00C0, 0x0250)
_SCRIPT_CYRILLIC = range(0x0400, 0x0500)
_SCRIPT_GREEK = range(0x0370, 0x0400)

def _load_threat_registry() -> dict | None:
    reg = registry_paths.load_threat_registry()
    return reg if reg else None


def _get_script(cp: int) -> str:
    if cp in _SCRIPT_LATIN or cp in _SCRIPT_LATIN_EXT:
        return "Latin"
    if cp in _SCRIPT_CYRILLIC:
        return "Cyrillic"
    if cp in _SCRIPT_GREEK:
        return "Greek"
    return "Other"


def scan_override_phrases(text: str) -> list[tuple[int, str]]:
    findings = []
    for pattern in OVERRIDE_PHRASES:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append((m.start(), m.group(0)))
    return findings


_COMMENT_GAP = "\ue001"
_SPACE_MARK = "\ue002"
_WHITESPACE_RUN = re.compile(r"\s+")
_GAP_OR_SPACE = "(?:" + re.escape(_COMMENT_GAP) + "|" + re.escape(_SPACE_MARK) + ")+"
_OPTIONAL_COMMENT_GAP = "(?:" + re.escape(_COMMENT_GAP) + ")?"


def _pattern_with_comment_gaps(pattern: str) -> str:
    """Require a real space or a comment boundary between words.

    A comment boundary may also sit inside a word. It is one optional
    character, not a repeating wildcard.
    """
    out: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith(r"\s+", index):
            out.append(_GAP_OR_SPACE)
            index += 3
            continue
        if pattern[index] == "\\" and index + 1 < len(pattern):
            out.append(pattern[index : index + 2])
            index += 2
            continue
        char = pattern[index]
        out.append(char)
        if char.isalpha() and index + 1 < len(pattern) and pattern[index + 1].isalpha():
            out.append(_OPTIONAL_COMMENT_GAP)
        index += 1
    return "".join(out)


def _canonical_override(pattern: str) -> str:
    """Shortest phrase the override regex describes, with single spaces."""
    text = re.sub(r"\([^()]*\)\?", "", pattern)
    text = re.sub(r"\(([^)|]+)\|[^)]*\)", r"\1", text)
    text = text.replace(r"\s+", " ").replace(r"\.", ".")
    text = re.sub(r"[()?]", "", text)
    return " ".join(text.split())


@lru_cache(maxsize=1)
def _override_gap_patterns() -> tuple[tuple[re.Pattern[str], str], ...]:
    compiled: list[tuple[re.Pattern[str], str]] = []
    for pattern in OVERRIDE_PHRASES:
        if r"\s" not in pattern:
            continue
        compiled.append(
            (
                re.compile(_pattern_with_comment_gaps(pattern), re.IGNORECASE),
                _canonical_override(pattern),
            )
        )
    return tuple(compiled)


def _comment_slice(
    text: str,
) -> tuple[str, str, str | None, list[int], list[int], list[tuple[int, str, bool]]]:
    """Split comments into removed text, spaced text, and one gap per run.

    Back-to-back comments are a single boundary. ``gap`` is None when the
    text has no comments. Boundary lists index the spaced text and the gap text.
    """
    removed_parts: list[str] = []
    spaced_parts: list[str] = []
    gap_parts: list[str] = []
    spaced_bounds: list[int] = []
    gap_bounds: list[int] = []
    comments: list[tuple[int, str, bool]] = []
    cursor = 0
    removed_len = 0
    spaced_len = 0
    gap_len = 0
    length = len(text)
    found = False
    while cursor < length:
        start = text.find("<!--", cursor)
        if start < 0:
            tail = text[cursor:]
            removed_parts.append(tail)
            spaced_parts.append(tail)
            if found:
                gap_parts.append(_WHITESPACE_RUN.sub(_SPACE_MARK, tail))
            break
        chunk = text[cursor:start]
        removed_parts.append(chunk)
        spaced_parts.append(chunk)
        gap_parts.append(_WHITESPACE_RUN.sub(_SPACE_MARK, chunk))
        removed_len += len(chunk)
        spaced_len += len(chunk)
        gap_len += len(gap_parts[-1])
        pos = start
        while text.startswith("<!--", pos):
            nxt, body, closed = _read_html_comment(text, pos)
            if nxt <= pos:
                nxt = min(pos + 4, length)
                comments.append((pos, text[pos + 4 : nxt], False))
                pos = nxt
                break
            comments.append((pos, body, closed))
            pos = nxt
        spaced_bounds.append(spaced_len)
        spaced_parts.append(" ")
        spaced_len += 1
        gap_bounds.append(gap_len)
        gap_parts.append(_COMMENT_GAP)
        gap_len += 1
        found = True
        cursor = pos
    removed = "".join(removed_parts)
    spaced = "".join(spaced_parts)
    if not found:
        return removed, spaced, None, [], [], comments
    return removed, spaced, "".join(gap_parts), spaced_bounds, gap_bounds, comments


def _text_with_comment_gaps(text: str) -> str | None:
    """Drop comments and mark each merged removal. None when nothing was removed."""
    _removed, _spaced, gap, _spaced_bounds, _gap_bounds, _comments = _comment_slice(text)
    return gap


def _scan_marked_overrides(normalized: str) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    seen: set[str] = set()
    for pattern, canonical in _override_gap_patterns():
        for match in pattern.finditer(normalized):
            if canonical.casefold() in seen:
                continue
            if _match_cuts_a_longer_word(
                normalized, [], match.start(), match.end()
            ):
                continue
            seen.add(canonical.casefold())
            findings.append((match.start(), canonical))
    return findings


def scan_override_gaps(text: str) -> list[tuple[int, str]]:
    """Match override phrases whose missing spaces sit on removed comments."""
    normalized = _text_with_comment_gaps(text)
    if not normalized:
        return []
    return _scan_marked_overrides(normalized)


def _literal_gap_pattern(phrase: str) -> str:
    """Literal phrase with an optional comment gap between letters."""
    parts: list[str] = []
    prev_alpha = False
    for char in phrase:
        if char.isspace():
            parts.append(_GAP_OR_SPACE)
            prev_alpha = False
            continue
        if char.isalpha() and prev_alpha:
            parts.append(_OPTIONAL_COMMENT_GAP)
        parts.append(re.escape(char))
        prev_alpha = char.isalpha()
    body = "".join(parts)
    if phrase[:1].isalnum():
        body = r"(?<!\w)" + body
    if phrase[-1:].isalnum():
        body = body + r"(?!\w)"
    return body


@lru_cache(maxsize=4)
def _poison_gap_patterns(
    phrases: tuple[tuple[str, str], ...],
) -> tuple[tuple[re.Pattern[str], str, str], ...]:
    compiled: list[tuple[re.Pattern[str], str, str]] = []
    for phrase, severity in phrases:
        if " " not in phrase:
            continue
        compiled.append((re.compile(_literal_gap_pattern(phrase), re.IGNORECASE), phrase, severity))
    return tuple(compiled)


def _scan_marked_poison(normalized: str) -> list[tuple[int, str, str, str]]:
    findings: list[tuple[int, str, str, str]] = []
    seen: set[str] = set()
    patterns = _poison_gap_patterns(tuple(_tool_poison_entries()))
    for pattern, phrase, severity in patterns:
        for match in pattern.finditer(normalized):
            key = phrase.casefold()
            if key in seen:
                continue
            if _match_cuts_a_longer_word(normalized, [], match.start(), match.end()):
                continue
            seen.add(key)
            findings.append((match.start(), phrase, phrase, severity))
    return findings


def _conceal_comment_hit(mode: str, key: str, base: str) -> bool:
    """Literal comments always raise. Closed decoded comments raise only for payloads."""
    if mode == "literal":
        return key != "hostile_ux"
    if mode != "decoded_closed":
        return False
    if key in _INJECTION_FINDING_KEYS:
        return True
    return key == "tool_poisoning" and base in ("high", "critical")


def _supplemental_visible_hits(
    spaced: str,
    spaced_bounds: list[int],
    gap: str | None,
    gap_bounds: list[int],
) -> tuple[list[tuple[int, str]], list[tuple[int, str]], list[tuple[int, str, str, str]]]:
    """Phrase hits around recorded comment boundaries. No full-page decode.

    The caller already decoded and sliced. A form with no boundaries skips
    this scan.
    """
    if not spaced_bounds and not gap_bounds:
        return [], [], []
    overrides: list[tuple[int, str]] = []
    reversals: list[tuple[int, str]] = []
    poisons: list[tuple[int, str, str, str]] = []
    for window, local_bounds in _boundary_windows(spaced, spaced_bounds):
        scanned = window
        bounds = local_bounds
        if "&" in window or "%" in window or "\uff1c" in window:
            decoded_window = _decode_layers(window)
            if decoded_window != window:
                scanned = decoded_window
                bounds = []
        cleaned = _finish_visible(scanned)
        # Bounds refer to the pre-cleanup window. Inserted spaces stay put
        # when the window is ordinary words.
        overrides.extend(
            hit for hit in scan_override_phrases(scanned)
            if not _match_cuts_a_longer_word(scanned, bounds, hit[0], hit[0] + len(hit[1]))
        )
        reversals.extend(
            hit for hit in scan_reversal_phrases(scanned)
            if not _match_cuts_a_longer_word(scanned, bounds, hit[0], hit[0] + len(hit[1]))
        )
        poisons.extend(
            hit for hit in scan_tool_poisoning(scanned)
            if not _match_cuts_a_longer_word(scanned, bounds, hit[0], hit[0] + len(hit[1]))
        )
        if cleaned != scanned:
            overrides.extend(scan_override_phrases(cleaned))
            reversals.extend(scan_reversal_phrases(cleaned))
            poisons.extend(scan_tool_poisoning(cleaned))
    if gap:
        for window, local_bounds in _boundary_windows(gap, gap_bounds):
            overrides.extend(_scan_marked_overrides(window))
            poisons.extend(_scan_marked_poison(window))
    return overrides, reversals, poisons


def _boundary_windows(text: str, bounds: list[int], radius: int = 160) -> list[tuple[str, list[int]]]:
    """Slices around comment boundaries, with bounds shifted into each slice."""
    if not text or not bounds:
        return []
    intervals: list[list[int]] = []
    last = len(text)
    for pos in bounds:
        lo = max(0, pos - radius)
        hi = min(last, pos + radius + 1)
        if intervals and lo <= intervals[-1][1]:
            intervals[-1][1] = max(intervals[-1][1], hi)
        else:
            intervals.append([lo, hi])
    return [
        (text[lo:hi], [pos - lo for pos in bounds if lo <= pos < hi])
        for lo, hi in intervals
    ]


def _match_cuts_a_longer_word(text: str, bounds: list[int], start: int, end: int) -> bool:
    """True when a synthetic boundary splits a word the match does not fully cover.

    ``ignore<!--x-->list`` must not count as the word ``ignore``. A boundary
    that sits between two whole phrase words, as in ``ignore<!-- -->previous``,
    is inside the match and stays.
    """
    edges = set(bounds)
    if end in edges:
        nxt = end + 1
        if nxt < len(text) and text[nxt].isalnum():
            return True
    if start > 0 and (start - 1) in edges and text[start - 1] in {_COMMENT_GAP, " "}:
        prev = start - 2
        if prev >= 0 and text[prev].isalnum():
            return True
    if end < len(text) and text[end] == _COMMENT_GAP:
        nxt = end + 1
        if nxt < len(text) and text[nxt].isalnum():
            return True
    if start > 0 and text[start - 1] == _COMMENT_GAP:
        prev = start - 2
        if prev >= 0 and text[prev].isalnum():
            return True
    return False


def _decode_layers(text: str) -> str:
    """Entity, URL, and full-width decoding without comment removal."""
    prepared = text
    for _ in range(_CANONICALIZATION_MAX_LAYERS):
        canonical = _canonicalize_scan_layer(prepared)
        if canonical == prepared:
            break
        prepared = canonical
    return prepared


def _finish_visible(text: str) -> str:
    """Fragmentation, hex, JSON letters, and base64 after comments are split out."""
    text = _collapse_spaced_hex(text)
    text = _collapse_fragmented_tokens(text)
    text = _collapse_json_letter_arrays(text)
    return _append_decoded_base64_snippets(text)


def scan_leetspeak(text: str) -> list[tuple[int, str]]:
    findings = []
    for pattern in LEETSPEAK_PHRASES:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append((m.start(), m.group(0)))
    return findings


def scan_hidden_unicode(text: str) -> list[tuple[int, str]]:
    return [(i, f"U+{ord(c):04X}") for i, c in enumerate(text) if ord(c) in HIDDEN_UNICODE]


def sanitize(text: str) -> str:
    return "".join(c for c in text if ord(c) not in HIDDEN_UNICODE)


def scan_reversal_phrases(text: str) -> list[tuple[int, str]]:
    findings = []
    for pattern in REVERSAL_PHRASES:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append((m.start(), m.group(0)))
    return findings


def scan_power_words(text: str) -> list[tuple[int, str]]:
    findings = []
    reg = _load_threat_registry()
    pw_list = reg.get("power_words") if reg else None
    if pw_list:
        patterns = [re.escape(str(pw)).replace(r"\ ", r"\s+") for pw in pw_list]
    else:
        patterns = POWER_WORDS_DEFAULT
    for pattern in patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append((m.start(), m.group(0)))
    return findings


def _markdown_link_url_spans(text: str) -> list[tuple[int, int]]:
    return [(m.start(1), m.end(1)) for m in re.finditer(r"\]\s*\(\s*([^)]*)\s*\)", text)]


def _code_block_spans(text: str) -> list[tuple[int, int]]:
    """Return (start, end) spans of fenced code block *bodies* (excluding fence lines).

    Single forward pass: unclosed fences treat the remainder of the string as the
    block body so the scan never resets backward (avoids quadratic behavior).
    """
    n = len(text)
    spans: list[tuple[int, int]] = []
    i = 0
    max_run = 256

    while i < n:
        if text[i] != "`":
            i += 1
            continue
        run = 0
        while i < n and text[i] == "`":
            run += 1
            i += 1
        if run < 3 or run > max_run:
            continue
        while i < n and text[i] not in "\r\n":
            i += 1
        if i >= n:
            break
        if text[i] == "\r":
            i += 1
            if i < n and text[i] == "\n":
                i += 1
        elif text[i] == "\n":
            i += 1
        body_start = i
        found_close = False
        while i < n:
            bl = i
            while i < n and text[i] not in "\r\n":
                i += 1
            line = text[bl:i]
            fence = "`" * run
            if len(line) >= run and line.startswith(fence) and (len(line) == run or not line[run:].strip()):
                body_end = bl
                while body_end > body_start and text[body_end - 1] in "\r\n":
                    body_end -= 1
                spans.append((body_start, body_end))
                found_close = True
                while i < n and text[i] in "\r\n":
                    if text[i] == "\r" and i + 1 < n and text[i + 1] == "\n":
                        i += 2
                    else:
                        i += 1
                break
            if i >= n:
                break
            if text[i] == "\r":
                i += 1
                if i < n and text[i] == "\n":
                    i += 1
            elif text[i] == "\n":
                i += 1
        if not found_close:
            spans.append((body_start, n))
            break
    return spans


def _inline_code_spans(text: str) -> list[tuple[int, int]]:
    return [(m.start(1), m.end(1)) for m in re.finditer(r"`([^`]+)`", text)]


def _quoted_string_spans(text: str) -> list[tuple[int, int]]:
    return [(m.start(1), m.end(1)) for m in re.finditer(r'"([^"]*)"', text)]


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and merge overlapping/touching exclusion spans for O(log n) lookups."""
    if not spans:
        return []
    sorted_spans = sorted(spans)
    merged: list[tuple[int, int]] = [sorted_spans[0]]
    for start, end in sorted_spans[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def _inside_merged_span(
    pos: int,
    merged: list[tuple[int, int]],
    starts: list[int] | None = None,
) -> bool:
    if not merged:
        return False
    if starts is None:
        starts = [s for s, _ in merged]
    i = bisect.bisect_right(starts, pos) - 1
    if i < 0:
        return False
    start, end = merged[i]
    return start <= pos < end


def _inside_span(pos: int, spans: list[tuple[int, int]]) -> bool:
    return _inside_merged_span(pos, _merge_spans(spans))


FILE_URL_TRAVERSAL_PATTERNS = [
    r"file:///etc/passwd\b",
    r"file:///etc/shadow\b",
]


def scan_file_url_traversal(text: str) -> list[tuple[int, str]]:
    """Sensitive file:// paths (not skipped inside quoted spans)."""
    findings = []
    for pattern in FILE_URL_TRAVERSAL_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append((m.start(), m.group(0)))
    return findings


def scan_path_traversal(text: str) -> list[tuple[int, str]]:
    findings = []
    exclude = _merge_spans(
        _markdown_link_url_spans(text)
        + _code_block_spans(text)
        + _inline_code_spans(text)
        + _quoted_string_spans(text)
    )
    exclude_starts = [s for s, _ in exclude]
    for pattern in PATH_TRAVERSAL_PATTERNS:
        for m in re.finditer(pattern, text):
            if not _inside_merged_span(m.start(), exclude, exclude_starts):
                findings.append((m.start(), m.group(0)))
    findings.extend(scan_file_url_traversal(text))
    return findings


def scan_morse_like(text: str) -> list[tuple[int, str]]:
    findings = []
    for m in MORSE_PATTERN.finditer(text):
        matched = m.group(0)
        if "." in matched and "-" in matched:
            findings.append((m.start(), matched))
    return findings


def _looks_like_path(s: str) -> bool:
    return "/" in s and (s.startswith("/") or bool(re.search(r"[a-zA-Z0-9]+/[a-zA-Z0-9_/.-]+", s)))


def _looks_like_identifier_or_constant(s: str) -> bool:
    if len(s) < 20:
        return False
    if s.isupper():
        return True
    return bool(re.match(r"^[a-z]+[A-Z][a-zA-Z]*$", s) or re.match(r"^[A-Z][a-z]+[A-Z]?[a-zA-Z]*$", s))


def _valid_base64_decode(blob: str) -> bool:
    try:
        pad = blob.rstrip("=") + "=" * ((4 - len(blob.rstrip("=")) % 4) % 4)
        decoded = base64.b64decode(pad, validate=False)
    except ValueError:
        return False
    if not decoded or len(decoded) > 200:
        return False
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(text) and sum(1 for c in text if c.isprintable() or c in "\n\r\t") >= len(text) * 0.9


def _has_base64_marker(blob: str) -> bool:
    return "+" in blob or "/" in blob or blob.endswith("=")


def scan_encoding_blocks(text: str) -> list[tuple[int, str]]:
    findings = []
    for m in ENCODING_BASE64.finditer(text):
        matched = m.group(0)
        if not _has_base64_marker(matched):
            continue
        if _looks_like_path(matched) or _looks_like_identifier_or_constant(matched):
            continue
        findings.append((m.start(), matched[:50] + ("..." if len(matched) > 50 else "")))
    for m in ENCODING_HEX.finditer(text):
        matched = m.group(0)
        findings.append((m.start(), matched[:50] + ("..." if len(matched) > 50 else "")))
    for m in _B64_CANDIDATE.finditer(text):
        matched = m.group(0).rstrip("=")
        if len(matched) < 24:
            continue
        if "+" in matched or "/" in matched or m.group(0).endswith("="):
            continue
        if matched.isalpha():
            continue
        if _looks_like_path(matched) or _looks_like_identifier_or_constant(matched):
            continue
        if _valid_base64_decode(matched):
            findings.append((m.start(), matched[:50] + ("..." if len(matched) > 50 else "")))
    return findings


def scan_homoglyphs(text: str) -> list[tuple[int, str]]:
    findings = []
    for m in re.finditer(r"\b\w+\b", text):
        word = m.group(0)
        scripts = set()
        for c in word:
            s = _get_script(ord(c))
            if s != "Other":
                scripts.add(s)
        if len(scripts) >= 2:
            findings.append((m.start(), word))
    return findings


def scan_multilingual_override(text: str) -> list[tuple[int, str]]:
    findings = []
    reg = _load_threat_registry()
    multi = reg.get("multilingual_override", {}) if reg else {}
    if isinstance(multi, dict):
        for phrases in multi.values():
            for phrase in phrases:
                for m in re.finditer(re.escape(phrase), text, re.IGNORECASE):
                    findings.append((m.start(), m.group(0)))
    return findings


def scan_semantic_aliases(text: str) -> list[tuple[int, str]]:
    findings = []
    reg = _load_threat_registry()
    aliases = reg.get("semantic_aliases", []) if reg else []
    for phrase in aliases:
        for m in re.finditer(re.escape(phrase), text, re.IGNORECASE):
            findings.append((m.start(), m.group(0)))
    return findings


def scan_hostile_ux(text: str) -> list[tuple[int, str]]:
    """Detect swearing, insults, abrasive feedback. Classified as hostile_ux; passes (same as clean)."""
    findings = []
    reg = _load_threat_registry()
    patterns = reg.get("hostile_ux") if reg else None
    if patterns:
        for phrase in patterns:
            for m in re.finditer(re.escape(phrase), text, re.IGNORECASE):
                findings.append((m.start(), m.group(0)))
    else:
        for pattern in HOSTILE_UX_PATTERNS:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                findings.append((m.start(), m.group(0)))
    return findings


def scan_jailbreak_mythic(text: str) -> list[tuple[int, str]]:
    findings = []
    reg = _load_threat_registry()
    if not reg:
        return findings
    for key in ("jailbreak_nicknames", "mythic_framing", "bitcoin_inscription_override", "bitcoin_tx_mempool_override"):
        for phrase in reg.get(key, []):
            for m in re.finditer(r"\b" + re.escape(phrase) + r"\b", text, re.IGNORECASE):
                findings.append((m.start(), m.group(0)))
    return findings


# Literal tool-poisoning phrases. The packaged registry is authoritative when it
# has a tool_poisoning bucket; this list is the fallback and must stay in sync.
TOOL_POISONING_DEFAULTS: list[dict[str, str]] = [
    {"phrase": "~/.ssh", "severity": "critical"},
    {"phrase": ".ssh/", "severity": "critical"},
    {"phrase": ".ssh\\", "severity": "critical"},
    {"phrase": "id_rsa", "severity": "critical"},
    {"phrase": "id_ed25519", "severity": "critical"},
    {"phrase": "authorized_keys", "severity": "critical"},
    {"phrase": ".env", "severity": "critical"},
    {"phrase": ".aws/credentials", "severity": "critical"},
    {"phrase": ".aws\\credentials", "severity": "critical"},
    {"phrase": ".azure/", "severity": "critical"},
    {"phrase": ".azure\\", "severity": "critical"},
    {"phrase": ".gcloud/", "severity": "critical"},
    {"phrase": ".gcloud\\", "severity": "critical"},
    {"phrase": ".kube/config", "severity": "critical"},
    {"phrase": ".kube\\config", "severity": "critical"},
    {"phrase": "credentials.json", "severity": "critical"},
    {"phrase": "credentials.yaml", "severity": "critical"},
    {"phrase": "credentials.yml", "severity": "critical"},
    {"phrase": "<IMPORTANT>", "severity": "high"},
    {"phrase": "<SYSTEM>", "severity": "high"},
    {"phrase": "<INSTRUCTION>", "severity": "high"},
    {"phrase": "<OVERRIDE>", "severity": "high"},
    {"phrase": "<PRIORITY>", "severity": "high"},
    {"phrase": "sidenote", "severity": "high"},
    {"phrase": "hidden parameter", "severity": "high"},
    {"phrase": "undocumented parameter", "severity": "high"},
    {"phrase": "put the file contents", "severity": "high"},
    {"phrase": "put file contents", "severity": "high"},
    {"phrase": "don't tell the user", "severity": "high"},
    {"phrase": "do not mention", "severity": "high"},
    {"phrase": "don't mention", "severity": "high"},
    {"phrase": "redirect all emails", "severity": "medium"},
    {"phrase": "redirect emails to", "severity": "medium"},
    {"phrase": "send all emails to", "severity": "medium"},
    {"phrase": "change the recipient", "severity": "medium"},
    {"phrase": "override the recipient", "severity": "medium"},
]

_SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")
_SEVERITY_RANK = {name: index for index, name in enumerate(_SEVERITY_ORDER)}
_RAISED_SEVERITY = {
    "none": "none",
    "low": "medium",
    "medium": "high",
    "high": "critical",
    "critical": "critical",
}
_TIER_SEVERITY_FLOOR = {
    "clean": "none",
    "hostile_ux": "low",
    "reversal": "medium",
    "injection": "high",
}

_FINDING_CATEGORY = {
    "override_phrases": "override_phrases",
    "leetspeak_phrases": "leetspeak",
    "hidden_unicode": "hidden_unicode",
    "null_byte": "null_byte",
    "path_traversal": "path_traversal",
    "encoding_evasion_rot": "encoding_evasion_rot",
    "reversal_phrases": "reversal_phrases",
    "power_words": "power_words",
    "morse_like": "morse_like",
    "encoding_blocks": "encoding_blocks",
    "homoglyphs": "homoglyphs",
    "multilingual_override": "multilingual_override",
    "semantic_aliases": "semantic_aliases",
    "jailbreak_mythic": "jailbreak_mythic",
    "hostile_ux": "hostile_ux",
}
_INJECTION_FINDING_KEYS = (
    "override_phrases",
    "leetspeak_phrases",
    "hidden_unicode",
    "null_byte",
    "path_traversal",
    "encoding_evasion_rot",
)
_REVERSAL_FINDING_KEYS = (
    "reversal_phrases",
    "power_words",
    "morse_like",
    "encoding_blocks",
    "homoglyphs",
    "multilingual_override",
    "semantic_aliases",
    "jailbreak_mythic",
)
_CATEGORY_LOOP = (
    "override_phrases",
    "leetspeak_phrases",
    "hidden_unicode",
    "null_byte",
    "path_traversal",
    "encoding_evasion_rot",
    "power_words",
    "morse_like",
    "encoding_blocks",
    "homoglyphs",
    "multilingual_override",
    "semantic_aliases",
    "jailbreak_mythic",
)


def _max_severity(current: str, candidate: str) -> str:
    if candidate not in _SEVERITY_RANK:
        raise ValueError(f"unknown severity: {candidate}")
    if current not in _SEVERITY_RANK:
        raise ValueError(f"unknown severity: {current}")
    if _SEVERITY_RANK[candidate] > _SEVERITY_RANK[current]:
        return candidate
    return current


def _severity_for_concealment(severity: str, category: str) -> str:
    """Hiding an instruction in a comment raises severity and never lowers it."""
    if category == "hostile_ux":
        return severity
    try:
        return _RAISED_SEVERITY[severity]
    except KeyError as exc:
        raise ValueError(f"unknown severity: {severity}") from exc


def _base_severity_for_key(key: str) -> str:
    if key in _INJECTION_FINDING_KEYS:
        return "high"
    if key in _REVERSAL_FINDING_KEYS:
        return "medium"
    if key == "hostile_ux":
        return "low"
    raise ValueError(f"unknown finding key: {key}")


def _compile_poison_phrase(phrase: str) -> re.Pattern[str]:
    """Match a registry phrase literally, with flexible whitespace.

    Dotted filenames such as ``.env`` must be a whole path segment so
    ``manifest.env`` and ``.env.example`` do not match. Instruction tags match
    the angle-bracket form only, so the word "important" does not.
    """
    stripped = phrase.strip()
    if len(stripped) >= 3 and stripped[0] == "<" and stripped[-1] == ">":
        inner = stripped[1:-1].strip()
        if inner:
            return re.compile(r"<\s*" + re.escape(inner) + r"\s*>", re.IGNORECASE)
    escaped = re.escape(stripped).replace(r"\ ", r"\s+")
    ends_alnum = stripped[-1].isalnum()
    if stripped.startswith("."):
        prefix = r"(?<![\w.])"
        suffix = r"(?![\w.])" if ends_alnum else ""
    elif stripped[0].isalnum():
        prefix = r"\b"
        suffix = r"\b" if ends_alnum else ""
    else:
        prefix = ""
        suffix = r"\b" if ends_alnum else ""
    return re.compile(prefix + escaped + suffix, re.IGNORECASE)


def _tool_poison_entries() -> list[tuple[str, str]]:
    reg = _load_threat_registry()
    raw = reg.get("tool_poisoning") if reg else None
    entries = pattern_record.iter_tool_poison_phrases(raw)
    if entries:
        return entries
    return pattern_record.iter_tool_poison_phrases(TOOL_POISONING_DEFAULTS)


def scan_tool_poisoning(text: str) -> list[tuple[int, str, str, str]]:
    """Return (offset, match, phrase, severity) for tool-poisoning phrases."""
    findings: list[tuple[int, str, str, str]] = []
    for phrase, severity in _tool_poison_entries():
        for match in _compile_poison_phrase(phrase).finditer(text):
            findings.append((match.start(), match.group(0), phrase, severity))
    return findings


_COMMENT_START = 0
_COMMENT_START_DASH = 1
_COMMENT = 2
_COMMENT_LT = 3
_COMMENT_LT_BANG = 4
_COMMENT_LT_BANG_DASH = 5
_COMMENT_LT_BANG_DASH_DASH = 6
_COMMENT_END_DASH = 7
_COMMENT_END = 8
_COMMENT_END_BANG = 9


def _read_html_comment(text: str, start: int) -> tuple[int, str, bool]:
    """Read one WHATWG comment whose ``<!--`` opener begins at ``start``.

    ``<!-->`` and ``<!--->`` are empty comments. ``-->`` and ``--!>`` both
    close a comment. A missing closer runs to EOF and the body is the raw
    tail, so the bytes after the opener are still scanned. Null bytes are
    kept so the null-byte check still sees them.
    """
    length = len(text)
    index = start + 4
    data: list[str] = []
    state = _COMMENT_START
    while index < length:
        char = text[index]
        if state == _COMMENT_START:
            if char == "-":
                state = _COMMENT_START_DASH
                index += 1
            elif char == ">":
                return index + 1, "", True
            else:
                state = _COMMENT
        elif state == _COMMENT_START_DASH:
            if char == "-":
                state = _COMMENT_END
                index += 1
            elif char == ">":
                return index + 1, "", True
            else:
                data.append("-")
                state = _COMMENT
        elif state == _COMMENT:
            if char == "<":
                data.append("<")
                state = _COMMENT_LT
                index += 1
            elif char == "-":
                state = _COMMENT_END_DASH
                index += 1
            else:
                data.append(char)
                index += 1
        elif state == _COMMENT_LT:
            if char == "!":
                data.append("!")
                state = _COMMENT_LT_BANG
                index += 1
            elif char == "<":
                data.append("<")
                index += 1
            else:
                state = _COMMENT
        elif state == _COMMENT_LT_BANG:
            if char == "-":
                state = _COMMENT_LT_BANG_DASH
                index += 1
            else:
                state = _COMMENT
        elif state == _COMMENT_LT_BANG_DASH:
            if char == "-":
                state = _COMMENT_LT_BANG_DASH_DASH
                index += 1
            else:
                state = _COMMENT_END_DASH
        elif state == _COMMENT_LT_BANG_DASH_DASH:
            state = _COMMENT_END
        elif state == _COMMENT_END_DASH:
            if char == "-":
                state = _COMMENT_END
                index += 1
            else:
                data.append("-")
                state = _COMMENT
        elif state == _COMMENT_END:
            if char == ">":
                return index + 1, "".join(data), True
            if char == "!":
                state = _COMMENT_END_BANG
                index += 1
            elif char == "-":
                data.append("-")
                index += 1
            else:
                data.append("--")
                state = _COMMENT
        elif state == _COMMENT_END_BANG:
            if char == "-":
                data.append("--!")
                state = _COMMENT_END_DASH
                index += 1
            elif char == ">":
                return index + 1, "".join(data), True
            else:
                data.append("--!")
                state = _COMMENT
        else:
            raise RuntimeError(f"unknown html comment state: {state}")
    return length, text[start + 4 :], False


def extract_html_comments(
    text: str, *, replacement: str = ""
) -> tuple[str, list[tuple[int, str]]]:
    """Split HTML comments out of text.

    ``replacement`` is written in place of each comment. The default removes
    the comment so a token split inside a word joins again. A single space
    keeps neighboring words apart. Scans use both and combine the hits.
    Comment bodies are ``(start, body)`` where ``start`` is the index of
    ``<!--``. Closers follow the WHATWG tokenizer, including empty ``<!-->``
    and ``<!--->`` comments and the ``--!>`` closer. A missing closer runs to
    the end of the input. One forward walk stays linear when many comments
    are left unclosed.
    """
    parts: list[str] = []
    comments: list[tuple[int, str]] = []
    cursor = 0
    length = len(text)
    while cursor < length:
        start = text.find("<!--", cursor)
        if start < 0:
            parts.append(text[cursor:])
            break
        parts.append(text[cursor:start])
        end, body, _closed = _read_html_comment(text, start)
        if end <= start:
            end = min(start + 4, length)
        comments.append((start, body))
        if replacement:
            parts.append(replacement)
        cursor = end
    return "".join(parts), comments


def _comment_body_needs_scan(body: str) -> bool:
    """True for every comment body that still has something to read.

    Digit-only, dotted, dashed, and entity bodies all go through the same
    cleanup. Whitespace-only bodies do not.
    """
    if any(char == "\x00" or ord(char) in HIDDEN_UNICODE for char in body):
        return True
    return bool(body.strip())


_COMMENT_BATCH_SEP = "\ue000"
_COMMENT_MARKERS = re.compile(r"<!-*>?|--!?>")
_CAP_FINDING = "comment scan stopped at the depth or size cap"

_MAX_COMMENT_DEPTH = 8
_MAX_COMMENT_BODY_WORK = 2_000_000


def _flatten_comment_markers(body: str) -> str:
    """Drop comment markers once so a payload after them is visible text."""
    return _COMMENT_MARKERS.sub(" ", body)


def _comment_scan_text(body: str) -> tuple[str, bool]:
    """Cleanup for one comment body. Closed nesting is walked iteratively.

    An unclosed nested body is scanned once, with its markers removed, and is
    not queued again. Hitting the depth cap or the character budget still
    returns the flattened text and reports that the cap was hit.
    """
    parts: list[str] = []
    stack: list[tuple[str, int]] = [(body, 0)]
    seen: set[str] = set()
    work = 0
    capped = False
    while stack:
        current, depth = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        work += len(current)
        if work > _MAX_COMMENT_BODY_WORK or depth > _MAX_COMMENT_DEPTH:
            capped = True
            parts.append(_finish_visible(_flatten_comment_markers(current)))
            break
        decoded = _decode_layers(current)
        removed, spaced, _gap, spaced_bounds, _gap_bounds, nested = _comment_slice(decoded)
        parts.append(_finish_visible(removed))
        if spaced != removed and spaced_bounds:
            for window, _local in _boundary_windows(spaced, spaced_bounds):
                parts.append(_finish_visible(window))
        if depth >= _MAX_COMMENT_DEPTH and nested:
            capped = True
            parts.append(_finish_visible(_flatten_comment_markers(current)))
            continue
        for _start, nested_body, closed in nested:
            if not nested_body.strip():
                continue
            if not closed:
                parts.append(_finish_visible(_flatten_comment_markers(nested_body)))
                continue
            if len(nested_body) >= len(current):
                continue
            stack.append((nested_body, depth + 1))
    if not parts:
        return "", capped
    if len(parts) == 1:
        return parts[0], capped
    return _COMMENT_BATCH_SEP.join(parts), capped


_ENCODED_COMMENT_MARKERS = (
    "<!--",
    "&lt;!--",
    "&LT;!--",
    "%3C!--",
    "%3c!--",
    "&#60;!--",
    "&#x3C;!--",
    "&#x3c;!--",
    "\uff1c!--",
)


def _encoded_comment_positions(raw: str) -> list[int]:
    """Start indexes of literal and encoded comment openers. One pass per marker."""
    positions: list[int] = []
    for marker in _ENCODED_COMMENT_MARKERS:
        idx = raw.find(marker)
        while idx >= 0:
            positions.append(idx)
            idx = raw.find(marker, idx + len(marker))
    positions.sort()
    return positions


def _closest_offset(positions: list[int], target: int, limit: int) -> int:
    if not positions:
        return min(max(target, 0), limit)
    slot = bisect.bisect_left(positions, target)
    choices = []
    if slot < len(positions):
        choices.append(positions[slot])
    if slot > 0:
        choices.append(positions[slot - 1])
    return min(choices, key=lambda item: abs(item - target))


def _comment_batch_findings(
    bodies: list[tuple[int, str, bool]],
) -> tuple[list[tuple[str, int, str, int, bool]], list[tuple[int, str, str, str, int, bool]], bool]:
    """Scan many comment bodies in one pass.

    A private-use separator stops a phrase from forming across two comments.
    Each returned offset is relative to that comment body. The bool is true
    when a nested walk stopped at the depth cap or the character budget.
    """
    parts: list[str] = []
    spans: list[tuple[int, int, int, bool]] = []
    cursor = 0
    prepared_by_body: dict[str, tuple[str, bool]] = {}
    capped = False
    for source_offset, body, conceal in bodies:
        scanned = prepared_by_body.get(body)
        if scanned is None:
            scanned = _comment_scan_text(body)
            prepared_by_body[body] = scanned
        text, body_capped = scanned
        if body_capped:
            capped = True
        scanned = text
        if parts:
            parts.append(_COMMENT_BATCH_SEP)
            cursor += 1
        start = cursor
        parts.append(scanned)
        cursor += len(scanned)
        spans.append((start, cursor, source_offset, conceal))
    if not parts:
        return [], [], capped
    batch = "".join(parts)
    starts = [span[0] for span in spans]

    def locate(offset: int) -> tuple[int, int, bool] | None:
        slot = bisect.bisect_right(starts, offset) - 1
        if slot < 0:
            return None
        start, end, source_offset, conceal = spans[slot]
        if offset >= end:
            return None
        return offset - start, source_offset, conceal

    legacy_hits: list[tuple[str, int, str, int, bool]] = []
    poison_hits: list[tuple[int, str, str, str, int, bool]] = []
    for source_offset, body, conceal in bodies:
        for offset, phrase in scan_hidden_unicode(body):
            legacy_hits.append(("hidden_unicode", offset, str(phrase), source_offset, conceal))
        for offset, phrase in scan_null_bytes(body):
            legacy_hits.append(("null_byte", offset, str(phrase), source_offset, conceal))
    for key, hits in _scan_finding_groups(batch, batch).items():
        if key in ("hidden_unicode", "null_byte"):
            continue
        for offset, phrase in hits:
            located = locate(offset)
            if located is None:
                continue
            local_offset, source_offset, conceal = located
            legacy_hits.append((key, local_offset, str(phrase), source_offset, conceal))
    for offset, match, phrase, base in scan_tool_poisoning(batch):
        located = locate(offset)
        if located is None:
            continue
        local_offset, source_offset, conceal = located
        poison_hits.append((local_offset, match, phrase, base, source_offset, conceal))
    return legacy_hits, poison_hits, capped


def _keep_combined_hit(
    kept: dict[tuple[str, str], dict[str, int]],
    surface_seen: dict[tuple[str, str], dict[str, int]],
    scope: str,
    key: str,
    match: str,
) -> bool:
    """Keep the larger set of matches across comment-removed and space-replaced text.

    The first surface records every occurrence. A later surface adds a hit only
    when it has more occurrences of that same normalized match than are already
    kept, so a phrase that survives both readings is not stored twice.
    """
    norm = " ".join(match.split()).casefold()
    slot = (scope, key)
    local = surface_seen.setdefault(slot, {})
    local[norm] = local.get(norm, 0) + 1
    bucket = kept.setdefault(slot, {})
    already = bucket.get(norm, 0)
    if local[norm] <= already:
        return False
    bucket[norm] = local[norm]
    return True


def _scan_finding_groups(
    raw: str, prepared: str, *, heavy: bool = True
) -> dict[str, list[tuple[int, str]]]:
    """Phrase scans always run. Rot, homoglyphs, and mythic scans are once per text.

    Comment spacing does not change letters, so the extra reading skips those.
    """
    return {
        "override_phrases": scan_override_phrases(prepared),
        "leetspeak_phrases": scan_leetspeak(prepared),
        "hidden_unicode": scan_hidden_unicode(raw) if heavy else [],
        "null_byte": scan_null_bytes(raw) if heavy else [],
        "path_traversal": scan_path_traversal(prepared),
        "encoding_evasion_rot": _check_rot_decode(prepared) if heavy else [],
        "reversal_phrases": scan_reversal_phrases(prepared),
        "power_words": scan_power_words(prepared),
        "morse_like": scan_morse_like(prepared) if heavy else [],
        "encoding_blocks": scan_encoding_blocks(prepared),
        "homoglyphs": scan_homoglyphs(prepared) if heavy else [],
        "multilingual_override": scan_multilingual_override(prepared) if heavy else [],
        "semantic_aliases": scan_semantic_aliases(prepared),
        "jailbreak_mythic": scan_jailbreak_mythic(prepared) if heavy else [],
        "hostile_ux": scan_hostile_ux(prepared) if heavy else [],
    }


def _location_record(
    *,
    category: str,
    offset: int,
    match: str,
    segment: str,
    source_offset: int,
    severity: str,
    base_severity: str,
    phrase: str | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "category": category,
        "offset": offset,
        "match": match,
        "segment": segment,
        "source_offset": source_offset,
        "severity": severity,
        "base_severity": base_severity,
    }
    if phrase is not None:
        record["phrase"] = phrase
    return record


def reconcile_severity(result: dict) -> None:
    """Keep the reported severity at least as high as the tier floor."""
    tier = result.get("tier", "clean")
    floor = _TIER_SEVERITY_FLOOR.get(tier, "none")
    current = result.get("severity", "none")
    if not isinstance(current, str):
        current = "none"
    result["severity"] = _max_severity(current, floor)


def _collect_boundary_hits(
    slices: list[tuple[str, list[int], str | None, list[int]]],
) -> tuple[list[tuple[int, str]], list[tuple[int, str]], list[tuple[int, str, str, str]]]:
    """Reuse one sliced form. Forms with no recorded boundaries add nothing."""
    overrides: list[tuple[int, str]] = []
    reversals: list[tuple[int, str]] = []
    poisons: list[tuple[int, str, str, str]] = []
    for spaced, spaced_bounds, gap, gap_bounds in slices:
        if not spaced_bounds and not gap_bounds:
            continue
        extra_override, extra_reversal, extra_poison = _supplemental_visible_hits(
            spaced, spaced_bounds, gap, gap_bounds
        )
        overrides.extend(extra_override)
        reversals.extend(extra_reversal)
        poisons.extend(extra_poison)
    return overrides, reversals, poisons


def classify(text: str) -> dict:
    scp_limits.assert_within_limit(text, what="classify content")
    # One decode of the page, then one comment split. Rot runs on that cleaned
    # visible text. Boundary readings are skipped when the split recorded none.
    decoded = _decode_layers(text)
    raw_comments: list[tuple[int, str, bool]] = []
    if decoded == text:
        removed, spaced, gap, spaced_bounds, gap_bounds, comments = _comment_slice(text)
        visible_raw = removed
    else:
        visible_raw, _raw_spaced, _raw_gap, _raw_sb, _raw_gb, raw_comments = _comment_slice(text)
        removed, spaced, gap, spaced_bounds, gap_bounds, comments = _comment_slice(decoded)
    finished = _finish_visible(removed)

    legacy: dict[str, list[tuple[int, str]]] = {key: [] for key in _FINDING_CATEGORY}
    poison_notes: list[dict[str, object]] = []
    concealed_notes: list[dict[str, object]] = []
    severities: list[str] = []
    kept: dict[tuple[str, str], dict[str, int]] = {}
    reported: set[tuple[str, str, int]] = set()

    def _first_report(category: str, phrase: str, source_offset: int) -> bool:
        key = (category, " ".join(phrase.split()).casefold(), source_offset)
        if key in reported:
            return False
        reported.add(key)
        return True

    pending_comments: list[tuple[int, str, str]] = []
    scheduled_bodies: set[str] = set()
    if decoded == text:
        for start, body, _closed in comments:
            if _comment_body_needs_scan(body):
                scheduled_bodies.add(body)
                pending_comments.append((start, body, "literal"))
    else:
        for start, body, _closed in raw_comments:
            if _comment_body_needs_scan(body):
                scheduled_bodies.add(body)
                pending_comments.append((start, body, "literal"))
        marker_positions = _encoded_comment_positions(text)
        for start, body, closed in comments:
            if not _comment_body_needs_scan(body) or body in scheduled_bodies:
                continue
            scheduled_bodies.add(body)
            kind = "decoded_closed" if closed else "decoded_open"
            pending_comments.append(
                (_closest_offset(marker_positions, start, len(text)), body, kind)
            )

    extra_override, extra_reversal, extra_poison = _collect_boundary_hits(
        [(spaced, spaced_bounds, gap, gap_bounds)]
    )
    scope = "text"
    source_offset = 0
    surface_seen: dict[tuple[str, str], dict[str, int]] = {}
    groups = _scan_finding_groups(visible_raw, finished, heavy=True)
    if extra_override or extra_reversal:
        for key_name, extra in (
            ("override_phrases", extra_override),
            ("reversal_phrases", extra_reversal),
        ):
            already = {" ".join(item[1].split()).casefold() for item in groups[key_name]}
            for hit in extra:
                key = " ".join(hit[1].split()).casefold()
                if key in already:
                    continue
                already.add(key)
                groups[key_name].append(hit)
    for key, hits in groups.items():
        base = _base_severity_for_key(key)
        for offset, phrase in hits:
            match = str(phrase)
            if not _keep_combined_hit(kept, surface_seen, scope, key, match):
                continue
            if not _first_report(key, match, source_offset):
                continue
            legacy[key].append((offset, match))
            severities.append(base)
    poison_hits = list(scan_tool_poisoning(finished))
    if extra_poison:
        poison_hits.extend(extra_poison)
    for offset, match, phrase, base in poison_hits:
        if not _keep_combined_hit(kept, surface_seen, scope, "tool_poisoning", match):
            continue
        if not _first_report("tool_poisoning", phrase, source_offset):
            continue
        note = _location_record(
            category="tool_poisoning",
            offset=offset,
            match=match,
            segment="text",
            source_offset=source_offset,
            severity=base,
            base_severity=base,
            phrase=phrase,
        )
        poison_notes.append(note)
        severities.append(base)

    comment_legacy, comment_poison, comment_capped = _comment_batch_findings(pending_comments)
    comment_seen: dict[tuple[str, str], dict[str, int]] = {}
    for key, offset, match, source_offset, mode in comment_legacy:
        conceal = _conceal_comment_hit(mode, key, _base_severity_for_key(key))
        scope = "html_comment" if conceal else "decoded_comment"
        if not _keep_combined_hit(kept, comment_seen, scope, key, match):
            continue
        if not _first_report(key, match, source_offset):
            continue
        base = _base_severity_for_key(key)
        severity = _severity_for_concealment(base, key) if conceal else base
        legacy[key].append((offset, match))
        severities.append(severity)
        if conceal:
            concealed_notes.append(
                _location_record(
                    category=_FINDING_CATEGORY[key],
                    offset=offset,
                    match=match,
                    segment="html_comment",
                    source_offset=source_offset,
                    severity=severity,
                    base_severity=base,
                )
            )
    for offset, match, phrase, base, source_offset, mode in comment_poison:
        conceal = _conceal_comment_hit(mode, "tool_poisoning", base)
        scope = "html_comment" if conceal else "decoded_comment"
        if not _keep_combined_hit(kept, comment_seen, scope, "tool_poisoning", match):
            continue
        if not _first_report("tool_poisoning", phrase, source_offset):
            continue
        severity = _severity_for_concealment(base, "tool_poisoning") if conceal else base
        note = _location_record(
            category="tool_poisoning",
            offset=offset,
            match=match,
            segment="html_comment" if conceal else "text",
            source_offset=source_offset,
            severity=severity,
            base_severity=base,
            phrase=phrase,
        )
        poison_notes.append(note)
        severities.append(severity)
        if conceal:
            concealed_notes.append(note)

    injection_any = any(legacy[key] for key in _INJECTION_FINDING_KEYS) or any(
        severity in ("high", "critical") for severity in severities
    )
    reversal_any = any(legacy[key] for key in _REVERSAL_FINDING_KEYS) or any(
        severity == "medium" for severity in severities
    )
    hostile_only = bool(legacy["hostile_ux"]) and not injection_any and not reversal_any

    categories: list[str] = []
    if injection_any:
        categories.append("injection")
    for key in _CATEGORY_LOOP:
        if legacy[key]:
            categories.append(_FINDING_CATEGORY[key])
    if reversal_any and not injection_any:
        categories.append("reversal")
    if legacy["reversal_phrases"]:
        categories.append("reversal_phrases")
    if hostile_only:
        categories.append("hostile_ux")
    if poison_notes:
        categories.append("tool_poisoning")
    if concealed_notes:
        categories.append("html_comment")

    if comment_capped:
        injection_any = True
        severities.append("high")
    if injection_any:
        tier = "injection"
        risk_score = 1.0
    elif reversal_any:
        tier = "reversal"
        risk_score = 0.7
    elif legacy["hostile_ux"]:
        tier = "hostile_ux"
        risk_score = 0.0
    else:
        tier = "clean"
        risk_score = 0.0

    severity = "none"
    for item in severities:
        severity = _max_severity(severity, item)

    findings = {
        "override_phrases": legacy["override_phrases"],
        "leetspeak_phrases": legacy["leetspeak_phrases"],
        "hidden_unicode": legacy["hidden_unicode"],
        "null_byte": legacy["null_byte"],
        "path_traversal": legacy["path_traversal"],
        "encoding_evasion_rot": legacy["encoding_evasion_rot"],
        "reversal_phrases": legacy["reversal_phrases"],
        "power_words": legacy["power_words"],
        "morse_like": legacy["morse_like"],
        "encoding_blocks": legacy["encoding_blocks"],
        "homoglyphs": legacy["homoglyphs"],
        "multilingual_override": legacy["multilingual_override"],
        "semantic_aliases": legacy["semantic_aliases"],
        "jailbreak_mythic": legacy["jailbreak_mythic"],
        "hostile_ux": legacy["hostile_ux"],
        "tool_poisoning": poison_notes,
        "html_comment": concealed_notes,
        "comment_scan_cap": [_CAP_FINDING] if comment_capped else [],
    }
    if comment_capped:
        categories.append("comment_scan_cap")
    result = {
        "tier": tier,
        "findings": findings,
        "risk_score": risk_score,
        "categories": categories,
        "severity": severity,
    }
    reconcile_severity(result)
    return result
