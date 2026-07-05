# PURPOSE: OWASP LLM01 mitigation - scan for prompt injection and hidden Unicode.
# DEPENDENCIES: Python 3.8+, no external packages
# Extracted from portfolio-harness for standalone SCP package.

"""
Scan text for prompt-injection patterns and hidden Unicode.
"""

import base64
import bisect
import codecs
import html
import json
import re
import sys
import unicodedata
import urllib.parse
from pathlib import Path

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
    r"you\s+are\s+now\s+in\s+(developer|debug)\s+mode",
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
_ALPHA_RUN = re.compile(r'[A-Za-z]{20,}')
_B64_MAX_LAYERS = 3


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
        for shift in range(1, 26):
            if shift == 13:
                continue
            _add(_match_override_phrases(_caesar_decode(text, shift), f'rot{shift}'))

    for m in _ALPHA_RUN.finditer(text):
        run = m.group(0)
        base = m.start()
        for shift in range(1, 26):
            if shift == 13:
                continue
            for item in _match_override_phrases(_caesar_decode(run, shift), f'rot{shift}'):
                keyed = (base + item[0], item[1])
                if keyed not in seen:
                    seen.add(keyed)
                    findings.append(keyed)
    return findings


_B64_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")


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


def _prepare_text_for_scan(text: str) -> str:
    """Normalize unicode, encoding evasion, fragmentation, and short base64 before pattern scans."""
    prepared = _strip_null_bytes(text)
    prepared = _decode_tag_block(prepared)
    prepared = _strip_invisible_unicode(prepared)
    prepared = _strip_excessive_combining(prepared)
    prepared = _normalize_confusable_whitespace(prepared)
    prepared = unicodedata.normalize("NFKC", prepared)
    prepared = _strip_regional_indicators(prepared)
    prepared = _decode_html_entities(prepared)
    prepared = _decode_url_encoding(prepared)
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
ENCODING_BASE64 = re.compile(r"(?=[A-Za-z0-9+/]*[+/=])[A-Za-z0-9+/]{16,}={0,2}")
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


def scan_encoding_blocks(text: str) -> list[tuple[int, str]]:
    findings = []
    for pat in (ENCODING_BASE64, ENCODING_HEX):
        for m in pat.finditer(text):
            matched = m.group(0)
            if pat == ENCODING_BASE64 and (_looks_like_path(matched) or _looks_like_identifier_or_constant(matched)):
                continue
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


def classify(text: str) -> dict:
    scp_limits.assert_within_limit(text, what="classify content")
    scan_text = _prepare_text_for_scan(text)
    override_findings = scan_override_phrases(scan_text)
    leetspeak_findings = scan_leetspeak(scan_text)
    unicode_findings = scan_hidden_unicode(text)
    null_findings = scan_null_bytes(text)
    path_traversal_findings = scan_path_traversal(scan_text)
    reversal_findings = scan_reversal_phrases(scan_text)
    power_findings = scan_power_words(scan_text)
    morse_findings = scan_morse_like(scan_text)
    encoding_findings = scan_encoding_blocks(scan_text)
    homoglyph_findings = scan_homoglyphs(scan_text)
    multi_findings = scan_multilingual_override(scan_text)
    alias_findings = scan_semantic_aliases(scan_text)
    jailbreak_findings = scan_jailbreak_mythic(scan_text)
    hostile_ux_findings = scan_hostile_ux(scan_text)
    rot_findings = _check_rot_decode(scan_text)

    injection_any = (
        override_findings or leetspeak_findings or unicode_findings
        or null_findings or path_traversal_findings or rot_findings
    )
    reversal_any = (
        reversal_findings or power_findings or morse_findings or encoding_findings
        or homoglyph_findings or multi_findings or alias_findings or jailbreak_findings
    )

    categories = []
    if injection_any:
        categories.append("injection")
    for name, f in [
        ("override_phrases", override_findings), ("leetspeak", leetspeak_findings),
        ("hidden_unicode", unicode_findings), ("null_byte", null_findings),
        ("path_traversal", path_traversal_findings),
        ("encoding_evasion_rot", rot_findings),
        ("power_words", power_findings), ("morse_like", morse_findings),
        ("encoding_blocks", encoding_findings), ("homoglyphs", homoglyph_findings),
        ("multilingual_override", multi_findings), ("semantic_aliases", alias_findings),
        ("jailbreak_mythic", jailbreak_findings),
    ]:
        if f:
            categories.append(name)
    if reversal_any and not injection_any:
        categories.append("reversal")
    if reversal_findings:
        categories.append("reversal_phrases")
    if hostile_ux_findings and not injection_any and not reversal_any:
        categories.append("hostile_ux")

    tier = "injection" if injection_any else ("reversal" if reversal_any else ("hostile_ux" if hostile_ux_findings else "clean"))
    risk_score = 1.0 if injection_any else (0.7 if reversal_any else (0.0 if hostile_ux_findings else 0.0))

    findings = {
        "override_phrases": [(p, str(ph)) for p, ph in override_findings],
        "leetspeak_phrases": [(p, str(ph)) for p, ph in leetspeak_findings],
        "hidden_unicode": [(p, str(cp)) for p, cp in unicode_findings],
        "null_byte": [(p, str(ph)) for p, ph in null_findings],
        "path_traversal": [(p, str(ph)) for p, ph in path_traversal_findings],
        "encoding_evasion_rot": [(p, str(ph)) for p, ph in rot_findings],
        "reversal_phrases": [(p, str(ph)) for p, ph in reversal_findings],
        "power_words": [(p, str(ph)) for p, ph in power_findings],
        "morse_like": [(p, str(ph)) for p, ph in morse_findings],
        "encoding_blocks": [(p, str(ph)) for p, ph in encoding_findings],
        "homoglyphs": [(p, str(ph)) for p, ph in homoglyph_findings],
        "multilingual_override": [(p, str(ph)) for p, ph in multi_findings],
        "semantic_aliases": [(p, str(ph)) for p, ph in alias_findings],
        "jailbreak_mythic": [(p, str(ph)) for p, ph in jailbreak_findings],
        "hostile_ux": [(p, str(ph)) for p, ph in hostile_ux_findings],
    }

    return {"tier": tier, "findings": findings, "risk_score": risk_score, "categories": categories}
