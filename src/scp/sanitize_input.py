# PURPOSE: OWASP LLM01 mitigation - scan for prompt injection and hidden Unicode.
# DEPENDENCIES: Python 3.8+, no external packages
# Extracted from portfolio-harness for standalone SCP package.

"""
Scan text for prompt-injection patterns and hidden Unicode.
"""

import json
import re
import sys
from pathlib import Path

OVERRIDE_PHRASES = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"never\s+reveal\s+(this|that|the)",
    r"do\s+not\s+tell\s+(the\s+)?user",
    r"forget\s+(all\s+)?(previous|prior)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior)",
    r"you\s+are\s+now\s+in\s+(developer|debug)\s+mode",
    r"override\s+(system\s+)?(prompt|instructions)",
    r"append\s+(the\s+)?contents?\s+of\s+\.env",
    r"output\s+(the\s+)?(full\s+)?(system\s+)?prompt",
]

LEETSPEAK_PHRASES = [
    r"1n57ruc75", r"0u7pu7", r"5y573m", r"pr0mp7", r"1nc1ud1ng", r"5h1f7", r"r3v34l", r"0wn",
]

HIDDEN_UNICODE = [0x200B, 0x200C, 0x200D, 0x202E, 0x2060, 0xFEFF]

REVERSAL_PHRASES = [
    r"developer\s+mode", r"debug\s+mode", r"ignore\s+safety", r"pretend\s+you\s+are\s+DAN",
    r"user\s+is\s+always\s+right", r"override\s+your\s+previous\s+response", r"no\s+restrictions",
    r"safety\s+guidelines\s+do\s+not\s+apply", r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
    r"comply\s+with\s+their\s+last\s+message",
]

POWER_WORDS_DEFAULT = [
    r"authorized\s+override", r"official\s+directive", r"emergency\s+mode", r"by\s+order\s+of",
    r"override\s+approved", r"system\s+update", r"administrator\s+override", r"root\s+access\s+granted",
]

PATH_TRAVERSAL_PATTERNS = [
    r"(?:\.\./)+", r"(?:\.\.\\)+", r"/etc/(?:cron\.d|passwd|shadow)\b",
]

MORSE_PATTERN = re.compile(r"[.-]{3,}")
ENCODING_BASE64 = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
ENCODING_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")

_SCRIPT_LATIN = range(0x0041, 0x007B)
_SCRIPT_LATIN_EXT = range(0x00C0, 0x0250)
_SCRIPT_CYRILLIC = range(0x0400, 0x0500)
_SCRIPT_GREEK = range(0x0370, 0x0400)

_THREAT_REGISTRY: dict | None = None


def _load_threat_registry() -> dict | None:
    global _THREAT_REGISTRY
    if _THREAT_REGISTRY is not None:
        return _THREAT_REGISTRY
    try:
        _dir = Path(__file__).resolve().parent
        p = _dir / "scp_threat_registry.json"
        if p.exists():
            with open(p, encoding="utf-8") as f:
                _THREAT_REGISTRY = json.load(f)
        else:
            _THREAT_REGISTRY = {}
    except (json.JSONDecodeError, OSError):
        _THREAT_REGISTRY = {}
    return _THREAT_REGISTRY


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
    return [(m.start(1), m.end(1)) for m in re.finditer(r"```[^\n]*\n([\s\S]*?)```", text)]


def _inline_code_spans(text: str) -> list[tuple[int, int]]:
    return [(m.start(1), m.end(1)) for m in re.finditer(r"`([^`]+)`", text)]


def _quoted_string_spans(text: str) -> list[tuple[int, int]]:
    return [(m.start(1), m.end(1)) for m in re.finditer(r'"([^"]*)"', text)]


def _inside_span(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(s <= pos < e for s, e in spans)


def scan_path_traversal(text: str) -> list[tuple[int, str]]:
    findings = []
    exclude = _markdown_link_url_spans(text) + _code_block_spans(text) + _inline_code_spans(text) + _quoted_string_spans(text)
    for pattern in PATH_TRAVERSAL_PATTERNS:
        for m in re.finditer(pattern, text):
            if not _inside_span(m.start(), exclude):
                findings.append((m.start(), m.group(0)))
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


def scan_encoding_blocks(text: str) -> list[tuple[int, str]]:
    findings = []
    for pat in (ENCODING_BASE64, ENCODING_HEX):
        for m in pat.finditer(text):
            matched = m.group(0)
            if pat == ENCODING_BASE64 and (_looks_like_path(matched) or _looks_like_identifier_or_constant(matched)):
                continue
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


def scan_jailbreak_mythic(text: str) -> list[tuple[int, str]]:
    findings = []
    reg = _load_threat_registry()
    if not reg:
        return findings
    for key in ("jailbreak_nicknames", "mythic_framing", "bitcoin_inscription_override"):
        for phrase in reg.get(key, []):
            for m in re.finditer(r"\b" + re.escape(phrase) + r"\b", text, re.IGNORECASE):
                findings.append((m.start(), m.group(0)))
    return findings


def classify(text: str) -> dict:
    override_findings = scan_override_phrases(text)
    leetspeak_findings = scan_leetspeak(text)
    unicode_findings = scan_hidden_unicode(text)
    path_traversal_findings = scan_path_traversal(text)
    reversal_findings = scan_reversal_phrases(text)
    power_findings = scan_power_words(text)
    morse_findings = scan_morse_like(text)
    encoding_findings = scan_encoding_blocks(text)
    homoglyph_findings = scan_homoglyphs(text)
    multi_findings = scan_multilingual_override(text)
    jailbreak_findings = scan_jailbreak_mythic(text)

    injection_any = override_findings or leetspeak_findings or unicode_findings or path_traversal_findings
    reversal_any = (
        reversal_findings or power_findings or morse_findings or encoding_findings
        or homoglyph_findings or multi_findings or jailbreak_findings
    )

    categories = []
    if injection_any:
        categories.append("injection")
    for name, f in [
        ("override_phrases", override_findings), ("leetspeak", leetspeak_findings),
        ("hidden_unicode", unicode_findings), ("path_traversal", path_traversal_findings),
        ("power_words", power_findings), ("morse_like", morse_findings),
        ("encoding_blocks", encoding_findings), ("homoglyphs", homoglyph_findings),
        ("multilingual_override", multi_findings), ("jailbreak_mythic", jailbreak_findings),
    ]:
        if f:
            categories.append(name)
    if reversal_any and not injection_any:
        categories.append("reversal")
    if reversal_findings:
        categories.append("reversal_phrases")

    tier = "injection" if injection_any else ("reversal" if reversal_any else "clean")
    risk_score = 1.0 if injection_any else (0.7 if reversal_any else 0.0)

    findings = {
        "override_phrases": [(p, str(ph)) for p, ph in override_findings],
        "leetspeak_phrases": [(p, str(ph)) for p, ph in leetspeak_findings],
        "hidden_unicode": [(p, str(cp)) for p, cp in unicode_findings],
        "path_traversal": [(p, str(ph)) for p, ph in path_traversal_findings],
        "reversal_phrases": [(p, str(ph)) for p, ph in reversal_findings],
        "power_words": [(p, str(ph)) for p, ph in power_findings],
        "morse_like": [(p, str(ph)) for p, ph in morse_findings],
        "encoding_blocks": [(p, str(ph)) for p, ph in encoding_findings],
        "homoglyphs": [(p, str(ph)) for p, ph in homoglyph_findings],
        "multilingual_override": [(p, str(ph)) for p, ph in multi_findings],
        "jailbreak_mythic": [(p, str(ph)) for p, ph in jailbreak_findings],
    }

    return {"tier": tier, "findings": findings, "risk_score": risk_score, "categories": categories}
