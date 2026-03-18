# PURPOSE: Structural anomaly checks for SCP.
# Extracted from portfolio-harness for standalone SCP package.

import re

HIDDEN_UNICODE = {0x200B, 0x200C, 0x200D, 0x202E, 0x2060, 0xFEFF}

DELIMITER_PATTERNS = [
    (re.compile(r"^---\s*$", re.MULTILINE), "horizontal_rule"),
    (re.compile(r"^===\s*$", re.MULTILINE), "horizontal_rule"),
    (re.compile(r"^(?:SYSTEM|ASSISTANT|USER|HUMAN):\s*", re.MULTILINE | re.IGNORECASE), "role_prefix"),
]

NON_ASCII_RATIO_THRESHOLD = 0.3
HIDDEN_RATIO_THRESHOLD = 0.02
CONTROL_RATIO_THRESHOLD = 0.01


def scan_unicode_density(text: str) -> dict:
    if not text:
        return {"ratio_non_ascii": 0.0, "ratio_control": 0.0, "ratio_hidden": 0.0, "anomaly": False}
    n = len(text)
    non_ascii = sum(1 for c in text if ord(c) > 127)
    control = sum(1 for c in text if ord(c) < 32 and ord(c) not in (9, 10, 13))
    hidden = sum(1 for c in text if ord(c) in HIDDEN_UNICODE)
    ratio_non_ascii = non_ascii / n
    ratio_control = control / n
    ratio_hidden = hidden / n
    anomaly = (
        ratio_non_ascii > NON_ASCII_RATIO_THRESHOLD
        or ratio_hidden > HIDDEN_RATIO_THRESHOLD
        or ratio_control > CONTROL_RATIO_THRESHOLD
    )
    return {
        "ratio_non_ascii": round(ratio_non_ascii, 4),
        "ratio_control": round(ratio_control, 4),
        "ratio_hidden": round(ratio_hidden, 4),
        "anomaly": anomaly,
    }


def _get_script(cp: int) -> str:
    if 0x0041 <= cp <= 0x007A or 0x00C0 <= cp <= 0x024F:
        return "Latin"
    if 0x0400 <= cp <= 0x04FF:
        return "Cyrillic"
    if 0x0370 <= cp <= 0x03FF:
        return "Greek"
    return "Other"


def scan_script_mixing(text: str) -> dict:
    mixed_words = []
    scripts_found = set()
    for m in re.finditer(r"\b\w+\b", text):
        word = m.group(0)
        scripts = set()
        for c in word:
            s = _get_script(ord(c))
            if s != "Other":
                scripts.add(s)
                scripts_found.add(s)
        if len(scripts) >= 2:
            mixed_words.append((m.start(), word))
    return {"scripts_found": list(scripts_found), "mixed_words": mixed_words}


def scan_delimiter_injection(text: str) -> list[tuple[int, str, str]]:
    findings = []
    for pattern, kind in DELIMITER_PATTERNS:
        for m in pattern.finditer(text):
            findings.append((m.start(), m.group(0).strip()[:30], kind))
    return findings


def run_all(text: str) -> dict:
    anomalies = []
    risk_boost = 0.0

    density = scan_unicode_density(text)
    if density["anomaly"]:
        anomalies.append({
            "type": "unicode_density",
            "detail": f"non_ascii={density['ratio_non_ascii']}, hidden={density['ratio_hidden']}",
        })
        risk_boost += 0.2

    script_result = scan_script_mixing(text)
    if script_result["mixed_words"]:
        anomalies.append({
            "type": "script_mixing",
            "detail": f"{len(script_result['mixed_words'])} mixed-script words",
            "mixed_words": [w for _, w in script_result["mixed_words"][:5]],
        })
        risk_boost += 0.2

    delim_findings = scan_delimiter_injection(text)
    if delim_findings:
        anomalies.append({
            "type": "delimiter_injection",
            "detail": f"{len(delim_findings)} delimiter/role patterns",
            "examples": [d[1] for d in delim_findings[:3]],
        })
        risk_boost += 0.15

    return {"anomalies": anomalies, "risk_boost": min(risk_boost, 0.5)}
