# PURPOSE: OWASP LLM06 mitigation - redact credentials and PII.
# Extracted from portfolio-harness for standalone SCP package.

import re

REDACT_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']+["\']?', re.IGNORECASE), r'\1=[REDACTED]'),
    (re.compile(r'(?i)\b(api_key|apikey|secret)\b\s*[:=]\s*["\']?[^\s"\']+["\']?', re.IGNORECASE), r'\1=[REDACTED]'),
    (re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), "[EMAIL_REDACTED]"),
    (re.compile(r'(?i)bearer\s+[a-zA-Z0-9._-]{20,}'), "Bearer [REDACTED]"),
    (re.compile(r'(?i)(token|key)\s*[:=]\s*["\']?[a-zA-Z0-9._-]{16,}["\']?', re.IGNORECASE), r'\1=[REDACTED]'),
]


def mask(text: str) -> str:
    result = text
    for pattern, replacement in REDACT_PATTERNS:
        result = pattern.sub(replacement, result)
    return result
