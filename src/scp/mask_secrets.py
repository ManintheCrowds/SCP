# PURPOSE: OWASP LLM06 mitigation - redact credentials and PII.
# Extracted from portfolio-harness for standalone SCP package.

from __future__ import annotations

import re
import sys
from pathlib import Path

from . import secret_surface

# RFC-ish bounds (avoid catastrophic backtracking on long almost-email strings).
_EMAIL_LOCAL_MAX = 64
_EMAIL_DOMAIN_MAX = 253


def _is_email_local_char(c: str) -> bool:
    o = ord(c)
    if c.isalnum():
        return True
    return c in "._%+-"


def _is_domain_label_char(c: str) -> bool:
    return c.isalnum() or c == "-"


def _try_email_span_at(text: str, at: int) -> tuple[int, int] | None:
    """If text[at] is '@', return (start, end_exclusive) for a bounded email-like span, else None."""
    if at < 0 or at >= len(text) or text[at] != "@":
        return None
    lo = max(0, at - _EMAIL_LOCAL_MAX)
    start = at
    while start > lo and _is_email_local_char(text[start - 1]):
        start -= 1
    if start == at:
        return None
    end = at + 1
    hi = min(len(text), at + 1 + _EMAIL_DOMAIN_MAX)
    while end < hi:
        c = text[end]
        if c == ".":
            if end + 1 >= len(text) or not _is_domain_label_char(text[end + 1]):
                break
            end += 1
            continue
        if _is_domain_label_char(c):
            end += 1
            continue
        break
    if end <= at + 1:
        return None
    domain = text[at + 1 : end]
    if "." not in domain:
        return None
    labels = domain.split(".")
    if not labels or any(not lbl for lbl in labels):
        return None
    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return None
    return (start, end)


def _mask_emails_linear(text: str) -> str:
    if "@" not in text:
        return text
    out: list[str] = []
    last = 0
    i = 0
    while i < len(text):
        if text[i] != "@":
            i += 1
            continue
        span = _try_email_span_at(text, i)
        if span is None:
            i += 1
            continue
        s, e = span
        out.append(text[last:s])
        out.append("[EMAIL_REDACTED]")
        last = e
        i = e
    out.append(text[last:])
    return "".join(out)


REDACT_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']+["\']?', re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r'(?i)\b(api_key|apikey|secret)\b\s*[:=]\s*["\']?[^\s"\']+["\']?', re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(?i)bearer\s+[a-zA-Z0-9._-]{20,}"), "Bearer [REDACTED]"),
    (re.compile(r'(?i)(token|key)\s*[:=]\s*["\']?[a-zA-Z0-9._-]{16,}["\']?', re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(?i)AWS_ACCESS_KEY_ID\s*=\s*\S+"), "AWS_ACCESS_KEY_ID=[REDACTED]"),
    (re.compile(r"(?i)AWS_SECRET_ACCESS_KEY\s*=\s*\S+"), "AWS_SECRET_ACCESS_KEY=[REDACTED]"),
    (re.compile(r"postgres://[^\s\"']+"), "postgres://[REDACTED]"),
    (
        re.compile(r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----"),
        "-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----",
    ),
    (re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"), "sk-[REDACTED]"),
    (re.compile(r"\bSSN:\s*\d{3}-\d{2}-\d{4}\b"), "SSN: [REDACTED]"),
]


def _mask_plain(text: str) -> str:
    result = text
    for pattern, replacement in REDACT_PATTERNS:
        result = pattern.sub(replacement, result)
    return _mask_emails_linear(result)


def _redaction_marker(piece: str) -> bool:
    return "[REDACTED]" in piece or "[EMAIL_REDACTED]" in piece


def credential_spans(text: str) -> list[tuple[int, int, str]]:
    """Secret spans. Email addresses are not credentials."""
    found: list[tuple[int, int, str]] = []
    covered: list[tuple[int, int]] = []
    for pattern, replacement in REDACT_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.start(), match.end()
            if any(start < right and end > left for left, right in covered):
                continue
            if _redaction_marker(match.group(0)):
                continue
            if isinstance(replacement, str):
                token = match.expand(replacement)
            else:
                token = replacement(match)
            found.append((start, end, token))
            covered.append((start, end))
    return found


def _email_spans(text: str) -> list[tuple[int, int, str]]:
    if "@" not in text:
        return []
    spans: list[tuple[int, int, str]] = []
    index = 0
    while True:
        at = text.find("@", index)
        if at < 0:
            return spans
        span = _try_email_span_at(text, at)
        if span is None:
            index = at + 1
            continue
        start, end = span
        spans.append((start, end, "[EMAIL_REDACTED]"))
        index = end


def _merge_spans(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    ordered = sorted(spans, key=lambda item: (item[0], item[1]))
    merged: list[tuple[int, int, str]] = []
    for start, end, token in ordered:
        if end <= start:
            continue
        if merged and start < merged[-1][1]:
            prev_start, prev_end, prev_token = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end), prev_token)
            continue
        merged.append((start, end, token))
    return merged


def _apply_spans(text: str, spans: list[tuple[int, int, str]]) -> str:
    if not spans:
        return text
    pieces: list[str] = []
    cursor = 0
    for start, end, token in _merge_spans(spans):
        if start < cursor:
            continue
        pieces.append(text[cursor:start])
        pieces.append(token)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _spans_on_view(view: str) -> list[tuple[int, int, str]]:
    return [*credential_spans(view), *_email_spans(view)]


def _mask_views(text: str, unjoined: str, joined: str) -> str:
    spans = secret_surface.map_spans(text, _spans_on_view(unjoined), joined=False)
    if joined != unjoined:
        spans.extend(secret_surface.map_spans(text, _spans_on_view(joined), joined=True))
    if not spans:
        return text
    return _apply_spans(text, spans)


class EgressMaskError(ValueError):
    """Raised when egress cannot prove the text is free of secrets."""

    def __init__(self, remaining: list[str]) -> None:
        self.remaining = remaining
        super().__init__("egress mask fail-closed")


def mask(text: str) -> str:
    """Detect on the shared unjoined and joined surfaces. Fail closed on budget."""
    try:
        unjoined, joined = secret_surface.detection_views(text)
    except secret_surface.NormalizationBudgetExceeded:
        return "[REDACTED]"
    if unjoined == text and joined == text:
        return _mask_plain(text)
    try:
        return _mask_views(text, unjoined, joined)
    except secret_surface.NormalizationBudgetExceeded:
        return "[REDACTED]"


def has_secrets(text: str) -> bool:
    """True when a credential is visible on the unjoined or the joined surface.

    An exhausted normalization budget fails closed. Email addresses alone do
    not count: mask() still redacts them, and the benign ceiling tracks
    credentials.
    """
    try:
        unjoined, joined = secret_surface.detection_views(text)
    except secret_surface.NormalizationBudgetExceeded:
        return True
    if credential_spans(unjoined):
        return True
    return joined != unjoined and bool(credential_spans(joined))


def prepare_outbound(text: str) -> str:
    """Mask, then rescan both surfaces. Any failure raises and the CLI writes nothing."""
    try:
        secret_surface.detection_views(text)
    except secret_surface.NormalizationBudgetExceeded as exc:
        raise EgressMaskError(["normalization-budget"]) from exc
    masked = mask(text)
    if has_secrets(masked):
        raise EgressMaskError(["residual"])
    return masked


def _read_text(target: str) -> str:
    if target == "-":
        return sys.stdin.buffer.read().decode("utf-8")
    return Path(target).read_text(encoding="utf-8")


def _cmd_check(paths: list[str]) -> int:
    if not paths:
        print("usage: python -m scp.mask_secrets --check <file> [file...]", file=sys.stderr)
        return 2
    failed = False
    for raw in paths:
        try:
            text = _read_text(raw)
        except (OSError, UnicodeDecodeError):
            print(f"unreadable {raw}", file=sys.stderr)
            return 1
        if has_secrets(text):
            print(f"secret-like text in {raw}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


def _cmd_egress(paths: list[str]) -> int:
    if len(paths) != 1:
        print("usage: python -m scp.mask_secrets --egress-prepare -", file=sys.stderr)
        return 2
    try:
        text = _read_text(paths[0])
        masked = prepare_outbound(text)
    except (OSError, UnicodeDecodeError, EgressMaskError):
        print("egress-prepare fail-closed", file=sys.stderr)
        return 1
    sys.stdout.write(masked)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: python -m scp.mask_secrets --check|--egress-prepare ...", file=sys.stderr)
        return 2
    command, rest = args[0], args[1:]
    if command == "--check":
        return _cmd_check(rest)
    if command == "--egress-prepare":
        return _cmd_egress(rest)
    print("usage: python -m scp.mask_secrets --check|--egress-prepare ...", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
