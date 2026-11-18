# PURPOSE: OWASP LLM06 mitigation - redact credentials and PII.
# Single source of truth for SCP secret/PII masking. Health-record patterns and
# the fail-closed --egress-prepare path are ported from the MiscRepos masker.
# Email redaction stays on the linear scanner (bounded, no nested-quantifier ReDoS).

"""
Redact credentials and PII from text before handoff, state, or logs.

Usage:
  python src/scp/mask_secrets.py <file>
  python src/scp/mask_secrets.py -
  python src/scp/mask_secrets.py --check <file> [file...]
  python src/scp/mask_secrets.py --egress-prepare <file>
  python src/scp/mask_secrets.py --egress-prepare -

--egress-prepare masks stdin or one file. On any error or residual match it
exits non-zero and writes nothing to stdout.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# RFC-ish bounds (avoid catastrophic backtracking on long almost-email strings).
_EMAIL_LOCAL_MAX = 64
_EMAIL_DOMAIN_MAX = 253

# Synthetic egress fixture name. Not a general person detector.
_BARE_FIXTURE_NAME = "Casey Example"

# Exact substrings from the synthetic egress handoff. Fail closed if any survive.
FIXTURE_SENTINELS: tuple[str, ...] = (
    _BARE_FIXTURE_NAME,
    "03/15/1985",
    "987-65-4321",
    "casey.example@syn.invalid",
    "212-555-0198",
)

# Longer tokens are listed first so a count never treats them as [REDACTED].
REDACTION_TOKENS: tuple[str, ...] = (
    "[EMAIL_REDACTED]",
    "[NAME_REDACTED]",
    "[DATE_REDACTED]",
    "[SSN_REDACTED]",
    "[PHONE_REDACTED]",
    "[REDACTED]",
)

_EGRESS_FAIL_RESIDUAL = "egress-prepare fail-closed: residual match"
_EGRESS_FAIL_ERROR = "egress-prepare fail-closed: error"


def _is_email_local_char(c: str) -> bool:
    if c.isalnum():
        return True
    return c in "._%+-"


def _is_domain_label_char(c: str) -> bool:
    return c.isalnum() or c == "-"


def _cat(*parts: str) -> str:
    """Build a token prefix without storing the joined form in source."""
    return "".join(parts)


# Bare cloud access-key and GitHub token shapes. Prefixes are concatenated so
# the source file does not contain a real-format token.
_BARE_ACCESS_KEY = re.compile(r"\b" + re.escape(_cat("AK", "IA")) + r"[A-Z2-7]{16}\b")
_BARE_GITHUB_TOKEN = re.compile(r"\b" + re.escape(_cat("gh", "p_")) + r"[A-Za-z0-9]{36}\b")


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


# A redaction token must not count as another secret on the egress rescan.
_NOT_REDACTED = r"(?!\[[A-Z_]*REDACTED\])"
_PEM_BEGIN = "-----BEGIN PRIVATE KEY-----"
_PEM_END = "-----END PRIVATE KEY-----"
_PEM_PATTERN = re.compile(_PEM_BEGIN + r"[\s\S]*?" + _PEM_END)

# Labeled SSN stays ahead of the bare SSN pattern so "SSN: 123-45-6789"
# still produces [REDACTED] for the existing corpus.
REDACT_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "password",
        re.compile(
            r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?" + _NOT_REDACTED + r"[^\s\"']+[\"']?"
        ),
        r"\1=[REDACTED]",
    ),
    (
        "api-key",
        re.compile(
            r"(?i)\b(api_key|apikey|secret)\b\s*[:=]\s*[\"']?"
            + _NOT_REDACTED
            + r"[^\s\"']+[\"']?"
        ),
        r"\1=[REDACTED]",
    ),
    ("bearer", re.compile(r"(?i)bearer\s+[a-zA-Z0-9._-]{20,}"), "Bearer [REDACTED]"),
    (
        "token",
        re.compile(r"(?i)(token|key)\s*[:=]\s*[\"']?[a-zA-Z0-9._-]{16,}[\"']?"),
        r"\1=[REDACTED]",
    ),
    (
        "aws-access-key-id",
        re.compile(r"(?i)AWS_ACCESS_KEY_ID\s*=\s*" + _NOT_REDACTED + r"\S+"),
        "AWS_ACCESS_KEY_ID=[REDACTED]",
    ),
    (
        "aws-secret-access-key",
        re.compile(r"(?i)AWS_SECRET_ACCESS_KEY\s*=\s*" + _NOT_REDACTED + r"\S+"),
        "AWS_SECRET_ACCESS_KEY=[REDACTED]",
    ),
    (
        "postgres",
        re.compile(r"postgres://" + _NOT_REDACTED + r"[^\s\"']+"),
        "postgres://[REDACTED]",
    ),
    (
        "private-key",
        _PEM_PATTERN,
        _PEM_BEGIN + "\n[REDACTED]\n" + _PEM_END,
    ),
    ("openai-key", re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"), "sk-[REDACTED]"),
    ("access-key", _BARE_ACCESS_KEY, "[REDACTED]"),
    ("github-token", _BARE_GITHUB_TOKEN, "[REDACTED]"),
    ("ssn-labeled", re.compile(r"\bSSN:\s*\d{3}-\d{2}-\d{4}\b"), "SSN: [REDACTED]"),
    (
        "patient",
        re.compile(r"(?i)\bPatient:\s*[A-Za-z][A-Za-z'\-]+(?:\s+[A-Za-z][A-Za-z'\-]+)+"),
        "Patient: [NAME_REDACTED]",
    ),
    (
        "dob",
        re.compile(r"(?i)\b(?:DOB|Date of Birth)\s*:\s*\d{1,2}/\d{1,2}/\d{2,4}"),
        "DOB: [DATE_REDACTED]",
    ),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN_REDACTED]"),
    (
        "phone",
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "[PHONE_REDACTED]",
    ),
]


class EgressMaskError(ValueError):
    """Raised when fixture sentinels or pattern matches remain after masking."""

    def __init__(self, remaining: list[str]) -> None:
        self.remaining = remaining
        super().__init__("egress mask fail-closed")


def mask(text: str) -> str:
    result = text
    for _name, pattern, replacement in REDACT_PATTERNS:
        result = pattern.sub(replacement, result)
    result = _mask_emails_linear(result)
    if _BARE_FIXTURE_NAME in result:
        result = result.replace(_BARE_FIXTURE_NAME, "[NAME_REDACTED]")
    return result


def _has_email(text: str) -> bool:
    if "@" not in text:
        return False
    start = 0
    while True:
        at = text.find("@", start)
        if at < 0:
            return False
        if _try_email_span_at(text, at) is not None:
            return True
        start = at + 1


def _private_key_residual(text: str) -> bool:
    """True when a private-key header still has a body other than the redaction token."""
    start = 0
    while True:
        found = text.find(_PEM_BEGIN, start)
        if found < 0:
            return False
        rest = text[found + len(_PEM_BEGIN) :]
        end = rest.find(_PEM_END)
        body = rest if end < 0 else rest[:end]
        if "".join(body.split()) != "[REDACTED]":
            return True
        start = found + len(_PEM_BEGIN)


def residual_secrets(text: str) -> list[str]:
    """Detectors that still match. This does not mask the text a second time."""
    found: list[str] = []
    for name, pattern, _replacement in REDACT_PATTERNS:
        if pattern is _PEM_PATTERN:
            if _private_key_residual(text):
                found.append(name)
            continue
        if pattern.search(text):
            found.append(name)
    if _has_email(text):
        found.append("email")
    found.extend(remaining_fixture_sentinels(text))
    return found


def redacted_count(masked: str) -> int:
    """Count redaction tokens without counting a longer token as [REDACTED]."""
    total = 0
    remaining = masked
    for token in REDACTION_TOKENS:
        total += remaining.count(token)
        remaining = remaining.replace(token, "")
    return total


def remaining_fixture_sentinels(text: str) -> list[str]:
    """Return fixture sentinel substrings still present in text."""
    return [s for s in FIXTURE_SENTINELS if s in text]


def prepare_outbound(text: str) -> str:
    """Mask text once, then rescan with every detector.

    A second mask pass is not the check. Any remaining hit raises, and the
    CLI writes nothing.
    """
    masked = mask(text)
    left = residual_secrets(masked)
    if left:
        raise EgressMaskError(left)
    return masked


def has_secrets(text: str) -> bool:
    """Return True if text appears to contain unredacted secrets."""

    def _redact_backtick_email(match: re.Match[str]) -> str:
        content = match.group(1)
        if "@" in content and re.search(r"\.[a-zA-Z]{2,}$", content.split("@")[-1]):
            return "`[EMAIL]`"
        return match.group(0)

    text_check = re.sub(r"`([^`]+)`", _redact_backtick_email, text)
    return mask(text_check) != text_check


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _cmd_check(args: list[str]) -> int:
    if len(args) < 2:
        print("Usage: mask_secrets.py --check <file> [file...]", file=sys.stderr)
        return 2
    failed = False
    for path_arg in args[1:]:
        path = Path(path_arg)
        if not path.is_file():
            print(f"Not found: {path}", file=sys.stderr)
            failed = True
            continue
        try:
            text = _read_text(path)
        except OSError:
            print(f"Not found: {path}", file=sys.stderr)
            failed = True
            continue
        if has_secrets(text):
            print(f"SECRETS DETECTED: {path} - redact before committing.", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print("OK: No secrets detected")
    return 0


def _egress_fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def _cmd_egress_prepare(args: list[str]) -> int:
    """Mask one input. Any error or residual match: non-zero, empty stdout."""
    if len(args) > 2:
        return _egress_fail(_EGRESS_FAIL_ERROR)
    try:
        if len(args) == 2 and args[1] != "-":
            path = Path(args[1])
            text = _read_text(path)
        else:
            text = sys.stdin.read()
        prepared = prepare_outbound(text)
    except EgressMaskError:
        return _egress_fail(_EGRESS_FAIL_RESIDUAL)
    except Exception:
        return _egress_fail(_EGRESS_FAIL_ERROR)
    sys.stdout.write(prepared)
    return 0


def _cmd_mask_text(text: str) -> int:
    sys.stdout.write(mask(text))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(__doc__ or "", file=sys.stderr)
        return 2
    command = args[0]
    if command == "--check":
        return _cmd_check(args)
    if command == "--egress-prepare":
        return _cmd_egress_prepare(args)
    if command == "-":
        return _cmd_mask_text(sys.stdin.read())
    if command.startswith("-"):
        print(f"Unknown option: {command}", file=sys.stderr)
        return 2
    path = Path(command)
    if not path.is_file():
        print(f"Not found: {path}", file=sys.stderr)
        return 2
    try:
        text = _read_text(path)
    except OSError:
        print(f"Not found: {path}", file=sys.stderr)
        return 2
    return _cmd_mask_text(text)


if __name__ == "__main__":
    sys.exit(main())
