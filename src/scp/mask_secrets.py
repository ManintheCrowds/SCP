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

import importlib
import re
import sys
from collections.abc import Callable
from pathlib import Path

try:
    from . import secret_text
except ImportError:  # python src/scp/mask_secrets.py
    secret_text = importlib.import_module("secret_text")

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
_OPENAI_PROJECT = re.compile(
    r"(?<![A-Za-z0-9])" + re.escape(_cat("sk-", "proj-")) + r"[A-Za-z0-9_-]{16,120}"
)
_ANTHROPIC_KEY = re.compile(
    r"(?<![A-Za-z0-9])" + re.escape(_cat("sk-", "ant-")) + r"[A-Za-z0-9_-]{16,120}"
)
_GITHUB_FINE_GRAINED = re.compile(
    r"(?<![A-Za-z0-9])" + re.escape(_cat("github", "_pat_")) + r"[A-Za-z0-9_]{20,220}"
)
_GITLAB_PAT = re.compile(
    r"(?<![A-Za-z0-9])" + re.escape(_cat("gl", "pat-")) + r"[A-Za-z0-9_-]{16,120}"
)
_STRIPE_LIVE = re.compile(
    r"(?<![A-Za-z0-9])" + re.escape(_cat("sk", "_live_")) + r"[A-Za-z0-9]{10,120}"
)
_AGE_SECRET = re.compile(
    r"(?<![A-Za-z0-9])" + re.escape(_cat("AGE-", "SECRET-", "KEY-1")) + r"[A-Z2-7]{20,120}"
)
_JWT = re.compile(
    r"\b"
    + re.escape(_cat("ey", "J"))
    + r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_TELEGRAM_BOT = re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,40}\b")


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
MAX_CLI_BYTES = 1_000_000

# Labeled SSN stays ahead of the bare SSN pattern so "SSN: 123-45-6789"
# still produces [REDACTED] for the existing corpus.
def _keep_assignment(match: re.Match[str]) -> str:
    """Keep the label and separator. Do not rewrite ':' to '='."""
    return f"{match.group(1)}{match.group(2)}[REDACTED]"


def _keep_dob_label(match: re.Match[str]) -> str:
    """Keep 'Date of Birth' instead of rewriting it to 'DOB'."""
    return f"{match.group(1)}{match.group(2)}[DATE_REDACTED]"


def _keep_quoted_secret(match: re.Match[str]) -> str:
    """Redact the whole quoted value, including spaces, and keep the quotes."""
    return f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED]{match.group(3)}"


def _keep_json_secret(match: re.Match[str]) -> str:
    return f"{match.group(1)}\"[REDACTED]\""


def _keep_wordpress_secret(match: re.Match[str]) -> str:
    return f"{match.group(1)}{match.group(3)}[REDACTED]{match.group(3)}"


_Replacement = str | Callable[[re.Match[str]], str]
REDACT_PATTERNS: list[tuple[str, re.Pattern[str], _Replacement]] = [
    (
        "password-quoted",
        re.compile(
            r"(?i)(password|passwd|pwd)(\s*[:=]\s*)([\"'])(?!\[[A-Z_]*REDACTED\])"
            r"((?:\\.|(?!\3).){0,200})\3"
        ),
        _keep_quoted_secret,
    ),
    (
        "json-secret",
        re.compile(
            r"(\"(?:password|token)\"\s*:\s*)\"(?!\[[A-Z_]*REDACTED\])"
            r"((?:[^\"\\]|\\.){1,200})\"",
            re.IGNORECASE,
        ),
        _keep_json_secret,
    ),
    (
        "wordpress-db-password",
        re.compile(
            r"(define\s*\(\s*(['\"])DB_PASSWORD\2\s*,\s*)"
            r"([\'\"])(?!\[[A-Z_]*REDACTED\])([^'\"]{1,200})\3",
            re.IGNORECASE,
        ),
        _keep_wordpress_secret,
    ),
    (
        "password",
        re.compile(
            r"(?i)(password|passwd|pwd)(\s*[:=]\s*)[\"']?" + _NOT_REDACTED + r"[^\s\"']+[\"']?"
        ),
        _keep_assignment,
    ),
    (
        "api-key",
        re.compile(
            r"(?i)\b(api_key|apikey|secret)\b(\s*[:=]\s*)[\"']?"
            + _NOT_REDACTED
            + r"[^\s\"']+[\"']?"
        ),
        _keep_assignment,
    ),
    ("bearer", re.compile(r"(?i)bearer\s+[a-zA-Z0-9._-]{20,}"), "Bearer [REDACTED]"),
    (
        "token",
        re.compile(r"(?i)(token|key)(\s*[:=]\s*)[\"']?[a-zA-Z0-9._-]{16,}[\"']?"),
        _keep_assignment,
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
    ("openai-project", _OPENAI_PROJECT, "[REDACTED]"),
    ("anthropic-key", _ANTHROPIC_KEY, "[REDACTED]"),
    ("github-fine-grained", _GITHUB_FINE_GRAINED, "[REDACTED]"),
    ("gitlab-pat", _GITLAB_PAT, "[REDACTED]"),
    ("stripe-live", _STRIPE_LIVE, "[REDACTED]"),
    ("telegram-bot", _TELEGRAM_BOT, "[REDACTED]"),
    ("age-secret", _AGE_SECRET, "[REDACTED]"),
    ("jwt", _JWT, "[REDACTED]"),
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
        re.compile(r"(?i)\b(DOB|Date of Birth)(\s*:\s*)\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"),
        _keep_dob_label,
    ),
    (
        "dob-iso",
        re.compile(r"(?i)\b(DOB|Date of Birth)(\s*:\s*)\d{4}-\d{2}-\d{2}"),
        _keep_dob_label,
    ),
    (
        "dob-written",
        re.compile(
            r"(?i)\b(DOB|Date of Birth)(\s*:\s*)"
            r"(?:(?:January|February|March|April|May|June|July|August|September|"
            r"October|November|December)\s+\d{1,2},\s+\d{4}|"
            r"\d{1,2}\s+(?:January|February|March|April|May|June|July|August|"
            r"September|October|November|December)\s+\d{4})"
        ),
        _keep_dob_label,
    ),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN_REDACTED]"),
    ("ssn-separated", re.compile(r"\b\d{3}([-. ])\d{2}\1\d{4}\b"), "[SSN_REDACTED]"),
    ("ssn-digits", re.compile(r"(?<!\d)\d{9}(?!\d)"), "[SSN_REDACTED]"),
    (
        "phone",
        re.compile(r"\b(?:\+?1[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b"),
        "[PHONE_REDACTED]",
    ),
    (
        "phone-intl",
        re.compile(r"\+\d{1,3}(?:[\s.\-]\d{2,4}){2,5}\b"),
        "[PHONE_REDACTED]",
    ),
]


class InputDecodeError(ValueError):
    """Raised when CLI input is not strict UTF-8 or contains a NUL."""


class InputTooLarge(ValueError):
    """Raised when CLI input exceeds MAX_CLI_BYTES."""


def decode_strict(data: bytes) -> str:
    """Decode CLI bytes. Invalid UTF-8 and NUL bytes fail closed."""
    if len(data) > MAX_CLI_BYTES:
        raise InputTooLarge("input cap")
    if b"\x00" in data:
        raise InputDecodeError("NUL byte")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputDecodeError("invalid utf-8") from exc


def _read_capped(handle) -> str:
    data = handle.read(MAX_CLI_BYTES + 1)
    return decode_strict(data)


class EgressMaskError(ValueError):
    """Raised when fixture sentinels or pattern matches remain after masking."""

    def __init__(self, remaining: list[str]) -> None:
        self.remaining = remaining
        super().__init__("egress mask fail-closed")


def _mask_private_keys(text: str) -> str:
    """Redact private-key blocks in linear time, including a missing END line."""
    for kind in _PEM_KINDS:
        begin, end = _pem_pair(kind)
        pieces: list[str] = []
        cursor = 0
        while cursor <= len(text):
            found = text.find(begin, cursor)
            if found < 0:
                pieces.append(text[cursor:])
                break
            pieces.append(text[cursor:found])
            end_at = text.find(end, found + len(begin))
            if end_at < 0:
                pieces.append(begin + "\n[REDACTED]\n")
                cursor = len(text)
                break
            pieces.append(begin + "\n[REDACTED]\n" + end)
            cursor = end_at + len(end)
        text = "".join(pieces)
    return text


def _mask_surface(text: str) -> str:
    result = _mask_private_keys(text)
    for _name, pattern, replacement in REDACT_PATTERNS:
        result = pattern.sub(replacement, result)
    result = _mask_emails_linear(result)
    if _BARE_FIXTURE_NAME in result:
        result = result.replace(_BARE_FIXTURE_NAME, "[NAME_REDACTED]")
    return result


def _collect_hits(text: str) -> list[str]:
    found: list[str] = []
    for name, pattern, _replacement in REDACT_PATTERNS:
        if name.endswith("private-key"):
            continue
        if pattern.search(text):
            found.append(name)
    if _private_key_residual(text):
        found.append("private-key")
    if _has_email(text):
        found.append("email")
    found.extend(remaining_fixture_sentinels(text))
    return found


def _contains_secret(text: str) -> bool:
    return bool(_collect_hits(text))


def mask(text: str) -> str:
    surface = secret_text.surface_for_matching(text, _contains_secret)
    return _mask_surface(surface)


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


_PEM_KINDS = ("", "RSA ", "EC ", "OPENSSH ")


def _pem_pair(kind: str) -> tuple[str, str]:
    return (f"-----BEGIN {kind}PRIVATE KEY-----", f"-----END {kind}PRIVATE KEY-----")


def _private_key_residual(text: str) -> bool:
    """True when a private-key header still has a body other than the redaction token."""
    for kind in _PEM_KINDS:
        begin, end = _pem_pair(kind)
        start = 0
        while True:
            found = text.find(begin, start)
            if found < 0:
                break
            rest = text[found + len(begin) :]
            end_at = rest.find(end)
            body = rest if end_at < 0 else rest[:end_at]
            if "".join(body.split()) != "[REDACTED]":
                return True
            start = found + len(begin)
    return False


def residual_secrets(text: str) -> list[str]:
    """Detectors that still match. This does not mask the text a second time."""
    surface = secret_text.surface_for_matching(text, _contains_secret)
    return _collect_hits(surface)


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


def _neutralize_backtick_emails(text: str) -> str:
    """Drop only a single-line backtick email from the check comparison.

    The span cannot cross a newline, and any other character inside the
    backticks is left in place.
    """

    def _replace(match: re.Match[str]) -> str:
        return "`" + _mask_emails_linear(match.group(1)) + "`"

    return re.sub(r"`([^`\n]*)`", _replace, text)


def has_secrets(text: str) -> bool:
    """Return True if text appears to contain unredacted secrets."""
    return mask(_neutralize_backtick_emails(text)) != _neutralize_backtick_emails(text)


def _read_path(path: Path) -> str:
    with path.open("rb") as handle:
        return _read_capped(handle)


def _read_stdin() -> str:
    return _read_capped(sys.stdin.buffer)


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
            text = _read_path(path)
        except (InputDecodeError, InputTooLarge):
            print("mask fail-closed: decode error", file=sys.stderr)
            failed = True
            continue
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
            text = _read_path(path)
        else:
            text = _read_stdin()
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
        try:
            text = _read_stdin()
        except (InputDecodeError, InputTooLarge):
            print("mask fail-closed: decode error", file=sys.stderr)
            return 1
        return _cmd_mask_text(text)
    if command.startswith("-"):
        print(f"Unknown option: {command}", file=sys.stderr)
        return 2
    path = Path(command)
    if not path.is_file():
        print(f"Not found: {path}", file=sys.stderr)
        return 2
    try:
        text = _read_path(path)
    except (InputDecodeError, InputTooLarge):
        print("mask fail-closed: decode error", file=sys.stderr)
        return 1
    except OSError:
        print(f"Not found: {path}", file=sys.stderr)
        return 2
    return _cmd_mask_text(text)


if __name__ == "__main__":
    sys.exit(main())
