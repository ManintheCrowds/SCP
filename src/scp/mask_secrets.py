# PURPOSE: OWASP LLM06 mitigation - redact credentials and PII.
# Extracted from portfolio-harness for standalone SCP package.

from __future__ import annotations

import csv
import heapq
import io
import re
import sys
from pathlib import Path

from . import secret_surface

# RFC-ish bounds (avoid catastrophic backtracking on long almost-email strings).
_EMAIL_LOCAL_MAX = 64
_EMAIL_DOMAIN_MAX = 253

# Above this length mask, has_secrets, egress, and the CLI fail closed.
MAX_SCAN_CHARS = 1_000_000


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


def _cat(*parts: str) -> str:
    """Join a prefix at runtime so the source file never stores it whole."""
    return "".join(parts)


# Unlabeled token shapes. Prefixes are concatenated so this file does not
# contain the joined form. Personal-data rules follow the same list so mask,
# has_secrets, egress, and the CLI all see them.
_BARE_GH_PERSONAL = re.compile(r"\b" + re.escape(_cat("gh", "p_")) + r"[A-Za-z0-9]{36}\b")
_BARE_GH_OAUTH = re.compile(r"\b" + re.escape(_cat("gh", "o_")) + r"[A-Za-z0-9]{36}\b")
_GH_FINE = re.compile(
    r"(?<![A-Za-z0-9])" + re.escape(_cat("github", "_pat_")) + r"[A-Za-z0-9_]{20,220}"
)
_GL_PAT = re.compile(
    r"(?<![A-Za-z0-9])" + re.escape(_cat("gl", "pat-")) + r"[A-Za-z0-9_-]{16,120}"
)
_PROJECT_KEY = re.compile(
    r"(?<![A-Za-z0-9])" + re.escape(_cat("sk-", "proj-")) + r"[A-Za-z0-9_-]{16,120}"
)
_ACCESS_KEY = re.compile(r"\b" + re.escape(_cat("AK", "IA")) + r"[A-Z2-7]{16}\b")
_SLACK_BOT = re.compile(
    r"(?<![A-Za-z0-9])" + re.escape(_cat("xo", "xb-")) + r"[0-9]{6,}(?:-[A-Za-z0-9]{6,}){1,4}"
)
# Three base64url segments. A header that starts with the JWT marker may use
# segments of 10 or more; other headers stay at 16. The signature segment
# allows a 4096-bit RSA signature. Quantifiers stay bounded.
_JWT_MARKER = _cat("ey", "J")
_B64URL = r"[A-Za-z0-9_-]"
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    + re.escape(_JWT_MARKER)
    + _B64URL
    + r"{7,1021}\."
    + _B64URL
    + r"{10,4096}\."
    + _B64URL
    + r"{10,1024}|"
    + _B64URL
    + r"{16,1024}\."
    + _B64URL
    + r"{16,4096}\."
    + _B64URL
    + r"{16,1024})(?![A-Za-z0-9_-])"
)

REDACT_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']+["\']?', re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r'(?i)\b(api_key|apikey|secret)\b\s*[:=]\s*["\']?[^\s"\']+["\']?', re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(?i)bearer\s+[a-zA-Z0-9._-]{20,}"), "Bearer [REDACTED]"),
    (
        re.compile(
            r"(?i)(AWS_SECRET_ACCESS_KEY|SecretAccessKey)"
            r"""(?:\\?["'])?\s*[:=]\s*\\?["']?[A-Za-z0-9/+][A-Za-z0-9/+=]{7,}"""
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"(?i)<(SecretAccessKey)>\s*[A-Za-z0-9/+=]{8,}"),
        r"<\1>[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(aws_secret_access_key)\s*[=\t]\s*[\"']?"
            r"[A-Za-z0-9/+][A-Za-z0-9/+=]{7,}"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(
            r"("
            + re.escape(_cat("AK", "IA"))
            + r"[A-Z0-9]{16})(\s*[\t,]\s*)[\"']?"
            r"[A-Za-z0-9/+][A-Za-z0-9/+=]{7,}"
        ),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r'(?i)(token|key)\s*[:=]\s*["\']?[a-zA-Z0-9._-]{16,}["\']?', re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(?i)AWS_ACCESS_KEY_ID\s*=\s*\S+"), "AWS_ACCESS_KEY_ID=[REDACTED]"),
    (re.compile(r"postgres://[^\s\"']+"), "postgres://[REDACTED]"),
    (re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"), "sk-[REDACTED]"),
    (_PROJECT_KEY, "[REDACTED]"),
    (_BARE_GH_PERSONAL, "[REDACTED]"),
    (_BARE_GH_OAUTH, "[REDACTED]"),
    (_GH_FINE, "[REDACTED]"),
    (_GL_PAT, "[REDACTED]"),
    (_ACCESS_KEY, "[REDACTED]"),
    (_SLACK_BOT, "[REDACTED]"),
    (_JWT, "[REDACTED]"),
    (re.compile(r"\bSSN:\s*\d{3}-\d{2}-\d{4}\b"), "SSN: [REDACTED]"),
    (
        re.compile(r"(?i)\bPatient:\s*[A-Za-z][A-Za-z'\-]+(?:\s+[A-Za-z][A-Za-z'\-]+)+"),
        "Patient: [NAME_REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(DOB|Date of Birth)(\s*:\s*)\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
        ),
        r"\1\2[DATE_REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(DOB|Date of Birth)(\s*:\s*)\d{4}-\d{2}-\d{2}"),
        r"\1\2[DATE_REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(DOB|Date of Birth)(\s*:\s*)"
            r"(?:(?:January|February|March|April|May|June|July|August|September|"
            r"October|November|December)\s+\d{1,2},\s+\d{4}|"
            r"\d{1,2}\s+(?:January|February|March|April|May|June|July|August|"
            r"September|October|November|December)\s+\d{4})"
        ),
        r"\1\2[DATE_REDACTED]",
    ),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN_REDACTED]"),
    (re.compile(r"\b\d{3}([-. ])\d{2}\1\d{4}\b"), "[SSN_REDACTED]"),
    (re.compile(r"(?<![A-Za-z0-9])\d{9}(?![A-Za-z0-9])"), "[SSN_REDACTED]"),
    (
        re.compile(r"\b(?:\+?1[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b"),
        "[PHONE_REDACTED]",
    ),
    (
        re.compile(r"\+\d{1,3}(?:[\s.\-]\d{2,4}){2,5}\b"),
        "[PHONE_REDACTED]",
    ),
]


_AWS_ID_FIELD = re.compile("^" + re.escape(_cat("AK", "IA")) + r"[A-Z0-9]{16}$")
_AWS_SECRET_FIELD = re.compile(r"^[A-Za-z0-9/+][A-Za-z0-9/+=]{19,}$")


def _mask_aws_row(line: str) -> str:
    """Mask a secret field on a row that also holds an access key id.

    Quotes, an extra column, and either field order are all the same row.
    """
    if "\t" in line:
        delimiter = "\t"
    elif "," in line:
        delimiter = ","
    else:
        return line
    try:
        fields = next(csv.reader([line], delimiter=delimiter))
    except csv.Error:
        return line
    if not any(_AWS_ID_FIELD.match(field.strip()) for field in fields):
        return line
    changed = False
    rewritten: list[str] = []
    for field in fields:
        body = field.strip()
        if _AWS_ID_FIELD.match(body):
            rewritten.append(field)
            continue
        if _AWS_SECRET_FIELD.match(body):
            rewritten.append("[REDACTED]")
            changed = True
            continue
        rewritten.append(field)
    if not changed:
        return line
    buffer = io.StringIO()
    csv.writer(buffer, delimiter=delimiter, lineterminator="").writerow(rewritten)
    return buffer.getvalue()


def _aws_line_spans(line: str, offset: int) -> list[tuple[int, int, str]]:
    if "\t" in line:
        delimiter = "\t"
    elif "," in line:
        delimiter = ","
    else:
        return []
    try:
        fields = next(csv.reader([line], delimiter=delimiter))
    except csv.Error:
        return []
    if not any(_AWS_ID_FIELD.match(field.strip()) for field in fields):
        return []
    spans: list[tuple[int, int, str]] = []
    cursor = 0
    for field in fields:
        body = field.strip()
        if _AWS_ID_FIELD.match(body) or not _AWS_SECRET_FIELD.match(body):
            continue
        start = line.find(body, cursor)
        if start < 0:
            continue
        spans.append((offset + start, offset + start + len(body), "[REDACTED]"))
        cursor = start + len(body)
    return spans


def _aws_row_spans(text: str) -> list[tuple[int, int, str]]:
    """Secret fields on CSV or TSV rows, including a normalized view."""
    spans: list[tuple[int, int, str]] = []
    offset = 0
    lines = text.split("\n")
    for index, line in enumerate(lines):
        spans.extend(_aws_line_spans(line, offset))
        offset += len(line)
        if index + 1 < len(lines):
            offset += 1
    return spans


def _mask_plain(text: str) -> str:
    text = "\n".join(_mask_aws_row(line) for line in text.split("\n"))
    pem = _pem_spans(text)
    result = _apply_spans(text, pem) if pem else text
    for pattern, replacement in REDACT_PATTERNS:
        result = pattern.sub(replacement, result)
    return _mask_emails_linear(result)


_MARKERS = (
    "[REDACTED]",
    "[EMAIL_REDACTED]",
    "[NAME_REDACTED]",
    "[DATE_REDACTED]",
    "[SSN_REDACTED]",
    "[PHONE_REDACTED]",
)


def _redaction_marker(piece: str) -> bool:
    return any(marker in piece for marker in _MARKERS)


def _over_cap(text: str) -> bool:
    return len(text) > MAX_SCAN_CHARS


_PEM_BEGIN = "-----BEGIN "
_PEM_KINDS = (
    "ENCRYPTED PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "PRIVATE KEY",
)


# Final byte is m (SGR), K (erase in line), or J (erase in display).
# Anything else, including an unfinished sequence, stays and is refused.
# U+009B (8-bit CSI, for example \x9b31m) is not stripped. It stays a C1
# byte so mask, has_secrets, and egress refuse it.
# The final letter is captured so a second view can keep it: a token's own
# m, K, or J must not be what finishes the sequence.
_CSI = re.compile(r"\x1b\[[0-9;:]*([mKJ])")
_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


# Params that belong to the sequence. Token digits use the same alphabet, so
# the second view removes only the introducer and leaves those characters.
_CSI_OPEN = re.compile(r"\x1b\[")


def _sgr_views(text: str) -> tuple[str, str]:
    """Strip a finished CSI, and also keep a view that retains its parameters.

    The parameter view is what catches a token letter or digit that merely
    completed an unfinished sequence.
    """
    if "\x1b" not in text:
        return text, text
    no_osc = _OSC.sub("", text)
    return _CSI.sub("", no_osc), _CSI_OPEN.sub("", no_osc)


def _pem_spans(text: str) -> list[tuple[int, int, str]]:
    """Private-key blocks, including a missing END line. One forward scan."""
    spans: list[tuple[int, int, str]] = []
    cursor = 0
    begin = _PEM_BEGIN
    while True:
        at = text.find(begin, cursor)
        if at < 0:
            return spans
        offset = at + len(begin)
        kind = None
        for candidate in _PEM_KINDS:
            if text.startswith(candidate + "-----", offset):
                kind = candidate
                break
        if kind is None:
            cursor = at + len(begin)
            continue
        header_end = at + len(begin) + len(kind) + 5
        end_marker = "-----END " + kind + "-----"
        end_at = text.find(end_marker, header_end)
        if end_at < 0:
            spans.append((at, len(text), "[REDACTED]"))
            return spans
        spans.append((at, end_at + len(end_marker), "[REDACTED]"))
        cursor = end_at + len(end_marker)


def credential_spans(text: str) -> list[tuple[int, int, str]]:
    """Secret and personal-data spans.

    Each pattern yields matches in order. A heap merges those lists, then one
    left-to-right sweep keeps the first non-overlapping span. The overlap
    work is linear in the number of matches.
    """
    if _over_cap(text):
        return [(0, len(text), "[REDACTED]")]
    streams: list[list[tuple[int, int, str]]] = []
    for pattern, replacement in REDACT_PATTERNS:
        found: list[tuple[int, int, str]] = []
        for match in pattern.finditer(text):
            if _redaction_marker(match.group(0)):
                continue
            if isinstance(replacement, str):
                token = match.expand(replacement)
            else:
                token = replacement(match)
            found.append((match.start(), match.end(), token))
        if found:
            streams.append(found)
    pem = _pem_spans(text)
    if pem:
        streams.append(pem)
    if not streams:
        return []
    heap: list[tuple[int, int, int, int, str]] = []
    for stream_index, stream in enumerate(streams):
        start, end, token = stream[0]
        heap.append((start, stream_index, 0, end, token))
    heapq.heapify(heap)
    accepted: list[tuple[int, int, str]] = []
    last_end = -1
    while heap:
        start, stream_index, item_index, end, token = heapq.heappop(heap)
        if start >= last_end and end > start:
            accepted.append((start, end, token))
            last_end = end
        next_index = item_index + 1
        stream = streams[stream_index]
        if next_index < len(stream):
            next_start, next_end, next_token = stream[next_index]
            heapq.heappush(heap, (next_start, stream_index, next_index, next_end, next_token))
    return accepted


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
    return [*credential_spans(view), *_email_spans(view), *_aws_row_spans(view)]


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


def _without_controls(text: str) -> str:
    if not secret_surface.has_refused_control(text):
        return text
    return "".join(char for char in text if not secret_surface.is_refused_control(char))


def _control_splits_a_token(text: str) -> bool:
    """A refused control next to a token run can hide a credential.

    Parameter digits stay in the text when the control itself is dropped, so
    one long side is enough. A cursor command in prose has no such side.
    One forward pass and one backward pass, then a scan of the controls.
    """
    alphabet = secret_surface._TOKEN_CHARS
    params = set("[];:?0123456789")
    length = len(text)
    end_run = [0] * length
    run = 0
    for index, char in enumerate(text):
        if char in alphabet:
            run += 1
        else:
            run = 0
        end_run[index] = run
    start_run = [0] * length
    run = 0
    for index in range(length - 1, -1, -1):
        if text[index] in alphabet:
            run += 1
        else:
            run = 0
        start_run[index] = run
    left_of = [-1] * length
    last = -1
    for index, char in enumerate(text):
        left_of[index] = last
        if char not in params:
            last = index
    right_of = [length] * length
    nxt = length
    for index in range(length - 1, -1, -1):
        right_of[index] = nxt
        if text[index] not in params:
            nxt = index
    for index, char in enumerate(text):
        if not secret_surface.is_refused_control(char):
            continue
        left_at = left_of[index]
        left = end_run[left_at] if left_at >= 0 and text[left_at] in alphabet else 0
        right_at = right_of[index]
        right = start_run[right_at] if right_at < length and text[right_at] in alphabet else 0
        if left >= 8 or right >= 8:
            return True
    return False


def _mask_chosen(text: str) -> str:
    """Mask one view. A control inside a token blanks that view; prose stays."""
    if _over_cap(text):
        return "[REDACTED]"
    if secret_surface.has_refused_control(text):
        if _control_splits_a_token(text):
            return "[REDACTED]"
        text = _without_controls(text)
    try:
        unjoined, joined = secret_surface.detection_views(text)
    except secret_surface.NormalizationBudgetExceeded:
        return "[REDACTED]"
    try:
        if unjoined == text and joined == text:
            masked = _mask_plain(text)
        else:
            masked = _mask_views(text, unjoined, joined)
    except secret_surface.NormalizationBudgetExceeded:
        return "[REDACTED]"
    return _without_controls(masked)


def _pattern_secret(text: str) -> bool:
    """A credential on this view. A refused control is not itself a credential."""
    if _over_cap(text):
        return True
    try:
        unjoined, joined = secret_surface.detection_views(text)
    except secret_surface.NormalizationBudgetExceeded:
        return True
    if _view_has_secret(unjoined):
        return True
    return joined != unjoined and _view_has_secret(joined)


def _letter_view(text: str) -> str:
    """Drop a finished CSI but keep the final letter."""
    if "\x1b" not in text:
        return text
    return _CSI.sub(r"\1", _OSC.sub("", text))


def _masked_ngrams(masked: str, size: int = 8) -> set[str]:
    """Every contiguous slice of `size` characters. Built once per scan."""
    if len(masked) < size:
        return set()
    return {masked[index : index + size] for index in range(len(masked) - size + 1)}


def _slice_visible(piece: str, ngrams: set[str]) -> bool:
    if len(piece) < 8 or not ngrams:
        return False
    return any(piece[index : index + 8] in ngrams for index in range(len(piece) - 7))


def _run_lengths(text: str) -> tuple[list[int], list[int]]:
    """Token-run length ending at each index, and starting at each index."""
    alphabet = secret_surface._TOKEN_CHARS
    length = len(text)
    ending = [0] * length
    run = 0
    for index, char in enumerate(text):
        if char in alphabet:
            run += 1
        else:
            run = 0
        ending[index] = run
    starting = [0] * length
    run = 0
    for index in range(length - 1, -1, -1):
        if text[index] in alphabet:
            run += 1
        else:
            run = 0
        starting[index] = run
    return ending, starting


def _csi_hides_a_token(text: str) -> bool:
    """A finished CSI ate part of a token, on either view, whatever else is present.

    Semicolons and colons are parameters, so they stay inside the match and
    do not split the token runs on either side. Run lengths are one pass.
    Each CSI is judged on its own, including when another secret is present.
    """
    if "\x1b" not in text or _over_cap(text):
        return False
    matches = list(_CSI.finditer(text))
    if not matches:
        return False
    stripped, _kept = _sgr_views(text)
    ngrams = _masked_ngrams(_mask_chosen(stripped))
    ending, starting = _run_lengths(text)
    for match in matches:
        pre = ending[match.start() - 1] if match.start() else 0
        post = starting[match.end()] if match.end() < len(text) else 0
        if pre < 4 and post < 8 and pre + post < 8:
            continue
        before = text[match.start() - pre : match.start()]
        after = text[match.end() : match.end() + post]
        # The final letter is kept in one candidate and dropped in the other,
        # so a parameter semicolon or colon cannot hide either shape.
        candidates = (before + match.group(1) + after, before + after)
        if any(_slice_visible(candidate, ngrams) for candidate in candidates):
            return True
    return False


def mask(text: str) -> str:
    """Detect on the shared unjoined and joined surfaces. Fail closed on budget.

    The stripped view and the view that keeps a CSI final letter are both
    scanned. A token character that finished the sequence is not emitted.
    """
    if _over_cap(text):
        return "[REDACTED]"
    stripped, _kept = _sgr_views(text)
    if _csi_hides_a_token(text):
        return "[REDACTED]"
    letter = _letter_view(text)
    masked = _mask_chosen(stripped)
    if letter != stripped and _pattern_secret(letter) and not _pattern_secret(masked):
        return _mask_chosen(letter)
    return masked


def _view_has_secret(text: str) -> bool:
    """True on the first hit. Does not compare matches against each other."""
    if _pem_spans(text):
        return True
    for pattern, _replacement in REDACT_PATTERNS:
        match = pattern.search(text)
        if match is not None and not _redaction_marker(match.group(0)):
            return True
    return False


def _detect(text: str) -> bool:
    """True when this one view shows a secret, a control, or a budget failure."""
    if _over_cap(text) or secret_surface.has_refused_control(text):
        return True
    try:
        unjoined, joined = secret_surface.detection_views(text)
    except secret_surface.NormalizationBudgetExceeded:
        return True
    if _view_has_secret(unjoined):
        return True
    return joined != unjoined and _view_has_secret(joined)


def has_secrets(text: str) -> bool:
    """True when a credential or personal-data value is visible.

    Scans the unjoined surface and the joined surface, and the view that
    keeps a CSI final letter. An exhausted normalization budget or an
    over-cap input fails closed. Email addresses alone do not count.
    """
    stripped, kept = _sgr_views(text)
    if _detect(stripped) or (kept != stripped and _detect(kept)):
        return True
    return _csi_hides_a_token(text)


def prepare_outbound(text: str) -> str:
    """Mask, then rescan both surfaces. Any failure raises and the CLI writes nothing."""
    stripped, kept = _sgr_views(text)
    if _over_cap(stripped) or _over_cap(kept):
        raise EgressMaskError(["input-cap"])
    if secret_surface.has_refused_control(stripped) or secret_surface.has_refused_control(kept):
        raise EgressMaskError(["control"])
    if _csi_hides_a_token(text):
        raise EgressMaskError(["control"])
    try:
        secret_surface.detection_views(stripped)
        if kept != stripped:
            secret_surface.detection_views(kept)
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
