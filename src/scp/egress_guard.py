# PURPOSE: Independent egress checks. These detectors are not the masker's rules.

from __future__ import annotations

import base64
import binascii
import importlib
import re

try:
    from . import secret_text
except ImportError:  # python src/scp/mask_secrets.py loads this file by path
    secret_text = importlib.import_module("secret_text")


def _cat(*parts: str) -> str:
    return "".join(parts)


def _decoded_payloads(text: str) -> list[str]:
    """Hex and URL-safe base64 candidates, decoded for a second detector pass."""
    found: list[str] = []
    for match in re.finditer(r"\b(?:[0-9a-fA-F]{2}){8,}\b", text):
        try:
            decoded = bytes.fromhex(match.group(0)).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            continue
        if decoded:
            found.append(decoded)
    for match in re.finditer(r"[A-Za-z0-9_-]{16,}={0,2}", text):
        chunk = match.group(0)
        pad = "=" * ((4 - len(chunk) % 4) % 4)
        try:
            raw = base64.urlsafe_b64decode(chunk + pad)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and decoded != chunk:
            found.append(decoded)
    return found


def views_for_rescan(text: str) -> list[str]:
    """Same surfaces as mask(), plus decoded payloads. The caller runs every detector."""
    unjoined, joined = secret_text.detection_views(text)
    views = [unjoined]
    if joined != unjoined:
        views.append(joined)
    views.extend(_decoded_payloads(unjoined))
    if joined != unjoined:
        views.extend(_decoded_payloads(joined))
    return views


def _double_url(text: str) -> str:
    if "%25" not in text and "%25".lower() not in text.lower():
        return text

    def repl(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 16))

    once = re.sub(r"(?i)%25([0-9a-f]{2})", repl, text)
    return re.sub(r"(?i)%([0-9a-f]{2})", repl, once)


def _has_email(text: str) -> bool:
    return re.search(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}", text) is not None


def _has_ssn(text: str) -> bool:
    flat = text
    return re.search(r"(?<!\d)\d{3}[-. ]?\d{2}[-. ]?\d{4}(?!\d)", flat) is not None


def _prefix_hit(text: str, prefix: str, body: str) -> bool:
    return re.search(r"(?<![A-Za-z0-9])" + re.escape(prefix) + body, text) is not None


def find_suspicious(text: str) -> list[str]:
    """Return labels for suspicious leftovers. Does not use the masker's pattern list."""
    hits: list[str] = []
    unjoined, joined = secret_text.detection_views(text)
    flat = unjoined.replace("\n", "").replace("\t", "")
    decoded = _double_url(flat)
    views = (unjoined, joined, flat, decoded)

    def any_view(pred) -> bool:
        return any(pred(view) for view in views)

    prefixes = (
        ("github-oauth", _cat("gh", "o_"), r"[A-Za-z0-9]{20,}"),
        ("github-app", _cat("gh", "s_"), r"[A-Za-z0-9]{20,}"),
        ("github-user", _cat("gh", "u_"), r"[A-Za-z0-9]{20,}"),
        ("slack-bot", _cat("xo", "xb-"), r"[A-Za-z0-9-]{10,}"),
        ("access-key", _cat("AK", "IA"), r"[A-Z2-7]{16}"),
    )
    for label, prefix, body in prefixes:
        if any_view(lambda view, prefix=prefix, body=body: _prefix_hit(view, prefix, body)):
            hits.append(label)
    webhook = _cat("hooks.", "slack.com/", "services/")
    if any(webhook in view for view in views):
        hits.append("slack-webhook")
    if any_view(lambda view: re.search(r"(?i)authorization\s*:\s*basic\s+[A-Za-z0-9+/=_-]{8,}", view) is not None):
        hits.append("basic-auth")
    if any_view(
        lambda view: re.search(
            r"(?i)(?:\"(?:secret|api_key|client_secret)\"\s*:\s*\"(?!\[[A-Z_]*REDACTED\])[^\"\n]{1,200}\"|"
            r"\bclient_secret\b\s*[:=]\s*(?!\[[A-Z_]*REDACTED\])\S+)",
            view,
        )
        is not None
    ):
        hits.append("client-secret")
    if any_view(_has_email):
        hits.append("email")
    if any_view(_has_ssn):
        hits.append("ssn")
    if any_view(
        lambda view: re.search(
            r"(?i)\b(?:DOB|Date of Birth|MRN)\b\s*:\s*(?!\[[A-Z_]*REDACTED\])\S+",
            view,
        )
        is not None
    ):
        hits.append("record-id")
    if any_view(
        lambda view: re.search(
            r"(?i)\bPatient:\s*(?!\[[A-Z_]*REDACTED\])\S[^:\n]{0,80}",
            view,
        )
        is not None
    ):
        hits.append("patient")
    if re.search(r"[A-Za-z0-9+/]{257,}={0,2}", unjoined) or re.search(
        r"[A-Za-z0-9_-]{257,}={0,2}", unjoined
    ):
        hits.append("long-encoding")
    if _encoded_payload_is_secret(unjoined):
        hits.append("encoded-payload")
    return hits


def _encoded_payload_is_secret(text: str) -> bool:
    for match in re.finditer(r"[A-Za-z0-9_-]{16,256}={0,2}", text):
        chunk = match.group(0)
        pad = "=" * ((4 - len(chunk) % 4) % 4)
        try:
            raw = base64.urlsafe_b64decode(chunk + pad)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _has_email(decoded) or "password=" in decoded or _prefix_hit(decoded, "AK" + "IA", r"[A-Z2-7]{16}"):
            return True
    for match in re.finditer(r"\b(?:[0-9a-fA-F]{2}){8,80}\b", text):
        try:
            decoded = bytes.fromhex(match.group(0)).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            continue
        if _has_email(decoded) or "password=" in decoded:
            return True
    return False
