# PURPOSE: SCP-ANT1 P1b — L402 macaroon+invoice parse/format helpers for HTTPS antigen fetch.
# DEPENDENCIES: none (stdlib only)
# MODIFICATION NOTES: P1b v0 — L402 only; Cashu NUT-24 deferred to P2 per ANT1 §11.6.

from __future__ import annotations

import os
import re

_L402_SCHEME = re.compile(r"^L402\s+", re.IGNORECASE)
_KV_QUOTED = re.compile(r'(\w+)=("([^"]*)"|([^,\s]+))')


def parse_www_authenticate_l402(header: str | None) -> dict | None:
    """Parse WWW-Authenticate L402 challenge into macaroon and invoice fields."""
    if not header:
        return None
    text = header.strip()
    if not _L402_SCHEME.match(text):
        return None
    text = _L402_SCHEME.sub("", text, count=1).strip()
    macaroon: str | None = None
    invoice: str | None = None
    for match in _KV_QUOTED.finditer(text):
        key = match.group(1).lower()
        value = match.group(3) if match.group(3) is not None else match.group(4)
        if key == "macaroon":
            macaroon = value
        elif key == "invoice":
            invoice = value
    if not macaroon and not invoice:
        return None
    return {
        "macaroon": macaroon,
        "invoice": invoice,
        "raw": header,
        "invoice_hint": _invoice_correlation_hint(invoice),
    }


def normalize_l402_token(token: str) -> tuple[str, str]:
    """Return (macaroon, preimage) from operator-supplied token string."""
    text = token.strip()
    if not text:
        raise ValueError("empty_l402_token")
    if text.lower().startswith("l402 "):
        text = text[5:].strip()
    if ":" not in text:
        raise ValueError("l402_token_must_be_macaroon_colon_preimage")
    macaroon, preimage = text.split(":", 1)
    macaroon = macaroon.strip()
    preimage = preimage.strip()
    if not macaroon or not preimage:
        raise ValueError("l402_token_must_be_macaroon_colon_preimage")
    return macaroon, preimage


def format_authorization_header(macaroon: str, preimage: str) -> str:
    """Build Authorization header value for L402 retry."""
    return f"L402 {macaroon}:{preimage}"


def l402_token_from_env() -> str | None:
    """Read operator-supplied L402 token from SCP_ANTIGEN_L402_TOKEN (never log)."""
    env = os.environ.get("SCP_ANTIGEN_L402_TOKEN")
    return env.strip() if env else None


def _invoice_correlation_hint(invoice: str | None) -> str | None:
    """Short non-secret correlation id for audit logs (payment hash prefix unavailable without decode)."""
    if not invoice:
        return None
    # lnbc... invoices: log prefix only — never full invoice in default audit.
    return invoice[:16] if len(invoice) > 16 else invoice
