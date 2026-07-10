# PURPOSE: Shared outbound HTTP policy — host allowlist + session hardening (SSRF).
# DEPENDENCIES: urllib.parse, requests
# MODIFICATION NOTES: Extracted for antigen fetch / contribute / registry_fetch reuse.

from __future__ import annotations

import re
from urllib.parse import urlparse

import requests

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def host_allowed(url: str, allowlist: list[str]) -> bool:
    """Fail-closed: empty allowlist rejects; only non-hex entries count as hosts."""
    if not allowlist:
        return False
    host = (urlparse(url).hostname or "").lower()
    allowed_hosts = {a.lower() for a in allowlist if not _HEX64.match(a.lower())}
    return host in allowed_hosts


def outbound_session(session: requests.Session | None = None) -> requests.Session:
    """Session that ignores HTTP(S)_PROXY ambient env (caller must pass allow_redirects=False)."""
    sess = session or requests.Session()
    sess.trust_env = False
    return sess
