# PURPOSE: Shared outbound HTTP/WS policy — host allowlist + session hardening (SSRF).
# DEPENDENCIES: urllib.parse, ipaddress, requests
# MODIFICATION NOTES: AppSec 2026-07-24 — env-only hosts; relay allowlist + blocked ranges

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse

import requests

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

FETCH_HOST_ENV = "SCP_ANTIGEN_FETCH_HOST_ALLOWLIST"
REGISTRY_HOST_ENV = "SCP_REGISTRY_FETCH_HOST_ALLOWLIST"
RELAY_ALLOWLIST_ENV = "SCP_ANTIGEN_RELAY_ALLOWLIST"


def host_allowed(url: str, allowlist: list[str]) -> bool:
    """Fail-closed: empty allowlist rejects; only non-hex entries count as hosts."""
    if not allowlist:
        return False
    host = (urlparse(url).hostname or "").lower()
    allowed_hosts = {a.lower() for a in allowlist if not _HEX64.match(a.lower())}
    return host in allowed_hosts


def env_fetch_host_allowlist() -> list[str]:
    """Operator-only HTTPS destinations for antigen fetch (MCP cannot expand)."""
    env = os.environ.get(FETCH_HOST_ENV, "")
    return [a.strip() for a in env.split(",") if a.strip()]


def env_registry_host_allowlist() -> list[str]:
    """Registry HTTPS hosts: dedicated env, else fall back to antigen fetch allowlist."""
    dedicated = os.environ.get(REGISTRY_HOST_ENV, "").strip()
    if dedicated:
        return [a.strip() for a in dedicated.split(",") if a.strip()]
    return env_fetch_host_allowlist()


def env_relay_allowlist() -> list[str]:
    env = os.environ.get(RELAY_ALLOWLIST_ENV, "")
    return [a.strip() for a in env.split(",") if a.strip()]


def _hostname_is_blocked(hostname: str) -> bool:
    h = (hostname or "").lower().rstrip(".")
    if not h:
        return True
    if h in ("localhost", "metadata.google.internal"):
        return True
    if h.endswith(".localhost") or h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # Not an IP literal — still block obvious metadata DNS names.
        if "169.254.169.254" in h:
            return True
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved:
        return True
    if ip.version == 4 and str(ip) == "169.254.169.254":
        return True
    return False


def relay_url_safe(url: str) -> bool:
    """Scheme/host safety for WebSocket relays (independent of allowlist membership)."""
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False
    if parsed.scheme != "wss":
        return False
    host = parsed.hostname
    if not host or _hostname_is_blocked(host):
        return False
    return True


def relay_allowed(url: str, allowlist: list[str]) -> bool:
    """Fail-closed: empty allowlist rejects; URL must be safe and host/exact match allowlist."""
    if not allowlist or not relay_url_safe(url):
        return False
    u = url.strip().rstrip("/")
    allowed = {a.strip().rstrip("/") for a in allowlist if a and a.strip()}
    if u in allowed:
        return True
    # Also allow matching by hostname entry in allowlist.
    host = (urlparse(u).hostname or "").lower()
    host_entries = {a.lower() for a in allowlist if a and "://" not in a}
    return host in host_entries


def filter_relays(
    requested: list[str] | None,
    *,
    require_env_allowlist: bool,
    fallback_defaults: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Resolve relay list: MCP requires env allowlist; caller may only subset it."""
    env_allow = env_relay_allowlist()
    if require_env_allowlist:
        if not env_allow:
            return ()
        candidates = [r.strip() for r in (requested or env_allow) if r and r.strip()]
        return tuple(r for r in candidates if relay_allowed(r, env_allow))

    # CLI / library: if env allowlist set, intersect; else filter defaults/requested for safety.
    if env_allow:
        candidates = [r.strip() for r in (requested or env_allow) if r and r.strip()]
        return tuple(r for r in candidates if relay_allowed(r, env_allow))

    candidates = [r.strip() for r in (requested or list(fallback_defaults)) if r and r.strip()]
    return tuple(r for r in candidates if relay_url_safe(r))


def pubkey_entries(allowlist: list[str] | None) -> list[str]:
    """Hex-64 issuer pubkeys only (strip host-shaped MCP allowlist noise)."""
    if not allowlist:
        return []
    out: list[str] = []
    for a in allowlist:
        s = a.strip().lower()
        if _HEX64.match(s):
            out.append(s)
    return out


def outbound_session(session: requests.Session | None = None) -> requests.Session:
    """Session that ignores HTTP(S)_PROXY ambient env (caller must pass allow_redirects=False)."""
    sess = session or requests.Session()
    sess.trust_env = False
    return sess
