# PURPOSE: SSRF mitigation for Ollama base URLs — keep rules aligned with MiscRepos .cursor/scripts/ollama_url_guard.py

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

_DEFAULT_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _normalize_host(host: str) -> str:
    h = host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        return h[1:-1]
    return h


def _extra_allowed_hosts() -> set[str]:
    raw = os.environ.get("OLLAMA_ALLOWED_HOSTS", "")
    return {_normalize_host(h) for h in raw.split(",") if h.strip()}


def _strict_resolution_enabled() -> bool:
    return os.environ.get("OLLAMA_URL_STRICT", "").strip().lower() in ("1", "true", "yes")


def _host_in_allowlist(host: str, extra: set[str]) -> bool:
    norm = _normalize_host(host)
    if norm in _DEFAULT_HOSTS:
        return True
    if norm in extra:
        return True
    return False


def _enforce_strict_resolved_ips(host: str, port: int) -> None:
    if not _strict_resolution_enabled():
        return
    norm = _normalize_host(host)
    try:
        ipaddress.ip_address(norm)
    except ValueError:
        pass
    else:
        return

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except OSError as e:
        raise ValueError(f"Could not resolve host under OLLAMA_URL_STRICT: {e}") from e

    for _fam, _typ, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip.is_loopback:
            continue
        if ip.is_private or ip.is_link_local:
            raise ValueError(
                f"Host resolves to disallowed address {ip_str} (private/link-local); "
                "adjust OLLAMA_ALLOWED_HOSTS or disable OLLAMA_URL_STRICT for trusted LAN only"
            )


def validate_ollama_base_url(url: str) -> str:
    """Return normalized base URL without trailing slash, or raise ValueError."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Ollama URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Ollama URL must not include userinfo")
    if parsed.fragment:
        raise ValueError("Ollama URL must not include a fragment")
    path = parsed.path or ""
    if path not in ("", "/"):
        raise ValueError("Ollama base URL must be origin only (no path); paths are fixed to /api/chat or /api/generate")
    if parsed.query:
        raise ValueError("Ollama URL must not include a query string")

    host = parsed.hostname
    if not host:
        raise ValueError("Ollama URL must include a host")

    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Invalid port")

    extra = _extra_allowed_hosts()
    if not _host_in_allowlist(host, extra):
        raise ValueError(
            f"Host {host!r} is not allowed. Use localhost, 127.0.0.1, ::1, or set OLLAMA_ALLOWED_HOSTS"
        )

    eff_port = port or (443 if parsed.scheme == "https" else 80)
    _enforce_strict_resolved_ips(host, eff_port)

    netloc = parsed.netloc
    base = f"{parsed.scheme}://{netloc}"
    return base.rstrip("/")
