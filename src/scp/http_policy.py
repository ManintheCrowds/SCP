# PURPOSE: Shared outbound HTTP/WS policy — host allowlist + session hardening (SSRF).
# DEPENDENCIES: urllib.parse, ipaddress, requests, urllib3
# MODIFICATION NOTES: AppSec 2026-10-06 — dial-host allowlist (reject \\ / userinfo; private block + A4 loopback)
# MODIFICATION NOTES: 2026-10-30 — legacy IPv4, encoded/Unicode hosts, pinned resolution, no redirects

from __future__ import annotations

import ipaddress
import os
import re
import socket
import unicodedata
from urllib.parse import unquote, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NameResolutionError, NewConnectionError
from urllib3.util import connection as urllib3_connection

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_NUMERIC_IPV4_PART = re.compile(r"(?:0x[0-9a-f]+|[0-9]+)\Z")
_CGNAT = ipaddress.IPv4Network("100.64.0.0/10")
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.IPv6Network("64:ff9b:1::/48")
# Dots that IDNA / getaddrinfo still fold into ASCII '.' (WHATWG / glibc).
_UNICODE_DOTS = str.maketrans(
    {
        "\u3002": ".",  # ideographic full stop
        "\uff0e": ".",  # fullwidth full stop
        "\uff61": ".",  # halfwidth ideographic full stop
        "\ufe52": ".",  # small full stop
        "\u2024": ".",  # one dot leader
    }
)

FETCH_HOST_ENV = "SCP_ANTIGEN_FETCH_HOST_ALLOWLIST"
REGISTRY_HOST_ENV = "SCP_REGISTRY_FETCH_HOST_ALLOWLIST"
RELAY_ALLOWLIST_ENV = "SCP_ANTIGEN_RELAY_ALLOWLIST"
REGISTRY_TLS_VERIFY_ENV = "SCP_REGISTRY_TLS_VERIFY"
ANTIGEN_TLS_VERIFY_ENV = "SCP_ANTIGEN_TLS_VERIFY"


def env_tls_verify(var: str = REGISTRY_TLS_VERIFY_ENV, *, default: str = "1") -> bool:
    """Operator env seam for requests verify=. Default verify-on; MCP must not override."""
    return os.environ.get(var, default).strip().lower() not in ("0", "false", "no")


def url_shape_ok(url: str) -> bool:
    """Reject backslash and userinfo before any dial-host comparison."""
    if not url or "\\" in url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    # Authority with @ but empty userinfo still counts as userinfo-shaped.
    netloc = parsed.netloc or ""
    if "@" in netloc:
        return False
    return True


def dial_hostname(url: str) -> str | None:
    """Hostname requests will dial (prepared URL). None = reject (shape/prepare/parity)."""
    if not url_shape_ok(url):
        return None
    try:
        parsed = urlparse(url)
        parse_host = (parsed.hostname or "").lower()
        if not parse_host:
            return None
        prepared = requests.Request("GET", url).prepare().url
        if not prepared:
            return None
        dial = (urlparse(prepared).hostname or "").lower()
    except Exception:
        return None
    if not dial or dial != parse_host:
        return None
    return dial


def https_or_loopback_http_ok(url: str) -> bool:
    """True for https, or http only when dial host is exact loopback (A4)."""
    if not url_shape_ok(url):
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme == "https":
        return dial_hostname(url) is not None
    if parsed.scheme == "http":
        dial = dial_hostname(url)
        return dial is not None and dial in _LOOPBACK_HOSTS
    return False


def host_allowed(url: str, allowlist: list[str]) -> bool:
    """Fail-closed: empty allowlist rejects; allowlist the host requests will dial.

    Rejects backslash/userinfo and parse/dial host mismatch. Refuses private and
    link-local dial targets except exact allowlisted loopback (Assumption A4).
    """
    if not allowlist:
        return False
    dial = dial_hostname(url)
    if not dial:
        return False
    allowed_hosts = {a.lower() for a in allowlist if not _HEX64.match(a.lower())}
    if dial not in allowed_hosts:
        return False
    # A4: exact allowlisted loopback may pass; other blocked ranges stay refused.
    if dial in _LOOPBACK_HOSTS:
        return True
    if _hostname_is_blocked(dial):
        return False
    return True


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


def _normalize_hostname(hostname: str) -> str:
    """Fold encoded and Unicode lookalikes into the host getaddrinfo would dial.

    Percent-decoding is applied twice so ``%252e`` cannot hide a dot. Trailing
    dots are stripped only for classification; DNS lookup still uses urllib3's
    original host so search-domain suffixing stays unchanged.
    """
    h = (hostname or "").strip().lower()
    for _ in range(2):
        decoded = unquote(h)
        folded = unicodedata.normalize("NFKC", decoded).translate(_UNICODE_DOTS)
        h = folded.strip().lower()
    return h.rstrip(".")


def _host_has_forbidden_chars(hostname: str) -> bool:
    if "%" in hostname:
        return True
    for char in hostname:
        if char in " \t\r\n\\/@#?" or ord(char) < 32:
            return True
    return False


def _looks_like_legacy_ipv4_literal(hostname: str) -> bool:
    """True for inet_aton forms that are not canonical ``ipaddress`` literals.

    Overflow and out-of-range parts still count. glibc wraps some of those
    into a real address, so treating them as ordinary DNS names is fail-open.
    """
    parts = hostname.split(".")
    if not 1 <= len(parts) <= 4:
        return False
    return all(_NUMERIC_IPV4_PART.fullmatch(part) for part in parts)


def _embedded_ipv4s(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    found: list[ipaddress.IPv4Address] = []
    mapped = ip.ipv4_mapped
    if mapped is not None:
        found.append(mapped)
    sixtofour = ip.sixtofour
    if sixtofour is not None:
        found.append(sixtofour)
    teredo = ip.teredo
    if teredo is not None:
        found.extend(teredo)
    if ip in _NAT64_WELL_KNOWN or ip in _NAT64_LOCAL:
        found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    elif mapped is None and (int(ip) >> 32) == 0:
        compatible = int(ip) & 0xFFFFFFFF
        if compatible > 1:
            found.append(ipaddress.IPv4Address(compatible))
    return found


def _ipv4_address_is_blocked(ip: ipaddress.IPv4Address) -> bool:
    # ``not is_global`` covers private, loopback, link-local, and reserved space.
    # CGNAT is neither global nor private here; multicast is still marked global.
    return ip.is_multicast or ip in _CGNAT or not ip.is_global


def _address_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return _ipv4_address_is_blocked(ip)
    if ip.is_multicast or ip.is_site_local or ip.is_reserved or not ip.is_global:
        return True
    return any(_ipv4_address_is_blocked(embedded) for embedded in _embedded_ipv4s(ip))


def _hostname_is_blocked(hostname: str) -> bool:
    h = _normalize_hostname(hostname)
    if not h or _host_has_forbidden_chars(h):
        return True
    if h in ("localhost", "metadata.google.internal"):
        return True
    if h.endswith(".localhost") or h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h.split("%", 1)[0])
    except ValueError:
        if _looks_like_legacy_ipv4_literal(h):
            return True
        # Not an IP literal — still block obvious metadata DNS names.
        if "169.254.169.254" in h:
            return True
        return False
    return _address_is_blocked(ip)


def _parse_resolved_ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return None


def _exact_loopback_name(hostname: str) -> bool:
    """True only for the A4 names, not for Unicode or numeric aliases of them."""
    raw = (hostname or "").strip().lower().rstrip(".")
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    return raw in _LOOPBACK_HOSTS


def _records_include_blocked(hostname: str, records: list[tuple]) -> bool:
    """True when any resolved address is blocked, unless the name is exact loopback."""
    allow_loopback = _exact_loopback_name(hostname)
    if not records:
        return True
    for record in records:
        sockaddr = record[4]
        ip = _parse_resolved_ip(sockaddr[0])
        if ip is None:
            return True
        if allow_loopback and ip.is_loopback:
            continue
        if _address_is_blocked(ip):
            return True
    return False


def resolved_url_blocked(url: str) -> bool:
    """True when the URL host is blocked as a literal or via its resolved addresses.

    Unresolvable names are blocked so a failed lookup cannot fall through to a
    later dial. Exact loopback URLs stay allowed.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return True
    host = parsed.hostname
    if not host:
        return True
    if parsed.port is not None:
        port = parsed.port
    elif parsed.scheme in ("https", "wss"):
        port = 443
    elif parsed.scheme in ("http", "ws"):
        port = 80
    else:
        return True
    try:
        return resolved_addresses_blocked(host, port)
    except socket.gaierror:
        return True


def resolved_addresses_blocked(hostname: str, port: int) -> bool:
    """Report whether ``hostname`` is a blocked literal or resolves to one.

    Raises ``socket.gaierror`` when a non-literal name does not resolve.
    Exact loopback names (``localhost``, ``127.0.0.1``, ``::1``) may resolve
    to loopback. Legacy numeric aliases are blocked before resolution.
    """
    if not _exact_loopback_name(hostname) and _hostname_is_blocked(hostname):
        return True
    family = urllib3_connection.allowed_gai_family()
    records = socket.getaddrinfo(hostname, port, family, socket.SOCK_STREAM)
    return _records_include_blocked(hostname, records)


def _open_pinned_socket(conn: HTTPConnection) -> socket.socket:
    """Dial an address from one validated lookup of the original host.

    The follow-up connect uses that address literal, not the hostname, so a
    DNS rebinding cannot change the target between check and TCP connect.
    """
    host = conn._dns_host
    if host.startswith("["):
        host = host.strip("[]")
    port = conn.port
    if not _exact_loopback_name(host) and _hostname_is_blocked(host):
        raise NewConnectionError(conn, "destination address is blocked")
    try:
        family = urllib3_connection.allowed_gai_family()
        records = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise NameResolutionError(conn.host, conn, exc) from exc
    if _records_include_blocked(host, records):
        raise NewConnectionError(conn, "destination address is blocked")

    last_error: OSError | None = None
    for record in records:
        sockaddr = record[4]
        ip = sockaddr[0]
        dest_port = sockaddr[1] if len(sockaddr) > 1 else port
        try:
            return urllib3_connection.create_connection(
                (ip, dest_port),
                conn.timeout,
                source_address=conn.source_address,
                socket_options=conn.socket_options,
            )
        except OSError as exc:
            last_error = exc
    raise NewConnectionError(
        conn, f"Failed to establish a new connection: {last_error}"
    )


class _PinnedHTTPConnection(HTTPConnection):
    def _new_conn(self) -> socket.socket:
        return _open_pinned_socket(self)


class _PinnedHTTPSConnection(HTTPSConnection):
    def _new_conn(self) -> socket.socket:
        return _open_pinned_socket(self)


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedHTTPAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _PinnedHTTPConnectionPool,
            "https": _PinnedHTTPSConnectionPool,
        }


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
    """Session that ignores ambient proxies, refuses redirects, and pins DNS.

    Redirects are forced off even if a caller passes ``allow_redirects=True``.
    TCP connects only to addresses checked in that same lookup, so a DNS
    rebinding between check and connect cannot retarget the dial.
    """
    sess = session or requests.Session()
    sess.trust_env = False
    if getattr(sess, "_scp_outbound_hardened", False):
        return sess
    mount = getattr(sess, "mount", None)
    if callable(mount):
        adapter = _PinnedHTTPAdapter()
        mount("https://", adapter)
        mount("http://", adapter)
    send = getattr(sess, "send", None)
    if callable(send):

        def _send_without_redirects(request, **kwargs):
            kwargs["allow_redirects"] = False
            return send(request, **kwargs)

        sess.send = _send_without_redirects  # type: ignore[method-assign]
    try:
        setattr(sess, "_scp_outbound_hardened", True)
    except (AttributeError, TypeError):
        pass
    return sess
