# PURPOSE: Unit tests for dial-host allowlist (SSRF: \\@ / userinfo / private).
# Run: PYTHONPATH=src pytest tests/test_http_policy_host_allowlist.py -q

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import requests

from scp import antigen_l402 as l402
from scp import http_policy
from scp.antigen_nostr import WebSocketRelayTransport


def test_backslash_at_rejected_even_when_parse_host_allowlisted():
    url = r"https://127.0.0.1:9\@example.com/x"
    assert http_policy.dial_hostname(url) is None
    assert http_policy.host_allowed(url, ["example.com"]) is False


def test_userinfo_rejected_when_hostname_allowlisted():
    url = "https://user:pass@example.com/x"
    assert http_policy.url_shape_ok(url) is False
    assert http_policy.host_allowed(url, ["example.com"]) is False


def test_backslash_anywhere_rejected():
    url = r"https://example.com/\path"
    assert http_policy.url_shape_ok(url) is False
    assert http_policy.host_allowed(url, ["example.com"]) is False


def test_clean_public_https_allowed():
    url = "https://example.com/antigens/x.json"
    assert http_policy.dial_hostname(url) == "example.com"
    assert http_policy.host_allowed(url, ["example.com"]) is True


def test_exact_allowlisted_loopback_http_allowed():
    url = "http://127.0.0.1:8765/snap"
    assert http_policy.https_or_loopback_http_ok(url) is True
    assert http_policy.host_allowed(url, ["127.0.0.1"]) is True


def test_private_ip_denied_even_when_allowlisted():
    assert http_policy.host_allowed("https://10.0.0.1/x", ["10.0.0.1"]) is False
    assert http_policy.host_allowed("https://169.254.1.1/x", ["169.254.1.1"]) is False


def test_public_ip_allowed_when_explicitly_allowlisted():
    assert http_policy.host_allowed("https://8.8.8.8/x", ["8.8.8.8"]) is True


@pytest.mark.parametrize(
    "url, host",
    [
        ("https://2130706433/x", "2130706433"),
        ("https://127.1/x", "127.1"),
        ("https://127.0.1/x", "127.0.1"),
        ("https://0x7f.1/x", "0x7f.1"),
        ("https://0x7f.0.0.1/x", "0x7f.0.0.1"),
        ("https://0x7f000001/x", "0x7f000001"),
        ("https://0177.0.0.1/x", "0177.0.0.1"),
        ("https://0177.0.1/x", "0177.0.1"),
        ("https://017700000001/x", "017700000001"),
        ("https://2852039166/x", "2852039166"),
        ("https://0xa9.0xfe.0xa9.0xfe/x", "0xa9.0xfe.0xa9.0xfe"),
        ("https://0251.0376.0251.0376/x", "0251.0376.0251.0376"),
        ("https://169.254.43518/x", "169.254.43518"),
        ("https://127.0.0.1./x", "127.0.0.1."),
        ("https://2130706433./x", "2130706433."),
        ("https://0x7f.1./x", "0x7f.1."),
        ("https://0x7f.0x0.0x0.0x1/x", "0x7f.0x0.0x0.0x1"),
        ("https://127.0.0.0x1/x", "127.0.0.0x1"),
        ("https://127.0.65535/x", "127.0.65535"),
        ("https://8.8.8/x", "8.8.8"),
        ("https://010.010.010.010/x", "010.010.010.010"),
        ("https://0x8.0x8.0x8.0x8/x", "0x8.0x8.0x8.0x8"),
        ("https://0/x", "0"),
        ("https://127.0.0.2/x", "127.0.0.2"),
        ("https://100.64.0.1/x", "100.64.0.1"),
        ("https://224.0.0.1/x", "224.0.0.1"),
        ("https://192.0.2.1/x", "192.0.2.1"),
        ("https://[::ffff:127.0.0.1]/x", "::ffff:127.0.0.1"),
        ("https://[::ffff:7f00:1]/x", "::ffff:7f00:1"),
        ("https://[::ffff:7f00:0001]/x", "::ffff:7f00:0001"),
        ("https://[::7f00:1]/x", "::7f00:1"),
        ("https://[::127.0.0.1]/x", "::127.0.0.1"),
        ("https://[::ffff:0:7f00:1]/x", "::ffff:0:7f00:1"),
        ("https://[0:0:0:0:0:ffff:127.0.0.1]/x", "0:0:0:0:0:ffff:127.0.0.1"),
        ("https://[64:ff9b::7f00:1]/x", "64:ff9b::7f00:1"),
        ("https://[64:ff9b::127.0.0.1]/x", "64:ff9b::127.0.0.1"),
        ("https://[64:ff9b:1::127.0.0.1]/x", "64:ff9b:1::127.0.0.1"),
        ("https://[2002:7f00:1::]/x", "2002:7f00:1::"),
        ("https://[2002:a9fe:a9fe::]/x", "2002:a9fe:a9fe::"),
        ("https://[::ffff:a9fe:a9fe]/x", "::ffff:a9fe:a9fe"),
        ("https://[::ffff:169.254.169.254]/x", "::ffff:169.254.169.254"),
        ("https://[ff02::1]/x", "ff02::1"),
        ("https://[fec0::1]/x", "fec0::1"),
        ("https://[fe80::1]/x", "fe80::1"),
        ("https://127.0.0.1%20/x", "127.0.0.1%20"),
        ("https://%20127.0.0.1/x", "%20127.0.0.1"),
        ("https://127.0.0.1%00.example.com/x", "127.0.0.1%00.example.com"),
        ("https://127.0.0.1%5c.example.com/x", "127.0.0.1%5c.example.com"),
        (
            "https://0000000000000000000000000000002130706433/x",
            "0000000000000000000000000000002130706433",
        ),
    ],
)
def test_legacy_numeric_ipv4_denied_even_when_allowlisted(url, host):
    assert http_policy.host_allowed(url, [host]) is False
    assert http_policy.host_allowed(url, [host, "example.com"]) is False


@pytest.mark.parametrize(
    "url, decoded",
    [
        ("https://127%2e0%2e0%2e1/x", "127.0.0.1"),
        ("https://127%2e1/x", "127.1"),
        ("https://0x7f%2e1/x", "0x7f.1"),
        ("https://%32%31%33%30%37%30%36%34%33%33/x", "2130706433"),
        ("https://127.0.0.1%2e/x", "127.0.0.1."),
        ("https://0177%2e0%2e0%2e1/x", "0177.0.0.1"),
    ],
)
def test_percent_encoded_literals_denied(url, decoded):
    encoded = url.split("/")[2]
    assert http_policy.host_allowed(url, [encoded, decoded, "example.com"]) is False


@pytest.mark.parametrize(
    "host",
    [
        "127。0。0。1",
        "127．0．0．1",
        "127｡0｡0｡1",
        "１２７．０．０．１",
        "①②⑦.0.0.1",
    ],
)
def test_unicode_dot_literals_denied(host):
    assert http_policy.host_allowed(f"https://{host}/x", [host, "127.0.0.1"]) is False
    assert http_policy.relay_url_safe(f"wss://{host}/x") is False


def test_userinfo_cannot_hide_legacy_or_loopback_host():
    assert http_policy.host_allowed(
        "https://example.com@2130706433/x", ["example.com", "2130706433"]
    ) is False
    assert http_policy.host_allowed(
        "https://example.com%40@127.0.0.1/x", ["example.com", "127.0.0.1"]
    ) is False
    assert http_policy.host_allowed(
        "https://127.0.0.1#@example.com/x", ["example.com"]
    ) is False


def test_relay_blocks_obfuscated_and_embedded_literals():
    plain = [
        "2130706433",
        "0x7f.1",
        "0177.0.0.1",
        "127.1",
        "2852039166",
        "100.64.0.1",
        "127%2e0%2e0%2e1",
    ]
    for host in plain:
        assert http_policy.relay_url_safe(f"wss://{host}/x") is False
    bracketed = [
        "::ffff:127.0.0.1",
        "::ffff:7f00:1",
        "::7f00:1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::7f00:1",
        "2002:7f00:1::",
        "2002:a9fe:a9fe::",
        "ff02::1",
        "fec0::1",
    ]
    for host in bracketed:
        assert http_policy.relay_url_safe(f"wss://[{host}]/x") is False
    assert http_policy.relay_url_safe("wss://example.com/x") is True
    assert http_policy.relay_url_safe("wss://8.8.8.8/x") is True


def test_wrapped_octal_literal_is_blocked_even_though_inet_aton_accepts_it():
    host = "0000000000000000000000000000002130706433"
    packed = socket.inet_aton(host)
    assert socket.inet_ntoa(packed) != host
    assert http_policy.host_allowed(f"https://{host}/x", [host]) is False
    assert http_policy.resolved_addresses_blocked(host, 443) is True


@pytest.mark.parametrize(
    "host",
    [
        "2130706433",
        "127.1",
        "0x7f.1",
        "0177.0.0.1",
        "2852039166",
        "::ffff:127.0.0.1",
        "::ffff:7f00:1",
        "::7f00:1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::",
        "2002:a9fe:a9fe::",
        "100.64.0.1",
    ],
)
def test_resolved_literal_targets_are_blocked(host):
    assert http_policy.resolved_addresses_blocked(host, 443) is True


def test_exact_loopback_and_canonical_public_resolution_allowed():
    assert http_policy.resolved_addresses_blocked("127.0.0.1", 80) is False
    assert http_policy.resolved_addresses_blocked("localhost", 80) is False
    assert http_policy.resolved_addresses_blocked("::1", 80) is False
    assert http_policy.resolved_addresses_blocked("8.8.8.8", 443) is False
    assert http_policy.host_allowed("http://[::1]/x", ["::1"]) is True


def test_dns_name_blocked_when_any_resolved_address_is_private(monkeypatch):
    def fake(host, port, *args, **kwargs):
        assert host == "example.com"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port)),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("169.254.169.254", port),
            ),
        ]

    monkeypatch.setattr(http_policy.socket, "getaddrinfo", fake)
    assert http_policy.resolved_addresses_blocked("example.com", 443) is True


def test_dns_name_allowed_when_resolution_is_public(monkeypatch):
    def fake(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))
        ]

    monkeypatch.setattr(http_policy.socket, "getaddrinfo", fake)
    assert http_policy.resolved_addresses_blocked("example.com", 443) is False


def test_outbound_session_refuses_rebinding_and_does_not_follow_redirects(monkeypatch):
    original = socket.getaddrinfo

    def fake_dns(host, port, *args, **kwargs):
        if host == "example.com":
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("169.254.169.254", port),
                )
            ]
        return original(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_dns)
    hits = {"n": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits["n"] += 1
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest")
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        sess = http_policy.outbound_session()
        with pytest.raises(requests.RequestException, match="blocked"):
            sess.get("http://example.com/x", timeout=2)
        port = server.server_address[1]
        response = sess.get(
            f"http://127.0.0.1:{port}/start",
            timeout=2,
            allow_redirects=True,
        )
        assert response.status_code == 302
        assert response.headers["Location"] == "http://169.254.169.254/latest"
        assert hits["n"] == 1
        assert response.history == []
    finally:
        server.shutdown()
        server.server_close()


def test_websocket_relay_skips_blocked_resolution_and_disables_redirects(monkeypatch):
    calls: list[tuple[str, dict]] = []

    class _FakeConn:
        def send(self, _msg):
            return None

        def recv(self):
            return '["OK"]'

        def close(self):
            return None

    class _FakeWS:
        def create_connection(self, url, **kwargs):
            calls.append((url, kwargs))
            return _FakeConn()

    monkeypatch.setattr("scp.antigen_nostr._require_websocket_client", lambda: _FakeWS())
    monkeypatch.setattr(
        http_policy,
        "resolved_url_blocked",
        lambda url: url == "wss://blocked.example/x",
    )
    WebSocketRelayTransport().publish(
        {"id": "1"},
        relays=("wss://example.com/x", "wss://blocked.example/x"),
    )
    assert calls == [
        ("wss://example.com/x", {"timeout": 10, "redirect_limit": 0}),
    ]


def test_loopback_mismatch_denied():
    # Shape reject (backslash) — dial never matches allowlisted parse host.
    url = r"https://127.0.0.1:9\@example.com/x"
    assert http_policy.host_allowed(url, ["127.0.0.1"]) is False
    assert http_policy.https_or_loopback_http_ok(url) is False


def test_assert_localhost_uses_dial_host():
    l402.assert_localhost_fetch_url("http://127.0.0.1/ok")
    with pytest.raises(ValueError, match="fetch_url_not_localhost"):
        l402.assert_localhost_fetch_url(r"https://127.0.0.1:9\@example.com/x")
    with pytest.raises(ValueError, match="fetch_url_not_localhost"):
        l402.assert_localhost_fetch_url("https://example.com/x")
