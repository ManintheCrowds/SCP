# PURPOSE: Unit tests for dial-host allowlist (SSRF: \\@ / userinfo / private).
# Run: PYTHONPATH=src pytest tests/test_http_policy_host_allowlist.py -q

from __future__ import annotations

import pytest

from scp import http_policy
from scp import antigen_l402 as l402


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
        ("https://2852039166/x", "2852039166"),
    ],
)
def test_legacy_numeric_ipv4_denied_even_when_allowlisted(url, host):
    assert http_policy.host_allowed(url, [host]) is False


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
