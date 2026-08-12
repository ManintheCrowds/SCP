# PURPOSE: AppSec — bounded HTTPS body reads (memory DoS) for antigen/registry fetch.
# Run: PYTHONPATH=src pytest tests/test_appsec_fetch_body_caps.py -q

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from scp import http_body
from scp import quarantine_limits
from scp import registry_fetch as rf
from scp.antigen_nostr import FetchError
from scp import antigen_nostr as nostr
from scp import scp_utils


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("SCP_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.setenv("SCP_ANTIGEN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SCP_PATTERN_SSOT_PATH", str(tmp_path / "ssot.json"))
    monkeypatch.setenv("SCP_QUARANTINE_MAX_CONTENT_BYTES", "100")
    monkeypatch.setenv("SCP_ANTIGEN_MAX_PAYLOAD_BYTES", "64")
    return tmp_path


def test_read_response_bytes_rejects_content_length():
    resp = MagicMock()
    resp.headers = {"Content-Length": "999999"}
    closed = {"n": 0}

    def _close():
        closed["n"] += 1

    resp.close = _close
    # Must not consume body
    resp.iter_content = lambda chunk_size=65536: (_ for _ in ()).throw(
        AssertionError("must not stream when Content-Length exceeds cap")
    )
    with pytest.raises(http_body.ResponseTooLargeError):
        http_body.read_response_bytes(resp, max_bytes=100)
    assert closed["n"] == 1


def test_read_response_bytes_stops_mid_stream():
    resp = MagicMock()
    resp.headers = {}
    chunks = [b"a" * 60, b"b" * 60, b"SHOULD_NOT_READ"]
    state = {"i": 0}

    def gen(chunk_size=65536):
        while state["i"] < len(chunks):
            c = chunks[state["i"]]
            state["i"] += 1
            yield c

    resp.iter_content = gen
    closed = {"n": 0}
    resp.close = lambda: closed.__setitem__("n", closed["n"] + 1)

    with pytest.raises(http_body.ResponseTooLargeError):
        http_body.read_response_bytes(resp, max_bytes=100)
    assert state["i"] == 2  # second chunk tripped the cap; third never yielded
    assert closed["n"] == 1


def test_registry_fetch_https_rejects_oversized_body(monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "example.com")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Length": "500"}
    mock_resp.iter_content = lambda chunk_size=65536: iter([b"x" * 500])

    with patch("scp.registry_fetch.requests.Session.get", return_value=mock_resp):
        with pytest.raises(rf.RegistryFetchError) as exc:
            rf._fetch_https("https://example.com/snap.json", ["example.com"])
    assert exc.value.reason == "response_too_large"


def test_antigen_process_fetch_rejects_oversized_body():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Length": "200"}
    mock_resp.iter_content = lambda chunk_size=65536: iter([b"{" + b"a" * 200])

    with pytest.raises(FetchError) as exc:
        nostr._process_fetch_response(
            mock_resp,
            url_host="example.com",
            expected_hash_bare_hex="a" * 64,
        )
    assert exc.value.reason == "response_too_large"


def test_read_response_json_under_cap():
    payload = {"ok": True, "n": 1}
    raw = json.dumps(payload).encode("utf-8")
    resp = MagicMock()
    resp.headers = {"Content-Length": str(len(raw))}
    resp.iter_content = lambda chunk_size=65536: iter([raw])
    resp.close = MagicMock()
    assert http_body.read_response_json(resp, max_bytes=10_000) == payload


def test_read_response_json_invalid_utf8_is_invalid_json():
    resp = MagicMock()
    resp.headers = {"Content-Length": "1"}
    resp.iter_content = lambda chunk_size=65536: iter([b"\xff"])
    resp.close = MagicMock()

    with pytest.raises(json.JSONDecodeError):
        http_body.read_response_json(resp, max_bytes=10_000)


def test_read_response_bytes_transport_error_is_not_size_error():
    resp = MagicMock()
    resp.headers = {}

    def boom(chunk_size=65536):
        raise requests.ConnectionError("reset")
        yield  # pragma: no cover

    resp.iter_content = boom
    resp.close = MagicMock()
    with pytest.raises(http_body.ResponseReadError) as exc:
        http_body.read_response_bytes(resp, max_bytes=100)
    assert exc.value.reason == "fetch_failed"


def test_antigen_fetch_closes_l402_challenge_response(monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "example.com")
    mock_resp = MagicMock()
    mock_resp.status_code = 402
    mock_resp.headers = {}
    mock_resp.close = MagicMock()

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        with pytest.raises(FetchError) as exc:
            nostr.fetch_payload("https://example.com/antigen.json", "a" * 64)

    assert exc.value.reason == "payment_required"
    mock_resp.close.assert_called_once()


def test_antigen_process_fetch_closes_non_200_response():
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.headers = {}
    mock_resp.close = MagicMock()

    with pytest.raises(FetchError) as exc:
        nostr._process_fetch_response(
            mock_resp,
            url_host="example.com",
            expected_hash_bare_hex="a" * 64,
        )

    assert exc.value.reason == "http_error"
    mock_resp.close.assert_called_once()


def test_registry_https_maps_transport_error_to_fetch_failed(monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "example.com")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}

    def boom(chunk_size=65536):
        raise requests.Timeout("slow")
        yield  # pragma: no cover

    mock_resp.iter_content = boom
    mock_resp.close = MagicMock()

    with patch("scp.registry_fetch.requests.Session.get", return_value=mock_resp):
        with pytest.raises(rf.RegistryFetchError) as exc:
            rf._fetch_https("https://example.com/snap.json", ["example.com"])
    assert exc.value.reason == "fetch_failed"


def test_registry_fetch_layout_counts_against_total_quarantine_quota(monkeypatch):
    monkeypatch.setenv("SCP_QUARANTINE_MAX_TOTAL_BYTES", "200")
    monkeypatch.setenv("SCP_QUARANTINE_EVICT_OLDEST_ON_PRESSURE", "0")

    scp_utils.quarantine(
        "x" * 80,
        reason="registry_fetch",
        source="https://example.com/one.json",
        layout=scp_utils.REGISTRY_FETCH_LAYOUT,
    )

    assert quarantine_limits.total_quarantine_bytes(scp_utils.quarantine_dir()) > 0
    with pytest.raises(ValueError, match="SCP_QUARANTINE_MAX_TOTAL_BYTES"):
        scp_utils.quarantine(
            "y" * 80,
            reason="registry_fetch",
            source="https://example.com/two.json",
            layout=scp_utils.REGISTRY_FETCH_LAYOUT,
        )


def test_parse_nostr_snapshot_rejects_oversized_content(monkeypatch):
    monkeypatch.setenv("SCP_QUARANTINE_MAX_CONTENT_BYTES", "50")
    event = {
        "pubkey": "a" * 64,
        "content": "{" + ("x" * 80) + "}",
        "sig": "c" * 128,
    }
    with patch.object(rf.nostr, "verify_event_signature", return_value=True):
        with pytest.raises(rf.RegistryFetchError) as exc:
            rf._parse_nostr_snapshot(event, ["a" * 64])
    assert exc.value.reason == "response_too_large"
