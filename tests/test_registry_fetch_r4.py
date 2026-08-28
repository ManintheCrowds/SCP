# PURPOSE: Tests for SCP-R4 registry fetch (HTTPS + nostr) quarantine path.
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from stream_response_mock import mock_json_response

from scp import antigen
from scp import antigen_nostr as nostr
from scp import pattern_record as pr
from scp import registry_contribute
from scp import registry_fetch
from scp import registry_ssot

FIXTURE = Path(__file__).parent / "fixtures" / "registry_snapshot_v1.json"
SECKEY = "0000000000000000000000000000000000000000000000000000000000000003"


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SCP_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.setenv("SCP_ANTIGEN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SCP_PATTERN_SSOT_PATH", str(tmp_path / "ssot.json"))
    monkeypatch.delenv("SCP_ANTIGEN_REGTEST_E2E", raising=False)
    monkeypatch.delenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", raising=False)
    monkeypatch.delenv("SCP_REGISTRY_FETCH_HOST_ALLOWLIST", raising=False)
    return tmp_path


def test_empty_host_allowlist_fail_closed(isolated_env):
    res = registry_fetch.fetch_registry("https://example.com/snap.json", [])
    assert res["ok"] is False
    assert res["error"] == "empty_host_allowlist"
    assert res["local_registry_unchanged"] is True


def test_caller_host_allowlist_ignored(isolated_env, monkeypatch):
    """Caller-supplied hosts must not expand destinations when env allowlist is empty."""
    res = registry_fetch.fetch_registry("https://example.com/snap.json", ["example.com"])
    assert res["ok"] is False
    assert res["error"] == "empty_host_allowlist"


def test_fetch_https_quarantine(isolated_env, monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "127.0.0.1")
    body = json.loads(FIXTURE.read_text(encoding="utf-8"))
    holder: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode("utf-8"))

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    holder["port"] = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{holder['port']}/registry.json"
    res = registry_fetch.fetch_registry(url, [])
    server.shutdown()

    assert res["ok"] is True
    assert res["merged"] is False
    assert res["quarantine_path"]
    assert res["diff_summary"]["add_count"] == 2
    qpath = Path(res["quarantine_path"])
    assert qpath.is_file()
    assert "registry_fetch" in qpath.parts
    # Merge-eligible after operator consent
    monkeypatch.setenv("SCP_REGISTRY_MERGE_CONSENT", "1")
    merge = registry_ssot.apply_merge(qpath, approve=True)
    assert merge["merged"] is True


def test_fetch_failure_unchanged_ssot(isolated_env, monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "127.0.0.1")
    res = registry_fetch.fetch_registry("https://127.0.0.1:59999/nope.json", [])
    assert res["ok"] is False
    assert res["local_registry_unchanged"] is True
    assert registry_ssot.load_ssot() == []


def test_regtest_localhost_guard(isolated_env, monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_REGTEST_E2E", "1")
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "example.com")
    res = registry_fetch.fetch_registry("https://example.com/snap.json", [])
    assert res["ok"] is False
    assert res["error"] == "fetch_url_not_localhost"


def test_fetch_nostr_registry_mock(isolated_env):
    snapshot = json.loads(FIXTURE.read_text(encoding="utf-8"))
    event = nostr.sign_event(
        {
            "kind": registry_fetch.REGISTRY_NOSTR_KIND,
            "tags": [],
            "content": json.dumps(snapshot),
            "created_at": 1,
        },
        seckey_hex=SECKEY,
    )

    transport = MagicMock()
    transport.subscribe.return_value = [event]

    issuer = antigen._pubkey_hex(bytes.fromhex(SECKEY))
    res = registry_fetch.fetch_registry(
        event["id"],
        [issuer],
        transport=transport,
    )

    assert res["ok"] is True
    assert res["merged"] is False
    assert res["diff_summary"]["add_count"] >= 1


def test_fetch_nostr_registry_announcement_follows_payload_url(isolated_env, monkeypatch):
    monkeypatch.setenv("SCP_REGISTRY_FETCH_HOST_ALLOWLIST", "raw.githubusercontent.com")
    snapshot = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload_url = "https://raw.githubusercontent.com/ManintheCrowds/scp-mycelium-registry/v0.1.0/snapshots/v0.1.0/registry.json"
    issuer = antigen._pubkey_hex(bytes.fromhex(SECKEY))
    bundle = antigen.export_bundle(
        registry_contribute._to_bundle_patterns(snapshot["patterns"]),
        antigen_id="registry.v0.1.0",
        seckey_hex=SECKEY,
        sign=True,
        payload_urls=[payload_url],
    )
    event = nostr.build_announcement_event(
        bundle,
        seckey_hex=SECKEY,
        created_at=1,
    )
    transport = MagicMock()
    transport.subscribe.return_value = [event]
    mock_resp = mock_json_response(snapshot)
    get_mock = MagicMock(return_value=mock_resp)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(registry_fetch.requests.Session, "get", get_mock)
        res = registry_fetch.fetch_registry(
            event["id"],
            [issuer],
            transport=transport,
        )

    assert res["ok"] is True
    assert res["merged"] is False
    assert res["diff_summary"]["add_count"] >= 1
    assert Path(res["quarantine_path"]).is_file()
    assert get_mock.call_args.kwargs["verify"] is True


def test_fetch_nostr_registry_announcement_honors_tls_verify_arg(
    isolated_env,
    monkeypatch,
):
    monkeypatch.setenv("SCP_REGISTRY_FETCH_HOST_ALLOWLIST", "raw.githubusercontent.com")
    snapshot = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload_url = "https://raw.githubusercontent.com/ManintheCrowds/scp-mycelium-registry/v0.1.0/snapshots/v0.1.0/registry.json"
    issuer = antigen._pubkey_hex(bytes.fromhex(SECKEY))
    bundle = antigen.export_bundle(
        registry_contribute._to_bundle_patterns(snapshot["patterns"]),
        antigen_id="registry.v0.1.0",
        seckey_hex=SECKEY,
        sign=True,
        payload_urls=[payload_url],
    )
    event = nostr.build_announcement_event(
        bundle,
        seckey_hex=SECKEY,
        created_at=1,
    )
    transport = MagicMock()
    transport.subscribe.return_value = [event]
    mock_resp = mock_json_response(snapshot)
    get_mock = MagicMock(return_value=mock_resp)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(registry_fetch.requests.Session, "get", get_mock)
        res = registry_fetch.fetch_registry(
            event["id"],
            [issuer],
            transport=transport,
            tls_verify=False,
        )

    assert res["ok"] is True
    assert get_mock.call_args.kwargs["verify"] is False


def test_fetch_nostr_registry_rejects_announcement_payload_hash_mismatch(
    isolated_env,
    monkeypatch,
):
    monkeypatch.setenv("SCP_REGISTRY_FETCH_HOST_ALLOWLIST", "raw.githubusercontent.com")
    snapshot = json.loads(FIXTURE.read_text(encoding="utf-8"))
    announced_snapshot = json.loads(FIXTURE.read_text(encoding="utf-8"))
    announced_snapshot["patterns"] = [announced_snapshot["patterns"][0]]
    payload_url = "https://raw.githubusercontent.com/ManintheCrowds/scp-mycelium-registry/v0.1.0/snapshots/v0.1.0/registry.json"
    issuer = antigen._pubkey_hex(bytes.fromhex(SECKEY))
    bundle = antigen.export_bundle(
        registry_contribute._to_bundle_patterns(announced_snapshot["patterns"]),
        antigen_id="registry.v0.1.0",
        seckey_hex=SECKEY,
        sign=True,
        payload_urls=[payload_url],
    )
    event = nostr.build_announcement_event(
        bundle,
        seckey_hex=SECKEY,
        created_at=1,
    )

    transport = MagicMock()
    transport.subscribe.return_value = [event]
    mock_resp = mock_json_response(snapshot)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(registry_fetch.requests.Session, "get", MagicMock(return_value=mock_resp))
        res = registry_fetch.fetch_registry(
            event["id"],
            [issuer],
            transport=transport,
        )

    assert res["ok"] is False
    assert res["error"] == "hash_mismatch"
    assert res["local_registry_unchanged"] is True


def test_invalid_snapshot_rejected(isolated_env):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"bad": True}).encode("utf-8"))

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}/bad.json"
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "127.0.0.1")
        res = registry_fetch.fetch_registry(url, [])
    server.shutdown()

    assert res["ok"] is False
    assert res["error"] == "invalid_snapshot"
    assert res["local_registry_unchanged"] is True
