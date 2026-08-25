# PURPOSE: Tests for SCP-R4 registry fetch (HTTPS + nostr) quarantine path.
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scp import pattern_record as pr
from scp import registry_fetch
from scp import registry_ssot

FIXTURE = Path(__file__).parent / "fixtures" / "registry_snapshot_v1.json"
EVENT_ID = "b" * 64


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
    event = {
        "id": EVENT_ID,
        "pubkey": "a" * 64,
        "created_at": 1,
        "kind": 30079,
        "tags": [],
        "content": json.dumps(snapshot),
        "sig": "c" * 128,
    }

    transport = MagicMock()
    transport.subscribe.return_value = [event]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(registry_fetch.nostr, "verify_event_signature", lambda _e: True)
        res = registry_fetch.fetch_registry(
            EVENT_ID,
            [event["pubkey"]],
            transport=transport,
        )

    assert res["ok"] is True
    assert res["merged"] is False
    assert res["diff_summary"]["add_count"] >= 1


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


def test_fetch_fails_closed_when_ssot_is_corrupt(isolated_env, monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "127.0.0.1")
    ssot_path = isolated_env / "ssot.json"
    ssot_path.write_text('{"patterns": [', encoding="utf-8")
    body = json.loads(FIXTURE.read_text(encoding="utf-8"))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode("utf-8"))

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    res = registry_fetch.fetch_registry(f"http://127.0.0.1:{port}/registry.json", [])
    server.shutdown()

    assert res["ok"] is False
    assert res["error"] == "ssot_corrupt"
    assert res["local_registry_unchanged"] is True
    assert ssot_path.read_text(encoding="utf-8") == '{"patterns": ['


def test_fetch_fails_closed_when_quarantine_write_fails(isolated_env, monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "127.0.0.1")
    body = json.loads(FIXTURE.read_text(encoding="utf-8"))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode("utf-8"))

        def log_message(self, *_args):
            return

    def raise_disk_full(*_args, **_kwargs):
        raise OSError("disk full")

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(registry_fetch.scp_utils, "quarantine", raise_disk_full)

    res = registry_fetch.fetch_registry(f"http://127.0.0.1:{port}/registry.json", [])
    server.shutdown()

    assert res["ok"] is False
    assert res["error"] == "quarantine_failed"
    assert res["local_registry_unchanged"] is True
