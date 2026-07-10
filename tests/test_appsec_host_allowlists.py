# PURPOSE: AppSec host-allowlist + outbound session hardening (SSRF / proxy pivot).
# Run: PYTHONPATH=src pytest tests/test_appsec_host_allowlists.py -q

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scp import antigen
from scp import antigen_mcp
from scp import antigen_nostr as nostr
from scp import registry_contribute as rc
from scp import registry_fetch as rf

PAYLOAD_URL = "https://example.com/antigens/inj.appsec.001.json"
EVIL_URL = "https://evil.example/steal"
LOCAL_URL = "http://127.0.0.1:8765/snap"


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("SCP_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.setenv("SCP_ANTIGEN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SCP_PATTERN_SSOT_PATH", str(tmp_path / "ssot.json"))
    monkeypatch.setenv("SCP_CONTRIBUTE_OPT_IN_LOG", str(tmp_path / "opt_in.jsonl"))
    monkeypatch.delenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", raising=False)
    monkeypatch.delenv("SCP_CONTRIBUTE_HOST_ALLOWLIST", raising=False)
    monkeypatch.delenv("SCP_ANTIGEN_REGTEST_E2E", raising=False)
    monkeypatch.delenv("SCP_ANTIGEN_L402_INTEGRATION", raising=False)
    monkeypatch.delenv("SCP_CONTRIBUTE_CONSENT", raising=False)
    return tmp_path


def _patterns() -> list[dict]:
    return [
        {
            "pattern_id": "inj.override.001",
            "category": "injection",
            "detector": {"kind": "token_family", "normalized": "authorized-override-family"},
            "severity": "high",
            "containment": "sanitize",
        }
    ]


def test_fetch_rejects_without_host_allowlist():
    bare = "a" * 64
    with pytest.raises(nostr.FetchError) as exc:
        nostr.fetch_payload(PAYLOAD_URL, bare)
    assert exc.value.reason == "host_not_on_allowlist"


def test_fetch_rejects_host_not_on_allowlist(monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "example.com")
    bare = "a" * 64
    with pytest.raises(nostr.FetchError) as exc:
        nostr.fetch_payload(EVIL_URL, bare)
    assert exc.value.reason == "host_not_on_allowlist"


def test_fetch_allowlisted_host_reaches_network(monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "example.com")
    payload = {"patterns": _patterns()}
    bare = antigen.compute_payload_hash(payload)[7:]
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = payload
    mock_resp.headers = {}

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp) as get:
        got = nostr.fetch_payload(PAYLOAD_URL, bare)
    assert got == payload
    assert get.call_args.kwargs.get("allow_redirects") is False


def test_fetch_session_disables_trust_env(monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "example.com")
    bare = "a" * 64
    mock_resp = MagicMock()
    mock_resp.status_code = 402
    mock_resp.headers = {"WWW-Authenticate": "L402"}

    captured: dict = {}

    class CapturingSession:
        def __init__(self) -> None:
            self.trust_env = True

        def get(self, *args, **kwargs):
            captured["trust_env"] = self.trust_env
            captured["kwargs"] = kwargs
            return mock_resp

    with patch("scp.antigen_nostr.requests.Session", CapturingSession):
        with pytest.raises(nostr.FetchError) as exc:
            nostr.fetch_payload(PAYLOAD_URL, bare)
    assert exc.value.reason == "payment_required"
    assert captured["trust_env"] is False
    assert captured["kwargs"].get("allow_redirects") is False


def test_mcp_fetch_rejects_empty_allowlist_before_network(monkeypatch):
    monkeypatch.delenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", raising=False)
    bare = "b" * 64
    with patch("scp.antigen_nostr.requests.Session.get") as get:
        out = json.loads(
            antigen_mcp.scp_antigen_fetch(PAYLOAD_URL, bare, allowlist="")
        )
    assert out["ok"] is False
    assert out["error"] == "host_not_on_allowlist"
    get.assert_not_called()


def test_mcp_fetch_uses_allowlist_hosts(monkeypatch):
    payload = {"patterns": _patterns()}
    bare = antigen.compute_payload_hash(payload)[7:]
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = payload
    mock_resp.headers = {}

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        out = json.loads(
            antigen_mcp.scp_antigen_fetch(
                PAYLOAD_URL, bare, allowlist="example.com"
            )
        )
    assert out["ok"] is True


def test_contribute_post_rejects_without_host_allowlist():
    snapshot = {
        "schema_revision": "scp.registry_snapshot.v1",
        "patterns": [{"pattern_id": "x"}],
    }
    with pytest.raises(rc.ContributeError) as exc:
        rc.post_registry_snapshot(PAYLOAD_URL, snapshot)
    assert exc.value.reason == "host_not_on_allowlist"


def test_contribute_post_rejects_non_allowlisted_host(monkeypatch):
    monkeypatch.setenv("SCP_CONTRIBUTE_HOST_ALLOWLIST", "example.com")
    snapshot = {"schema_revision": "scp.registry_snapshot.v1", "patterns": []}
    with pytest.raises(rc.ContributeError) as exc:
        rc.post_registry_snapshot(EVIL_URL, snapshot)
    assert exc.value.reason == "host_not_on_allowlist"


def test_contribute_post_allowlisted_disables_redirects(monkeypatch):
    monkeypatch.setenv("SCP_CONTRIBUTE_HOST_ALLOWLIST", "example.com")
    snapshot = {"schema_revision": "scp.registry_snapshot.v1", "etag": "sha256:" + "a" * 64, "patterns": []}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"ETag": snapshot["etag"]}

    with patch("scp.registry_contribute.requests.Session.post", return_value=mock_resp) as post:
        out = rc.post_registry_snapshot(PAYLOAD_URL, snapshot)
    assert out["status"] == 200
    assert post.call_args.kwargs.get("allow_redirects") is False


def test_contribute_session_trust_env_false(monkeypatch):
    monkeypatch.setenv("SCP_CONTRIBUTE_HOST_ALLOWLIST", "127.0.0.1")
    snapshot = {"schema_revision": "scp.registry_snapshot.v1", "patterns": []}
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.headers = {}
    captured: dict = {}

    class CapturingSession:
        def __init__(self) -> None:
            self.trust_env = True

        def post(self, *args, **kwargs):
            captured["trust_env"] = self.trust_env
            captured["kwargs"] = kwargs
            return mock_resp

    with patch("scp.registry_contribute.requests.Session", CapturingSession):
        rc.post_registry_snapshot(LOCAL_URL, snapshot)
    assert captured["trust_env"] is False
    assert captured["kwargs"].get("allow_redirects") is False


def test_registry_fetch_https_disables_redirects():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "schema_revision": "scp.registry_snapshot.v1",
        "registry_version": "v",
        "patterns": [
            {
                "pattern_id": "contrib.inj.deadbeef",
                "category": "injection",
                "detector": {"kind": "token_family", "normalized": "injection-family-deadbeef"},
                "risk_tier": "medium",
            }
        ],
    }
    mock_resp.headers = {}

    with patch("scp.registry_fetch.requests.Session.get", return_value=mock_resp) as get:
        # May fail validation later; we only care redirects flag was set on GET
        try:
            rf._fetch_https(PAYLOAD_URL, ["example.com"])
        except Exception:
            pass
    assert get.called
    assert get.call_args.kwargs.get("allow_redirects") is False
