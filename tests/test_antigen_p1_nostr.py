# PURPOSE: Eval suite for SCP-ANT1 Antigen P1 (nostr pub/sub + HTTPS fetch).
# Run: pytest tests/test_antigen_p1_nostr.py

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from stream_response_mock import mock_json_response

from scp import antigen, antigen_nostr as nostr

SECKEY = "0000000000000000000000000000000000000000000000000000000000000003"
PAYLOAD_URL = "https://example.com/antigens/inj.nostr.001.json"


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


@pytest.fixture
def issuer() -> str:
    return antigen._pubkey_hex(bytes.fromhex(SECKEY))


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("SCP_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.setenv("SCP_ANTIGEN_AUDIT_LOG", str(tmp_path / "antigen_audit.jsonl"))
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(tmp_path / "registry.json"))
    monkeypatch.delenv("SCP_ANTIGEN_ISSUER_ALLOWLIST", raising=False)
    monkeypatch.delenv("SCP_ANTIGEN_ALLOWLIST_FILE", raising=False)
    monkeypatch.delenv("NOSTR_SECKEY", raising=False)
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "example.com")
    return tmp_path


def _signed_bundle(issuer: str, antigen_id: str = "inj.nostr.001") -> dict:
    return antigen.export_bundle(
        _patterns(),
        antigen_id=antigen_id,
        seckey_hex=SECKEY,
        sign=True,
        free_tier_summary="test summary",
        risk_tags=["injection"],
        payload_urls=[PAYLOAD_URL],
    )


def test_build_parse_roundtrip(issuer):
    bundle = _signed_bundle(issuer)
    event = nostr.build_announcement_event(bundle, seckey_hex=SECKEY, created_at=1_700_000_000)
    assert event["kind"] == nostr.ANTIGEN_NOSTR_KIND
    assert event["pubkey"] == issuer
    assert nostr.verify_event_signature(event)

    ann = nostr.parse_announcement_event(event)
    assert ann is not None
    assert ann.antigen_id == "inj.nostr.001"
    assert ann.payload_hash_bare == bundle["manifest"]["payload_content_hash"][7:]
    assert ann.payload_urls == (PAYLOAD_URL,)
    assert ann.schema_revision == "scp.pattern_bundle.v0"
    assert ann.free_tier_summary == "test summary"
    assert ann.risk_tags == ("injection",)


def test_wrong_kind_rejected(issuer):
    bundle = _signed_bundle(issuer)
    event = nostr.build_announcement_event(bundle, seckey_hex=SECKEY)
    event["kind"] = 30079
    event["id"] = nostr.compute_event_id(event)
    assert nostr.parse_announcement_event(event) is None


def test_bad_signature_rejected(issuer):
    bundle = _signed_bundle(issuer)
    event = nostr.build_announcement_event(bundle, seckey_hex=SECKEY)
    sig = event["sig"]
    event["sig"] = ("f" if sig[0] != "f" else "e") + sig[1:]
    assert nostr.parse_announcement_event(event) is None


def test_publish_requires_payload_urls(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.nostr.002", seckey_hex=SECKEY, sign=True)
    with pytest.raises(ValueError, match="payload_urls"):
        nostr.build_announcement_event(bundle, seckey_hex=SECKEY)


def test_empty_allowlist_discover_returns_empty(issuer):
    bundle = _signed_bundle(issuer)
    event = nostr.build_announcement_event(bundle, seckey_hex=SECKEY)
    mem = nostr.InMemoryRelayTransport()
    mem.publish(event, relays=("memory://",))
    out = nostr.discover_announcements(allowlist=[], transport=mem)
    assert out == []


def test_inmemory_relay_publish_subscribe(issuer, monkeypatch):
    bundle = _signed_bundle(issuer)
    mem = nostr.InMemoryRelayTransport()
    monkeypatch.delenv("SCP_ANTIGEN_RELAY_ALLOWLIST", raising=False)
    nostr.publish_announcement(
        bundle,
        seckey_hex=SECKEY,
        relays=None,
        transport=mem,
        approve=True,
        skip_consent_check=True,
    )
    assert len(mem.events) == 1

    found = nostr.discover_announcements(
        allowlist=[issuer],
        antigen_id="inj.nostr.001",
        transport=mem,
    )
    assert len(found) == 1
    assert found[0].antigen_id == "inj.nostr.001"
    assert found[0].issuer_pubkey == issuer


def test_cli_publish_rejects_filtered_empty_relay_list(issuer, monkeypatch):
    bundle = _signed_bundle(issuer)
    monkeypatch.setenv("SCP_ANTIGEN_RELAY_ALLOWLIST", "wss://allowed.example")
    out = nostr.publish_announcement(
        bundle,
        seckey_hex=SECKEY,
        relays=["wss://other.example"],
        approve=True,
        skip_consent_check=True,
    )
    assert out.get("published") is False
    assert out.get("reason") == "empty_relay_allowlist"


def test_parse_announcement_rejects_oversized_content_before_hash(monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_MAX_PAYLOAD_BYTES", "32")
    monkeypatch.setenv("SCP_QUARANTINE_MAX_CONTENT_BYTES", "32")
    event = {
        "id": "a" * 64,
        "pubkey": "b" * 64,
        "created_at": 1,
        "kind": nostr.ANTIGEN_NOSTR_KIND,
        "tags": [],
        "content": "x" * 20_000,
        "sig": "c" * 128,
    }

    def fail_compute_event_id(_event):
        raise AssertionError("oversized event must be rejected before hashing")

    monkeypatch.setattr(nostr, "compute_event_id", fail_compute_event_id)

    assert nostr.parse_announcement_event(event) is None


def test_websocket_subscribe_drops_oversized_event_frame(monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_MAX_PAYLOAD_BYTES", "32")
    monkeypatch.setenv("SCP_QUARANTINE_MAX_CONTENT_BYTES", "32")
    event = {
        "id": "a" * 64,
        "pubkey": "b" * 64,
        "created_at": 1,
        "kind": nostr.ANTIGEN_NOSTR_KIND,
        "tags": [],
        "content": "x" * 20_000,
        "sig": "c" * 128,
    }
    raw = json.dumps(["EVENT", "sub", event])
    conn = MagicMock()
    conn.recv.side_effect = [raw]

    class FakeWebSocket:
        @staticmethod
        def create_connection(_relay, timeout):
            return conn

    monkeypatch.setattr(nostr, "_require_websocket_client", lambda: FakeWebSocket)

    out = nostr.WebSocketRelayTransport().subscribe(
        [{"kinds": [nostr.ANTIGEN_NOSTR_KIND]}],
        relays=("wss://relay.example",),
        timeout_s=1.0,
    )

    assert out == []
    conn.close.assert_called_once()


def test_websocket_publish_rejects_oversized_ack(monkeypatch):
    monkeypatch.setenv("SCP_ANTIGEN_MAX_PAYLOAD_BYTES", "32")
    monkeypatch.setenv("SCP_QUARANTINE_MAX_CONTENT_BYTES", "32")
    conn = MagicMock()
    conn.recv.return_value = "x" * 20_000

    class FakeWebSocket:
        @staticmethod
        def create_connection(_relay, timeout):
            return conn

    monkeypatch.setattr(nostr, "_require_websocket_client", lambda: FakeWebSocket)

    with pytest.raises(RuntimeError, match="relay_response_too_large"):
        nostr.WebSocketRelayTransport().publish(
            {"kind": nostr.ANTIGEN_NOSTR_KIND},
            relays=("wss://relay.example",),
        )
    conn.close.assert_called_once()


def test_fetch_payload_hash_match(issuer):
    payload = {"patterns": _patterns()}
    bare = antigen.compute_payload_hash(payload)[7:]

    mock_resp = mock_json_response(payload)

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        got = nostr.fetch_payload(PAYLOAD_URL, bare)
    assert got == payload


def test_fetch_payload_hash_mismatch(issuer):
    payload = {"patterns": _patterns()}
    bare = antigen.compute_payload_hash(payload)[7:]
    tampered = {"patterns": _patterns()}
    tampered["patterns"][0]["severity"] = "low"

    mock_resp = mock_json_response(tampered)

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        with pytest.raises(nostr.FetchError, match="hash_mismatch"):
            nostr.fetch_payload(PAYLOAD_URL, bare)


def test_fetch_402_surfaces_metadata(issuer):
    bare = "a" * 64
    mock_resp = MagicMock()
    mock_resp.status_code = 402
    mock_resp.headers = {"WWW-Authenticate": "L402"}
    mock_resp.json.side_effect = ValueError("no json")
    mock_resp.close = MagicMock()

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        with pytest.raises(nostr.FetchError) as exc:
            nostr.fetch_payload(PAYLOAD_URL, bare)
    assert exc.value.reason == "payment_required"
    assert exc.value.l402 is not None
    assert exc.value.l402["status"] == 402
    mock_resp.close.assert_called_once()


def test_e2e_discover_fetch_import_quarantine_only(issuer):
    bundle = _signed_bundle(issuer)
    event = nostr.build_announcement_event(bundle, seckey_hex=SECKEY)
    mem = nostr.InMemoryRelayTransport()
    mem.publish(event, relays=("memory://",))

    announcements = nostr.discover_announcements(allowlist=[issuer], transport=mem)
    assert len(announcements) == 1

    payload = bundle["payload"]
    mock_resp = mock_json_response(payload)

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        res = nostr.import_from_announcement(announcements[0], allowlist=[issuer])

    assert res["accepted"] is True
    assert res["merged"] is False
    assert res["quarantine_id"]


def test_bundle_from_announcement_importable(issuer):
    bundle = _signed_bundle(issuer)
    event = nostr.build_announcement_event(bundle, seckey_hex=SECKEY)
    ann = nostr.parse_announcement_event(event)
    assert ann is not None
    rebuilt = nostr.bundle_from_announcement(ann, bundle["payload"])
    v = antigen.verify_bundle(rebuilt, allowlist=[issuer], require_signature=False)
    assert v["ok"] is True, v["errors"]


def test_publish_dry_run(issuer):
    bundle = _signed_bundle(issuer)
    out = nostr.publish_announcement(bundle, seckey_hex=SECKEY, relays=[], dry_run=True)
    assert out["dry_run"] is True
    assert out.get("signed") is False
    assert "sig" not in out["event"]
    assert "id" not in out["event"]
    assert out["published"] is False
    assert "event" in out


@pytest.mark.skipif(
    not os.getenv("SCP_ANTIGEN_NOSTR_INTEGRATION"),
    reason="set SCP_ANTIGEN_NOSTR_INTEGRATION=1 for live relay smoke",
)
def test_live_relay_publish_dry_run_only(issuer):
    bundle = _signed_bundle(issuer)
    out = nostr.publish_announcement(
        bundle,
        seckey_hex=SECKEY,
        relays=list(nostr.DEFAULT_RELAYS),
        dry_run=True,
    )
    assert out["dry_run"] is True
