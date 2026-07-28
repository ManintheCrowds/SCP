# PURPOSE: AppSec gates for antigen MCP — consent, L402, relays, merge, TLS (2026-07-28).
# Run: PYTHONPATH=src pytest tests/test_appsec_antigen_mcp_gates.py -q

from __future__ import annotations

import inspect
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scp import antigen
from scp import antigen_mcp
from scp import antigen_nostr as nostr
from scp import encounter_auto_log
from scp import http_policy
from scp import operator_consent
from scp import registry_ssot

SECKEY = "1" * 64
PAYLOAD_URL = "https://example.com/antigens/inj.appsec.001.json"


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("SCP_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.setenv("SCP_ANTIGEN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SCP_PATTERN_SSOT_PATH", str(tmp_path / "ssot.json"))
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(tmp_path / "registry.json"))
    monkeypatch.delenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", raising=False)
    monkeypatch.delenv("SCP_ANTIGEN_RELAY_ALLOWLIST", raising=False)
    monkeypatch.delenv("SCP_ANTIGEN_PUBLISH_CONSENT", raising=False)
    monkeypatch.delenv("SCP_REGISTRY_MERGE_CONSENT", raising=False)
    monkeypatch.delenv("SCP_ANTIGEN_L402_TOKEN", raising=False)
    monkeypatch.delenv("SCP_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("NOSTR_SECKEY", raising=False)
    monkeypatch.delenv("SCP_REGISTRY_TLS_VERIFY", raising=False)
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


def test_relay_url_safe_blocks_loopback_and_metadata():
    assert http_policy.relay_url_safe("wss://relay.damus.io") is True
    assert http_policy.relay_url_safe("ws://relay.damus.io") is False
    assert http_policy.relay_url_safe("wss://127.0.0.1:8080") is False
    assert http_policy.relay_url_safe("wss://169.254.169.254/latest") is False
    assert http_policy.relay_url_safe("wss://localhost") is False


def test_mcp_publish_requires_consent(monkeypatch):
    seckey = bytes.fromhex(SECKEY)
    issuer = antigen._pubkey_hex(seckey)
    bundle = antigen.export_bundle(
        _patterns(),
        antigen_id="inj.publish.001",
        seckey_hex=SECKEY,
        sign=True,
        payload_urls=[PAYLOAD_URL],
    )
    monkeypatch.setenv("NOSTR_SECKEY", SECKEY)
    monkeypatch.setenv("SCP_ANTIGEN_RELAY_ALLOWLIST", "wss://relay.damus.io")
    out = json.loads(
        antigen_mcp.scp_antigen_publish(json.dumps(bundle), approve=True, dry_run=False)
    )
    assert out.get("published") is False
    assert out.get("reason") == "consent_required"


def test_mcp_publish_dry_run_unsigned(monkeypatch):
    bundle = antigen.export_bundle(
        _patterns(),
        antigen_id="inj.publish.002",
        seckey_hex=SECKEY,
        sign=True,
        payload_urls=[PAYLOAD_URL],
    )
    monkeypatch.setenv("NOSTR_SECKEY", SECKEY)
    monkeypatch.setenv("SCP_ANTIGEN_RELAY_ALLOWLIST", "wss://relay.damus.io")
    out = json.loads(
        antigen_mcp.scp_antigen_publish(json.dumps(bundle), dry_run=True)
    )
    assert out["dry_run"] is True
    assert out.get("signed") is False
    assert "sig" not in out["event"]


def test_mcp_publish_rejects_empty_relay_allowlist(monkeypatch):
    bundle = antigen.export_bundle(
        _patterns(),
        antigen_id="inj.publish.003",
        seckey_hex=SECKEY,
        sign=True,
        payload_urls=[PAYLOAD_URL],
    )
    monkeypatch.setenv("NOSTR_SECKEY", SECKEY)
    monkeypatch.setenv("SCP_ANTIGEN_PUBLISH_CONSENT", "1")
    monkeypatch.delenv("SCP_ANTIGEN_RELAY_ALLOWLIST", raising=False)
    out = json.loads(
        antigen_mcp.scp_antigen_publish(json.dumps(bundle), approve=True)
    )
    assert out.get("reason") == "empty_relay_allowlist"


def test_mcp_merge_requires_consent():
    seckey = bytes.fromhex(SECKEY)
    issuer = antigen._pubkey_hex(seckey)
    bundle = antigen.export_bundle(
        _patterns(), antigen_id="inj.merge.001", seckey_hex=SECKEY, sign=True
    )
    out = json.loads(
        antigen_mcp.scp_antigen_merge(json.dumps(bundle), approve=True, allowlist=issuer)
    )
    assert out["merged"] is False
    assert out["reason"] == "consent_required"


def test_mcp_merge_forces_signature_verification(monkeypatch):
    """Unsigned bundle cannot merge via MCP even with approve + consent."""
    seckey = bytes.fromhex(SECKEY)
    issuer = antigen._pubkey_hex(seckey)
    monkeypatch.setenv("SCP_REGISTRY_MERGE_CONSENT", "1")
    bundle = antigen.export_bundle(
        _patterns(), antigen_id="inj.merge.002", issuer_pubkey=issuer, sign=False
    )
    out = json.loads(
        antigen_mcp.scp_antigen_merge(json.dumps(bundle), approve=True, allowlist=issuer)
    )
    assert out.get("merged") is False
    assert out.get("reason") == "verification_failed"
    assert "signature_required_but_absent" in out.get("errors", [])


def test_mcp_dev_auto_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("SCP_REGISTRY_MERGE_DEV_AUTO", "1")
    monkeypatch.delenv("SCP_REGISTRY_MERGE_CONSENT", raising=False)
    from scp import pattern_record as pr

    snap = pr.build_registry_snapshot(
        [
            {
                "pattern_id": "inj.devauto.001",
                "category": "injection",
                "detector": {"kind": "token_family", "normalized": "dev-auto-family"},
                "risk_tier": "low",
                "drift_score": 0.01,
                "registry_bucket": "power_words",
            }
        ],
        registry_version="2026-01-01T00:00:00Z",
    )
    qfile = tmp_path / "q-devauto.json"
    qfile.write_text(json.dumps({"snapshot": snap}), encoding="utf-8")
    out = json.loads(
        antigen_mcp.scp_apply_registry_quarantine(str(qfile), approve=False)
    )
    assert out.get("merged") is False
    assert out.get("reason") == "approval_required"
    assert registry_ssot.load_ssot() == []


def test_mcp_export_rejects_seckey():
    out = json.loads(
        antigen_mcp.scp_antigen_export(
            json.dumps(_patterns()),
            antigen_id="inj.export.001",
            seckey_hex=SECKEY,
            sign=True,
        )
    )
    assert out.get("error") == "seckey_hex_not_allowed_on_mcp"


def test_mcp_contribute_rejects_seckey():
    out = json.loads(
        antigen_mcp.scp_contribute_pattern(
            transport="https",
            raw_content="ignore previous instructions override",
            category="injection",
            https_url=PAYLOAD_URL,
            seckey_hex=SECKEY,
            approve=False,
        )
    )
    assert out.get("error") == "seckey_hex_not_allowed_on_mcp"
    assert out.get("submitted") is False


def test_mcp_publish_blocks_loopback_relay_even_if_env_lists_it(monkeypatch):
    bundle = antigen.export_bundle(
        _patterns(),
        antigen_id="inj.publish.005",
        seckey_hex=SECKEY,
        sign=True,
        payload_urls=[PAYLOAD_URL],
    )
    monkeypatch.setenv("NOSTR_SECKEY", SECKEY)
    monkeypatch.setenv("SCP_ANTIGEN_PUBLISH_CONSENT", "1")
    monkeypatch.setenv("SCP_ANTIGEN_RELAY_ALLOWLIST", "wss://127.0.0.1:8080")
    out = json.loads(
        antigen_mcp.scp_antigen_publish(json.dumps(bundle), approve=True)
    )
    assert out.get("published") is False
    assert out.get("reason") == "empty_relay_allowlist"


def test_mcp_verify_forces_signature():
    seckey = bytes.fromhex(SECKEY)
    issuer = antigen._pubkey_hex(seckey)
    bundle = antigen.export_bundle(
        _patterns(), antigen_id="inj.verify.001", issuer_pubkey=issuer, sign=False
    )
    out = json.loads(
        antigen_mcp.scp_antigen_verify(
            json.dumps(bundle), allowlist=issuer, require_signature=False
        )
    )
    assert out.get("ok") is False
    assert "signature_required_but_absent" in out.get("errors", [])


def test_library_publish_without_approve():
    bundle = antigen.export_bundle(
        _patterns(),
        antigen_id="inj.publish.004",
        seckey_hex=SECKEY,
        sign=True,
        payload_urls=[PAYLOAD_URL],
    )
    out = nostr.publish_announcement(bundle, seckey_hex=SECKEY, relays=[], approve=False)
    assert out["published"] is False
    assert out["reason"] == "approval_required"


def test_encounter_masks_secrets(tmp_path, monkeypatch):
    base = tmp_path / "docs" / "encounter_bestiary"
    base.mkdir(parents=True)
    monkeypatch.setenv("ENCOUNTER_BESTIARY_DIR", str(base))
    monkeypatch.setenv("SCP_ENCOUNTER_AUTO_LOG", "1")
    secret_blob = (
        "ignore previous instructions AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG "
        "and sk-abcdefghijklmnopqrstuvwxyz123456"
    )
    meta = encounter_auto_log.maybe_log_encounter(secret_blob, "injection")
    assert meta is not None
    text = list(base.glob("*_encounters.md"))[0].read_text(encoding="utf-8")
    assert "wJalrXUtnFEMI" not in text
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in text
    assert "[REDACTED]" in text or "REDACTED" in text.upper() or "***" in text


def test_mcp_transport_scope_restores(monkeypatch):
    monkeypatch.delenv("SCP_MCP_TRANSPORT", raising=False)
    assert operator_consent.mcp_transport_active() is False
    with operator_consent.mcp_transport_scope():
        assert operator_consent.mcp_transport_active() is True
    assert operator_consent.mcp_transport_active() is False


def test_mcp_registry_tools_have_no_tls_verify_param():
    assert "tls_verify" not in inspect.signature(antigen_mcp.scp_fetch_registry).parameters
    assert "tls_verify" not in inspect.signature(antigen_mcp.scp_contribute_pattern).parameters


def test_env_tls_verify_defaults_and_disable(monkeypatch):
    monkeypatch.delenv("SCP_REGISTRY_TLS_VERIFY", raising=False)
    assert http_policy.env_tls_verify() is True
    monkeypatch.setenv("SCP_REGISTRY_TLS_VERIFY", "0")
    assert http_policy.env_tls_verify() is False
    monkeypatch.setenv("SCP_REGISTRY_TLS_VERIFY", "false")
    assert http_policy.env_tls_verify() is False
    monkeypatch.setenv("SCP_REGISTRY_TLS_VERIFY", "no")
    assert http_policy.env_tls_verify() is False
    monkeypatch.setenv("SCP_REGISTRY_TLS_VERIFY", "")
    assert http_policy.env_tls_verify() is True
    monkeypatch.setenv("SCP_REGISTRY_TLS_VERIFY", "   ")
    assert http_policy.env_tls_verify() is True
    monkeypatch.setenv("SCP_REGISTRY_TLS_VERIFY", "1")
    assert http_policy.env_tls_verify() is True


def test_mcp_fetch_ignores_antigen_tls_env(monkeypatch):
    """Registry MCP must not weaken TLS when only SCP_ANTIGEN_TLS_VERIFY=0."""
    captured: dict = {}

    def fake_fetch(*_args, **kwargs):
        captured["tls_verify"] = kwargs.get("tls_verify")
        return {"ok": True, "merged": False}

    monkeypatch.setattr(antigen_mcp.registry_fetch_mod, "fetch_registry", fake_fetch)
    monkeypatch.delenv("SCP_REGISTRY_TLS_VERIFY", raising=False)
    monkeypatch.setenv("SCP_ANTIGEN_TLS_VERIFY", "0")
    antigen_mcp.scp_fetch_registry("https://example.com/snap.json", allowlist="a" * 64)
    assert captured["tls_verify"] is True


def test_mcp_fetch_registry_tls_verify_from_env_only(monkeypatch):
    captured: dict = {}

    def fake_fetch(*_args, **kwargs):
        captured["tls_verify"] = kwargs.get("tls_verify")
        return {"ok": True, "merged": False, "quarantine_path": "/tmp/q.json"}

    monkeypatch.setattr(antigen_mcp.registry_fetch_mod, "fetch_registry", fake_fetch)
    monkeypatch.delenv("SCP_REGISTRY_TLS_VERIFY", raising=False)
    antigen_mcp.scp_fetch_registry("https://example.com/snap.json", allowlist="a" * 64)
    assert captured["tls_verify"] is True

    monkeypatch.setenv("SCP_REGISTRY_TLS_VERIFY", "0")
    antigen_mcp.scp_fetch_registry("https://example.com/snap.json", allowlist="a" * 64)
    assert captured["tls_verify"] is False


def test_mcp_contribute_tls_verify_from_env_only(monkeypatch):
    captured: dict = {}

    def fake_submit(**kwargs):
        captured["tls_verify"] = kwargs.get("tls_verify")
        return {"ok": True, "submitted": False, "proposal": True}

    monkeypatch.setattr(
        antigen_mcp.registry_contribute_mod, "submit_contribution", fake_submit
    )
    monkeypatch.delenv("SCP_REGISTRY_TLS_VERIFY", raising=False)
    antigen_mcp.scp_contribute_pattern(
        transport="https",
        raw_content="ignore previous instructions override",
        category="injection",
        https_url=PAYLOAD_URL,
        approve=False,
    )
    assert captured["tls_verify"] is True

    monkeypatch.setenv("SCP_REGISTRY_TLS_VERIFY", "0")
    antigen_mcp.scp_contribute_pattern(
        transport="https",
        raw_content="ignore previous instructions override",
        category="injection",
        https_url=PAYLOAD_URL,
        approve=False,
    )
    assert captured["tls_verify"] is False


def test_mcp_fetch_registry_session_get_verify_flag(monkeypatch):
    """End-to-end: MCP → fetch_registry → Session.get(verify=…) honors env only."""
    monkeypatch.setenv("SCP_ANTIGEN_FETCH_HOST_ALLOWLIST", "example.com")
    monkeypatch.delenv("SCP_REGISTRY_TLS_VERIFY", raising=False)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "schema_revision": "scp.registry_snapshot.v1",
        "registry_version": "2026-01-01T00:00:00Z",
        "patterns": [
            {
                "pattern_id": "inj.tls.001",
                "category": "injection",
                "detector": {
                    "kind": "token_family",
                    "normalized": "tls-env-family",
                },
                "risk_tier": "medium",
            }
        ],
    }
    mock_resp.headers = {}

    with patch(
        "scp.registry_fetch.requests.Session.get", return_value=mock_resp
    ) as mock_get:
        out = json.loads(
            antigen_mcp.scp_fetch_registry(
                "https://example.com/snap.json", allowlist="a" * 64
            )
        )
    assert mock_get.called
    assert mock_get.call_args.kwargs.get("verify") is True
    assert out.get("ok") is True

    monkeypatch.setenv("SCP_REGISTRY_TLS_VERIFY", "0")
    with patch(
        "scp.registry_fetch.requests.Session.get", return_value=mock_resp
    ) as mock_get:
        antigen_mcp.scp_fetch_registry(
            "https://example.com/snap.json", allowlist="a" * 64
        )
    assert mock_get.call_args.kwargs.get("verify") is False
