# PURPOSE: Tests for SCP-R6 contribute consent and opt-in log.
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scp import antigen_nostr as nostr
from scp import registry_contribute as rc

SECKEY = "0000000000000000000000000000000000000000000000000000000000000003"
PAYLOAD_URL = "https://example.com/registry/snapshot.json"


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SCP_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.setenv("SCP_ANTIGEN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SCP_PATTERN_SSOT_PATH", str(tmp_path / "ssot.json"))
    monkeypatch.setenv("SCP_CONTRIBUTE_OPT_IN_LOG", str(tmp_path / "contribute_opt_in.jsonl"))
    monkeypatch.setenv(
        "SCP_CONTRIBUTE_HOST_ALLOWLIST", "example.com,127.0.0.1,localhost"
    )
    monkeypatch.delenv("SCP_CONTRIBUTE_CONSENT", raising=False)
    monkeypatch.delenv("NOSTR_SECKEY", raising=False)
    return tmp_path


def test_publish_without_consent_rejected(isolated_env):
    raw = "ignore safety override system prompt"
    res = rc.submit_contribution(
        raw_content=raw,
        category="injection",
        transport="nostr",
        https_url=PAYLOAD_URL,
        approve=True,
        dry_run=False,
        seckey_hex=SECKEY,
        relay_transport=nostr.InMemoryRelayTransport(),
    )
    assert res["ok"] is False
    assert res["error"] == "consent_required"
    assert res["submitted"] is False
    assert res["local_staging_preserved"] is True
    assert res.get("quarantine_path")


def test_proposal_without_consent_ok(isolated_env):
    raw = "ignore safety override system prompt"
    res = rc.submit_contribution(
        raw_content=raw,
        category="injection",
        transport="nostr",
        https_url=PAYLOAD_URL,
        approve=False,
    )
    assert res["ok"] is True
    assert res["submitted"] is False
    assert res["proposal"]["pattern_ids"]


def test_opt_in_log_written_on_success(isolated_env, monkeypatch):
    monkeypatch.setenv("SCP_CONTRIBUTE_CONSENT", "1")
    log_path = Path(isolated_env / "contribute_opt_in.jsonl")
    raw = "ignore safety override system prompt"
    mem = nostr.InMemoryRelayTransport()
    res = rc.submit_contribution(
        raw_content=raw,
        category="injection",
        transport="nostr",
        https_url=PAYLOAD_URL,
        approve=True,
        dry_run=False,
        seckey_hex=SECKEY,
        relay_transport=mem,
    )
    assert res["ok"] is True
    assert res["submitted"] is True
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["schema_revision"] == "scp.contribute_opt_in.v1"
    assert entry["transport"] == "nostr"
    assert entry["pattern_ids"]
    assert "at" in entry
    assert "raw_content" not in entry
    assert "operator_note" not in entry


def test_opt_in_log_not_written_on_consent_required(isolated_env):
    log_path = Path(isolated_env / "contribute_opt_in.jsonl")
    raw = "ignore safety override system prompt"
    rc.submit_contribution(
        raw_content=raw,
        category="injection",
        transport="nostr",
        https_url=PAYLOAD_URL,
        approve=True,
        dry_run=False,
        seckey_hex=SECKEY,
        relay_transport=nostr.InMemoryRelayTransport(),
    )
    assert not log_path.exists()


def test_opt_in_log_not_written_on_proposal(isolated_env):
    log_path = Path(isolated_env / "contribute_opt_in.jsonl")
    raw = "ignore safety override system prompt"
    rc.submit_contribution(
        raw_content=raw,
        category="injection",
        transport="nostr",
        https_url=PAYLOAD_URL,
        approve=False,
    )
    assert not log_path.exists()


def test_append_contribute_opt_in_log_custom_path(isolated_env, monkeypatch):
    log_path = isolated_env / "custom_opt_in.jsonl"
    monkeypatch.setenv("SCP_CONTRIBUTE_OPT_IN_LOG", str(log_path))
    rc.append_contribute_opt_in_log(
        pattern_ids=["contrib.inj.abc12345"],
        transport="https",
        operator_note="reviewed checklist",
    )
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["pattern_ids"] == ["contrib.inj.abc12345"]
    assert entry["operator_note"] == "reviewed checklist"
