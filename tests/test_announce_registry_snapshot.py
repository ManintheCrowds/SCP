# PURPOSE: Tests for announce_registry_snapshot CLI (dry-run, no live relays).
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from announce_registry_snapshot import announce_snapshot  # noqa: E402

from scp import antigen
from scp import antigen_nostr as nostr
from scp import pattern_record as pr

SECKEY = "0000000000000000000000000000000000000000000000000000000000000003"
PAYLOAD_URL = "https://example.com/snapshots/v0.1.0/registry.json"


def _minimal_snapshot() -> dict:
    rec = {
        "pattern_id": "legacy.power_words.abc12345",
        "category": "injection",
        "detector": {"kind": "token_family", "normalized": "injection-family-abc12345"},
        "risk_tier": "medium",
        "registry_bucket": "power_words",
    }
    return pr.build_registry_snapshot([rec], registry_version="2026-01-01T00:00:00Z")


def test_announce_snapshot_dry_run_returns_pubkey_unsigned():
    snapshot = _minimal_snapshot()
    session = MagicMock()
    session.get.return_value = MagicMock(
        status_code=200,
        text=json.dumps(snapshot),
    )
    session.get.return_value.json.return_value = snapshot
    session.get.return_value.raise_for_status = MagicMock()

    result = announce_snapshot(
        payload_url=PAYLOAD_URL,
        version="0.1.0",
        seckey_hex=SECKEY,
        dry_run=True,
        session=session,
    )

    expected_pubkey = antigen._pubkey_hex(bytes.fromhex(SECKEY))
    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["signed"] is False
    assert result["issuer_pubkey"] == expected_pubkey
    assert result["event_id"] == ""
    assert result["published"] is False
    assert result["pattern_count"] == 1
    session.get.assert_called_once_with(PAYLOAD_URL, timeout=30)


def test_announce_snapshot_publish_uses_relay_transport():
    snapshot = _minimal_snapshot()
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200)
    session.get.return_value.json.return_value = snapshot
    session.get.return_value.raise_for_status = MagicMock()
    mem = nostr.InMemoryRelayTransport()

    result = announce_snapshot(
        payload_url=PAYLOAD_URL,
        version="0.1.0",
        seckey_hex=SECKEY,
        dry_run=False,
        relay_transport=mem,
        session=session,
    )

    assert result["ok"] is True
    assert result["published"] is True
    assert len(mem.events) == 1


def test_announce_snapshot_rejects_bad_schema():
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200)
    session.get.return_value.json.return_value = {"schema_revision": "wrong", "patterns": []}
    session.get.return_value.raise_for_status = MagicMock()

    with pytest.raises(SystemExit):
        announce_snapshot(
            payload_url=PAYLOAD_URL,
            version="0.1.0",
            seckey_hex=SECKEY,
            dry_run=True,
            session=session,
        )
