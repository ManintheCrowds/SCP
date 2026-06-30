# PURPOSE: Eval suite for SCP-ANT1 Antigen P1b (L402 payment retry on HTTPS fetch).
# Run: pytest tests/test_antigen_p1b_l402.py

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scp import antigen, antigen_cli, antigen_l402 as l402, antigen_mcp, antigen_nostr as nostr

SECKEY = "0000000000000000000000000000000000000000000000000000000000000003"
PAYLOAD_URL = "https://example.com/antigens/inj.l402.001.json"
MACAROON = "AgEDbm9kZUBsb2NhbA"
PREIMAGE = "b" * 64
INVOICE = "lnbc100n1pjexample"
WWW_AUTH = f'L402 macaroon="{MACAROON}", invoice="{INVOICE}"'
TOKEN = f"{MACAROON}:{PREIMAGE}"


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
    monkeypatch.delenv("SCP_ANTIGEN_L402_TOKEN", raising=False)
    return tmp_path


def _signed_bundle(issuer: str, antigen_id: str = "inj.l402.001") -> dict:
    return antigen.export_bundle(
        _patterns(),
        antigen_id=antigen_id,
        issuer_pubkey=issuer,
        seckey_hex=SECKEY,
        sign=True,
        payload_urls=[PAYLOAD_URL],
    )


def _audit_events(tmp_path: Path) -> list[dict]:
    log = tmp_path / "antigen_audit.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_parse_www_authenticate_l402():
    parsed = l402.parse_www_authenticate_l402(WWW_AUTH)
    assert parsed is not None
    assert parsed["macaroon"] == MACAROON
    assert parsed["invoice"] == INVOICE
    assert parsed["invoice_hint"] == INVOICE[:16]


def test_normalize_l402_token():
    mac, pre = l402.normalize_l402_token(TOKEN)
    assert mac == MACAROON
    assert pre == PREIMAGE
    mac2, pre2 = l402.normalize_l402_token(f"L402 {TOKEN}")
    assert mac2 == MACAROON
    assert pre2 == PREIMAGE


def test_format_authorization_header():
    assert l402.format_authorization_header(MACAROON, PREIMAGE) == f"L402 {TOKEN}"


def test_fetch_402_enriched_metadata():
    bare = "a" * 64
    mock_resp = MagicMock()
    mock_resp.status_code = 402
    mock_resp.headers = {"WWW-Authenticate": WWW_AUTH}

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        with pytest.raises(nostr.FetchError) as exc:
            nostr.fetch_payload(PAYLOAD_URL, bare)
    assert exc.value.reason == "payment_required"
    assert exc.value.l402 is not None
    assert exc.value.l402["macaroon"] == MACAROON
    assert exc.value.l402["invoice"] == INVOICE


def test_fetch_l402_token_retry_200(issuer):
    bundle = _signed_bundle(issuer)
    bare = antigen.compute_payload_hash(bundle["payload"])[7:]
    body = bundle["payload"]

    mock_402 = MagicMock()
    mock_402.status_code = 402
    mock_402.headers = {"WWW-Authenticate": WWW_AUTH}

    mock_200 = MagicMock()
    mock_200.status_code = 200
    mock_200.json.return_value = body

    def _get(url, timeout=30, headers=None):
        if headers and headers.get("Authorization", "").startswith("L402 "):
            return mock_200
        return mock_402

    with patch("scp.antigen_nostr.requests.Session.get", side_effect=_get):
        payload = nostr.fetch_payload(PAYLOAD_URL, bare, l402_token=TOKEN)
    assert payload == bundle["payload"]


def test_parse_www_authenticate_l402_unquoted():
    header = f"L402 macaroon={MACAROON}, invoice={INVOICE}"
    parsed = l402.parse_www_authenticate_l402(header)
    assert parsed is not None
    assert parsed["macaroon"] == MACAROON
    assert parsed["invoice"] == INVOICE


def test_parse_www_authenticate_l402_non_l402_returns_none():
    assert l402.parse_www_authenticate_l402("Bearer token123") is None
    assert l402.parse_www_authenticate_l402("") is None
    assert l402.parse_www_authenticate_l402("L402") is None


def test_parse_www_authenticate_l402_partial_fields():
    mac_only = l402.parse_www_authenticate_l402(f'L402 macaroon="{MACAROON}"')
    assert mac_only is not None
    assert mac_only["macaroon"] == MACAROON
    assert mac_only["invoice"] is None


def test_normalize_l402_token_invalid():
    with pytest.raises(ValueError, match="empty_l402_token"):
        l402.normalize_l402_token("")
    with pytest.raises(ValueError, match="macaroon_colon_preimage"):
        l402.normalize_l402_token("no-colon-here")


def test_fetch_invalid_l402_token_raises_fetch_error():
    bare = "a" * 64
    with pytest.raises(nostr.FetchError, match="invalid_l402_token"):
        nostr.fetch_payload(PAYLOAD_URL, bare, l402_token="bad-token")


def test_fetch_l402_token_still_402_audits_retry_failed(tmp_path: Path):
    bare = "a" * 64
    mock_resp = MagicMock()
    mock_resp.status_code = 402
    mock_resp.headers = {"WWW-Authenticate": WWW_AUTH}

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        with pytest.raises(nostr.FetchError) as exc:
            nostr.fetch_payload(PAYLOAD_URL, bare, l402_token=TOKEN)
    assert exc.value.reason == "payment_required"
    types = [e["event"] for e in _audit_events(tmp_path)]
    assert "fetch_l402_retry_failed" in types
    assert "fetch_l402_retry" not in types


def test_mcp_antigen_fetch_402_json():
    bare = "a" * 64
    mock_resp = MagicMock()
    mock_resp.status_code = 402
    mock_resp.headers = {"WWW-Authenticate": WWW_AUTH}

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        raw = antigen_mcp.scp_antigen_fetch(PAYLOAD_URL, bare)
    out = json.loads(raw)
    assert out["ok"] is False
    assert out["status"] == 402
    assert out["l402"]["macaroon"] == MACAROON
    assert out["l402"]["invoice"] == INVOICE
    assert PREIMAGE not in raw


def test_mcp_antigen_fetch_invalid_token():
    bare = "a" * 64
    raw = antigen_mcp.scp_antigen_fetch(PAYLOAD_URL, bare, l402_token="not-valid")
    out = json.loads(raw)
    assert out["ok"] is False
    assert out["error"] == "invalid_l402_token"


def test_cli_fetch_402_json(capsys):
    bare = "a" * 64
    mock_resp = MagicMock()
    mock_resp.status_code = 402
    mock_resp.headers = {"WWW-Authenticate": WWW_AUTH}

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        rc = antigen_cli.main(["fetch", PAYLOAD_URL, "--hash", bare])
    assert rc == 2
    captured = capsys.readouterr()
    out = json.loads(captured.out)
    assert out["ok"] is False
    assert out["status"] == 402
    assert out["l402"]["macaroon"] == MACAROON
    assert PREIMAGE not in captured.out


def test_import_from_announcement_paid_quarantine_only(issuer, tmp_path: Path):
    bundle = _signed_bundle(issuer)
    event = nostr.build_announcement_event(bundle, seckey_hex=SECKEY)
    ann = nostr.parse_announcement_event(event)
    assert ann is not None
    bare = antigen.compute_payload_hash(bundle["payload"])[7:]

    mock_200 = MagicMock()
    mock_200.status_code = 200
    mock_200.json.return_value = bundle["payload"]

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_200):
        result = nostr.import_from_announcement(ann, allowlist=[issuer], l402_token=TOKEN)

    assert result.get("accepted") is True
    assert result.get("rejected") is not True
    assert result.get("merged") is False
    assert result.get("merge_proposal", {}).get("auto_merge") is False
    assert "quarantine_id" in result
    events = _audit_events(tmp_path)
    event_types = [e["event"] for e in events]
    assert "fetch_l402_retry" in event_types
    assert "fetch_ok" in event_types
    assert "import_accepted" in event_types
    for e in events:
        blob = json.dumps(e)
        assert PREIMAGE not in blob
        assert MACAROON not in blob


def test_audit_challenge_no_secrets(tmp_path: Path):
    bare = "c" * 64
    mock_resp = MagicMock()
    mock_resp.status_code = 402
    mock_resp.headers = {"WWW-Authenticate": WWW_AUTH}

    with patch("scp.antigen_nostr.requests.Session.get", return_value=mock_resp):
        with pytest.raises(nostr.FetchError):
            nostr.fetch_payload(PAYLOAD_URL, bare, antigen_id="inj.l402.001")

    events = _audit_events(tmp_path)
    challenge = [e for e in events if e.get("event") == "fetch_l402_challenge"]
    assert len(challenge) == 1
    assert challenge[0].get("invoice_hint") == INVOICE[:16]
    assert MACAROON not in json.dumps(challenge[0])
