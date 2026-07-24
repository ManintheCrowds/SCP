# PURPOSE: Eval suite for SCP-ANT1 Antigen P0 (export/verify/import/merge). Doubles as the
#   autoresearch ratchet eval for src/scp/antigen.py.
# Run: pytest tests/test_antigen_p0.py  (bare install OK; coincurve/jsonschema optional)

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scp import antigen, scp_utils, antigen_cli

# Deterministic test key (secret = 3), in range 1..n-1.
SECKEY = "0000000000000000000000000000000000000000000000000000000000000003"


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
    """Isolate quarantine dir, audit log, and registry to tmp_path."""
    monkeypatch.setenv("SCP_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.setenv("SCP_ANTIGEN_AUDIT_LOG", str(tmp_path / "antigen_audit.jsonl"))
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(tmp_path / "registry.json"))
    monkeypatch.setenv("SCP_REGISTRY_MERGE_CONSENT", "1")
    monkeypatch.delenv("SCP_ANTIGEN_ISSUER_ALLOWLIST", raising=False)
    monkeypatch.delenv("SCP_ANTIGEN_ALLOWLIST_FILE", raising=False)
    return tmp_path


# --------------------------------------------------------------------------- happy path

def test_export_signed_roundtrip_accepted(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.001", seckey_hex=SECKEY, sign=True)
    assert bundle["manifest"]["issuer_pubkey"] == issuer
    assert bundle["manifest"]["payload_content_hash"].startswith("sha256:")
    assert bundle["manifest"]["signature"]["alg"] == "schnorr-secp256k1"

    v = antigen.verify_bundle(bundle, allowlist=[issuer])
    assert v["ok"] is True, v["errors"]

    res = antigen.import_bundle(bundle, allowlist=[issuer])
    assert res["accepted"] is True
    assert res["merged"] is False
    assert res["quarantine_id"]


def test_unsigned_bundle_rejected_by_default_accepted_only_with_optout(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.002", issuer_pubkey=issuer)
    # Fail-safe default: no signature -> rejected (P0 has no transport auth).
    v_default = antigen.verify_bundle(bundle, allowlist=[issuer])
    assert v_default["ok"] is False
    assert "signature_required_but_absent" in v_default["errors"]
    # Explicit opt-out (authenticated channel) accepts.
    v_optout = antigen.verify_bundle(bundle, allowlist=[issuer], require_signature=False)
    assert v_optout["ok"] is True, v_optout["errors"]


# --------------------------------------------------------------------------- auto-reject rules (spec 11.4)

def test_hash_mismatch_rejected(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.003", issuer_pubkey=issuer)
    bundle["payload"]["patterns"][0]["severity"] = "low"  # tamper after hashing
    v = antigen.verify_bundle(bundle, allowlist=[issuer], require_signature=False)
    assert v["ok"] is False
    assert "hash_mismatch" in v["errors"]


def test_invalid_signature_rejected(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.004", seckey_hex=SECKEY, sign=True)
    sig = bundle["manifest"]["signature"]["sig"]
    bundle["manifest"]["signature"]["sig"] = ("f" if sig[0] != "f" else "e") + sig[1:]
    v = antigen.verify_bundle(bundle, allowlist=[issuer])
    assert v["ok"] is False
    assert "invalid_signature" in v["errors"]


def test_off_allowlist_rejected(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.005", issuer_pubkey=issuer)
    v = antigen.verify_bundle(bundle, allowlist=["deadbeef" * 8], require_signature=False)
    assert v["ok"] is False
    assert "issuer_not_on_allowlist" in v["errors"]


def test_empty_allowlist_fails_closed(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.006", issuer_pubkey=issuer)
    v = antigen.verify_bundle(bundle, allowlist=[], require_signature=False)
    assert v["ok"] is False
    assert "issuer_not_on_allowlist" in v["errors"]


def test_unsupported_schema_revision_rejected(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.007", issuer_pubkey=issuer)
    bundle["manifest"]["schema_revision"] = "scp.pattern_bundle.v9"
    v = antigen.verify_bundle(bundle, allowlist=[issuer], require_signature=False)
    assert v["ok"] is False
    assert "unsupported_schema_revision" in v["errors"]


def test_unsupported_payload_format_rejected(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.008", issuer_pubkey=issuer)
    bundle["manifest"]["payload_format"] = "application/gzip"  # deferred to P1+
    v = antigen.verify_bundle(bundle, allowlist=[issuer], require_signature=False)
    assert v["ok"] is False
    assert "unsupported_payload_format" in v["errors"]


def test_oversize_payload_rejected(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.009", issuer_pubkey=issuer)
    v = antigen.verify_bundle(bundle, allowlist=[issuer], max_payload_bytes=10, require_signature=False)
    assert v["ok"] is False
    assert "payload_over_size_cap" in v["errors"]


def test_prohibited_key_rejected(issuer):
    payload = {"patterns": _patterns(), "raw_log": "victim said ..."}  # disallowed (D invariant)
    bundle = {
        "manifest": {
            "schema_revision": "scp.pattern_bundle.v0",
            "antigen_id": "inj.set.010",
            "issuer_pubkey": issuer,
            "issued_at": "2026-06-29T00:00:00Z",
            "payload_content_hash": antigen.compute_payload_hash(payload),
            "payload_format": "application/json",
        },
        "payload": payload,
    }
    v = antigen.verify_bundle(bundle, allowlist=[issuer], require_signature=False)
    assert v["ok"] is False
    assert "prohibited_key" in v["errors"]


def test_pii_email_in_payload_rejected(issuer):
    patterns = _patterns()
    patterns[0]["detector"]["normalized"] = "contact victim@example.com for the exploit"
    payload = {"patterns": patterns}
    bundle = {
        "manifest": {
            "schema_revision": "scp.pattern_bundle.v0",
            "antigen_id": "inj.set.011",
            "issuer_pubkey": issuer,
            "issued_at": "2026-06-29T00:00:00Z",
            "payload_content_hash": antigen.compute_payload_hash(payload),
            "payload_format": "application/json",
        },
        "payload": payload,
    }
    v = antigen.verify_bundle(bundle, allowlist=[issuer], require_signature=False)
    assert v["ok"] is False
    assert "pii_email_in_payload" in v["errors"]


def test_require_signature_absent_rejected(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.012", issuer_pubkey=issuer)
    v = antigen.verify_bundle(bundle, allowlist=[issuer], require_signature=True)
    assert v["ok"] is False
    assert "signature_required_but_absent" in v["errors"]


# --------------------------------------------------------------------------- quarantine + merge gate

def test_quarantine_before_merge(issuer):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.013", seckey_hex=SECKEY, sign=True)
    res = antigen.import_bundle(bundle, allowlist=[issuer])
    assert res["accepted"] is True
    entries = scp_utils.list_quarantine()
    assert any(e["quarantine_id"] == res["quarantine_id"] for e in entries)


def test_no_auto_merge_then_gated_merge(issuer, isolated_env):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.014", seckey_hex=SECKEY, sign=True)

    # import never merges
    res = antigen.import_bundle(bundle, allowlist=[issuer])
    assert res["merged"] is False

    # merge without approval = proposal only
    prop = antigen.merge_to_registry(bundle, approve=False, allowlist=[issuer])
    assert prop["merged"] is False
    assert prop["reason"] == "approval_required"

    registry_path = isolated_env / "registry.json"
    assert not registry_path.exists()  # nothing written yet

    # approved merge writes only the imported_antigens namespace
    done = antigen.merge_to_registry(bundle, approve=True, allowlist=[issuer])
    assert done["merged"] is True
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    assert "imported_antigens" in data
    assert data["imported_antigens"][0]["antigen_id"] == "inj.set.014"


def test_merge_is_idempotent(issuer, isolated_env):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.015", seckey_hex=SECKEY, sign=True)
    antigen.merge_to_registry(bundle, approve=True, allowlist=[issuer])
    antigen.merge_to_registry(bundle, approve=True, allowlist=[issuer])
    data = json.loads((isolated_env / "registry.json").read_text(encoding="utf-8"))
    keys = [e["key"] for e in data["imported_antigens"]]
    assert len(keys) == len(set(keys)) == 1  # replaced, not duplicated


def test_rejected_import_logs_hash_only_no_quarantine(issuer, isolated_env):
    bundle = antigen.export_bundle(_patterns(), antigen_id="inj.set.016", issuer_pubkey=issuer)
    res = antigen.import_bundle(bundle, allowlist=["deadbeef" * 8])  # off-allowlist -> reject
    assert res["rejected"] is True

    # No content quarantined on reject.
    assert scp_utils.list_quarantine() == []

    # Audit logged the hash only, no payload content.
    audit = (isolated_env / "antigen_audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    rejected = [json.loads(line) for line in audit if json.loads(line)["event"] == "import_rejected"]
    assert rejected and rejected[-1]["payload_hash"] == res["payload_hash"]
    assert "patterns" not in audit[-1]  # no payload body in the log line


def test_reject_reasons_carry_no_payload_content(issuer, isolated_env):
    # Oversized 'notes' with hazardous-looking text: must be rejected WITHOUT echoing the body
    # into errors/audit (the jsonschema maxLength message would otherwise leak it).
    secret_body = "TOPSECRET_VICTIM_DATA_" + ("x" * 3000)
    payload = {"patterns": _patterns(), "notes": secret_body}
    bundle = {
        "manifest": {
            "schema_revision": "scp.pattern_bundle.v0",
            "antigen_id": "inj.set.017",
            "issuer_pubkey": issuer,
            "issued_at": "2026-06-29T00:00:00Z",
            "payload_content_hash": antigen.compute_payload_hash(payload),
            "payload_format": "application/json",
        },
        "payload": payload,
    }
    res = antigen.import_bundle(bundle, allowlist=[issuer], require_signature=False)
    assert res["rejected"] is True
    assert "notes_too_long" in res["reasons"]

    errors_blob = json.dumps(res["reasons"])
    assert "TOPSECRET" not in errors_blob
    assert secret_body[:40] not in errors_blob

    audit = (isolated_env / "antigen_audit.jsonl").read_text(encoding="utf-8")
    assert "TOPSECRET" not in audit  # no payload-derived content reached the log


# --------------------------------------------------------------------------- CLI smoke

def test_cli_export_verify_roundtrip(issuer, tmp_path, capsys):
    patterns_file = tmp_path / "patterns.json"
    patterns_file.write_text(json.dumps(_patterns()), encoding="utf-8")
    bundle_file = tmp_path / "bundle.json"

    rc = antigen_cli.main([
        "export", "--antigen-id", "inj.cli.001", "--patterns-file", str(patterns_file),
        "--seckey-hex", SECKEY, "--sign", "--out", str(bundle_file),
    ])
    assert rc == 0
    assert bundle_file.exists()

    capsys.readouterr()
    rc = antigen_cli.main(["verify", "--bundle", str(bundle_file), "--allowlist", issuer])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True, out["errors"]
