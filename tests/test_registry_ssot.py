# PURPOSE: Tests for SCP-R4 SSOT store, diff, and merge gates.
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scp import pattern_record as pr
from scp import registry_ssot


def _rec(pid: str, *, tier: str = "low", drift: float = 0.05, norm: str = "token-a") -> dict:
    return {
        "pattern_id": pid,
        "category": "injection",
        "detector": {"kind": "token_family", "normalized": norm},
        "risk_tier": tier,
        "drift_score": drift,
    }


@pytest.fixture(autouse=True)
def isolated_ssot(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SCP_PATTERN_SSOT_PATH", str(tmp_path / "ssot.json"))
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(tmp_path / "projection.json"))
    monkeypatch.setenv("SCP_ANTIGEN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SCP_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.delenv("SCP_REGISTRY_MERGE_DEV_AUTO", raising=False)
    return tmp_path


def test_diff_add_and_conflict():
    registry_ssot.save_ssot([_rec("existing.001", norm="local-token")])
    remote = [_rec("existing.001", norm="remote-token"), _rec("new.001")]
    d = registry_ssot.diff_snapshot(remote)
    assert d["add_count"] == 1
    assert d["conflict_count"] == 1


def test_apply_merge_requires_approve(isolated_ssot):
    snap = {
        "schema_revision": pr.REGISTRY_SNAPSHOT_REVISION,
        "registry_version": "2026-07-02T00:00:00Z",
        "patterns": [_rec("merge.001")],
    }
    root = isolated_ssot
    qfile = root / "q.json"
    qfile.write_text(json.dumps({"snapshot": snap}), encoding="utf-8")

    res = registry_ssot.apply_merge(qfile, approve=False)
    assert res["merged"] is False
    assert res["reason"] == "approval_required"


def test_apply_merge_operator_approved(isolated_ssot):
    snap = {
        "schema_revision": pr.REGISTRY_SNAPSHOT_REVISION,
        "registry_version": "2026-07-02T00:00:00Z",
        "patterns": [_rec("merge.approved.001")],
    }
    qfile = isolated_ssot / "q2.json"
    qfile.write_text(json.dumps({"snapshot": snap}), encoding="utf-8")

    res = registry_ssot.apply_merge(qfile, approve=True)
    assert res["merged"] is True
    assert res["applied"] == 1
    ssot = registry_ssot.load_ssot()
    assert any(p["pattern_id"] == "merge.approved.001" for p in ssot)


def test_apply_merge_rejects_invalid_existing_ssot_before_save(isolated_ssot):
    poisoned = _rec("local.bad.001")
    poisoned["registry_bucket"] = "multilingual_override"
    poisoned["source_ref"] = {"lang": []}
    registry_ssot.save_ssot([poisoned])

    snap = {
        "schema_revision": pr.REGISTRY_SNAPSHOT_REVISION,
        "registry_version": "2026-07-02T00:00:00Z",
        "patterns": [_rec("merge.good.001")],
    }
    qfile = isolated_ssot / "q-poisoned.json"
    qfile.write_text(json.dumps({"snapshot": snap}), encoding="utf-8")

    res = registry_ssot.apply_merge(qfile, approve=True)

    assert res["merged"] is False
    assert res["reason"] == "local_ssot_validation_failed"
    assert any("invalid_source_ref_lang" in e for e in res["errors"])
    assert not any(p["pattern_id"] == "merge.good.001" for p in registry_ssot.load_ssot())
    assert not (isolated_ssot / "projection.json").exists()


def test_apply_merge_projection_write_failure_does_not_save_ssot(isolated_ssot, monkeypatch):
    projection_dir = isolated_ssot / "projection-as-dir"
    projection_dir.mkdir()
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(projection_dir))
    snap = {
        "schema_revision": pr.REGISTRY_SNAPSHOT_REVISION,
        "registry_version": "2026-07-02T00:00:00Z",
        "patterns": [_rec("merge.projection-fails.001")],
    }
    qfile = isolated_ssot / "q-projection-fails.json"
    qfile.write_text(json.dumps({"snapshot": snap}), encoding="utf-8")

    with pytest.raises(IsADirectoryError):
        registry_ssot.apply_merge(qfile, approve=True)

    assert not any(
        p["pattern_id"] == "merge.projection-fails.001" for p in registry_ssot.load_ssot()
    )


def test_apply_merge_ssot_write_failure_does_not_write_projection(isolated_ssot, monkeypatch):
    ssot_dir = isolated_ssot / "ssot-as-dir"
    ssot_dir.mkdir()
    monkeypatch.setenv("SCP_PATTERN_SSOT_PATH", str(ssot_dir))
    snap = {
        "schema_revision": pr.REGISTRY_SNAPSHOT_REVISION,
        "registry_version": "2026-07-02T00:00:00Z",
        "patterns": [_rec("merge.ssot-fails.001")],
    }
    qfile = isolated_ssot / "q-ssot-fails.json"
    qfile.write_text(json.dumps({"snapshot": snap}), encoding="utf-8")

    with pytest.raises(IsADirectoryError):
        registry_ssot.apply_merge(qfile, approve=True)

    assert not (isolated_ssot / "projection.json").exists()


def test_dev_auto_low_risk_only(isolated_ssot, monkeypatch):
    monkeypatch.setenv("SCP_REGISTRY_MERGE_DEV_AUTO", "1")
    monkeypatch.setenv("SCP_REGISTRY_MAX_DRIFT", "0.15")

    snap = {
        "schema_revision": pr.REGISTRY_SNAPSHOT_REVISION,
        "registry_version": "2026-07-02T00:00:00Z",
        "patterns": [
            _rec("auto.low.001", tier="low", drift=0.1),
            _rec("auto.high.001", tier="high", drift=0.0),
        ],
    }
    qfile = isolated_ssot / "q3.json"
    qfile.write_text(json.dumps({"snapshot": snap}), encoding="utf-8")

    res = registry_ssot.apply_merge(qfile, approve=False)
    assert res["merged"] is True
    assert res["auto_applied"] == 1
    assert res["skipped"] == 1
