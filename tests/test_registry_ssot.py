# PURPOSE: Tests for SCP-R4 SSOT store, diff, and merge gates.
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scp import pattern_record as pr
from scp import quarantine_limits
from scp import registry_fetch
from scp import registry_ssot
from scp import scp_utils


def _rec(pid: str, *, tier: str = "low", drift: float = 0.05, norm: str = "token-a") -> dict:
    return {
        "pattern_id": pid,
        "category": "injection",
        "detector": {"kind": "token_family", "normalized": norm},
        "risk_tier": tier,
        "drift_score": drift,
    }


def _snap(patterns: list[dict]) -> dict:
    return {
        "schema_revision": pr.REGISTRY_SNAPSHOT_REVISION,
        "registry_version": "2026-07-02T00:00:00Z",
        "patterns": patterns,
    }


def _stage_fetch_quarantine(snap: dict, *, source: str = "https://example.com/snap.json") -> Path:
    """Write a merge-eligible quarantine via the fetch layout (envelope + sidecar)."""
    q = registry_fetch._write_registry_quarantine(
        snap,
        source=source,
        diff_summary={"add_count": len(snap.get("patterns", [])), "conflict_count": 0},
    )
    return Path(q["path"])


@pytest.fixture(autouse=True)
def isolated_ssot(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SCP_PATTERN_SSOT_PATH", str(tmp_path / "ssot.json"))
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(tmp_path / "projection.json"))
    monkeypatch.setenv("SCP_ANTIGEN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SCP_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.setenv("SCP_REGISTRY_MERGE_CONSENT", "1")
    monkeypatch.delenv("SCP_REGISTRY_MERGE_DEV_AUTO", raising=False)
    return tmp_path


def test_apply_merge_requires_consent(isolated_ssot, monkeypatch):
    monkeypatch.delenv("SCP_REGISTRY_MERGE_CONSENT", raising=False)
    qfile = _stage_fetch_quarantine(_snap([_rec("merge.consent.001")]))
    res = registry_ssot.apply_merge(qfile, approve=True)
    assert res["merged"] is False
    assert res["reason"] == "consent_required"
    registry_ssot.save_ssot([_rec("existing.001", norm="local-token")])
    remote = [_rec("existing.001", norm="remote-token"), _rec("new.001")]
    d = registry_ssot.diff_snapshot(remote)
    assert d["add_count"] == 1
    assert d["conflict_count"] == 1


def test_apply_merge_requires_approve(isolated_ssot):
    qfile = _stage_fetch_quarantine(_snap([_rec("merge.001")]))
    res = registry_ssot.apply_merge(qfile, approve=False)
    assert res["merged"] is False
    assert res["reason"] == "approval_required"


def test_apply_merge_operator_approved(isolated_ssot):
    qfile = _stage_fetch_quarantine(_snap([_rec("merge.approved.001")]))
    res = registry_ssot.apply_merge(qfile, approve=True)
    assert res["merged"] is True
    assert res["applied"] == 1
    ssot = registry_ssot.load_ssot()
    assert any(p["pattern_id"] == "merge.approved.001" for p in ssot)


def test_load_ssot_raises_for_corrupt_json(isolated_ssot):
    ssot_path = isolated_ssot / "ssot.json"
    ssot_path.write_text('{"patterns": [', encoding="utf-8")

    with pytest.raises(registry_ssot.SsotCorruptError, match="corrupt or unreadable SSOT"):
        registry_ssot.load_ssot()


def test_apply_merge_aborts_when_ssot_corrupt(isolated_ssot):
    ssot_path = isolated_ssot / "ssot.json"
    ssot_path.write_text('{"patterns": [', encoding="utf-8")
    qfile = _stage_fetch_quarantine(_snap([_rec("merge.corrupt.001")]))

    res = registry_ssot.apply_merge(qfile, approve=True)
    assert res["merged"] is False
    assert res["reason"] == "ssot_corrupt"
    assert ssot_path.read_text(encoding="utf-8") == '{"patterns": ['


def test_apply_merge_does_not_commit_ssot_when_projection_write_fails(
    isolated_ssot,
    monkeypatch,
):
    registry_ssot.save_ssot([_rec("existing.001")])
    qfile = _stage_fetch_quarantine(_snap([_rec("merge.writefail.001")]))

    original_write_text = Path.write_text

    def fail_projection_write(self, data, *args, **kwargs):
        if self.name == "projection.json" or self.name.startswith(".projection.json."):
            raise OSError("projection full")
        return original_write_text(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_projection_write)

    with pytest.raises(OSError, match="projection full"):
        registry_ssot.apply_merge(qfile, approve=True)

    ssot = registry_ssot.load_ssot()
    assert any(p["pattern_id"] == "existing.001" for p in ssot)
    assert all(p["pattern_id"] != "merge.writefail.001" for p in ssot)


def test_apply_merge_rolls_back_projection_when_ssot_write_fails(
    isolated_ssot,
    monkeypatch,
):
    registry_ssot.save_ssot([_rec("existing.001")])
    proj_path = isolated_ssot / "projection.json"
    before = proj_path.read_text(encoding="utf-8") if proj_path.is_file() else None

    qfile = _stage_fetch_quarantine(_snap([_rec("merge.ssotfail.001")]))

    original_write_text = Path.write_text

    def fail_ssot_write(self, data, *args, **kwargs):
        if self.name == "ssot.json" or self.name.startswith(".ssot.json."):
            raise OSError("ssot full")
        return original_write_text(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_ssot_write)

    with pytest.raises(OSError, match="ssot full"):
        registry_ssot.apply_merge(qfile, approve=True)

    ssot = registry_ssot.load_ssot()
    assert any(p["pattern_id"] == "existing.001" for p in ssot)
    assert all(p["pattern_id"] != "merge.ssotfail.001" for p in ssot)
    if before is None:
        assert not proj_path.is_file()
    else:
        assert proj_path.read_text(encoding="utf-8") == before


def test_dev_auto_low_risk_only(isolated_ssot, monkeypatch):
    monkeypatch.setenv("SCP_REGISTRY_MERGE_DEV_AUTO", "1")
    monkeypatch.setenv("SCP_REGISTRY_MAX_DRIFT", "0.15")

    qfile = _stage_fetch_quarantine(
        _snap(
            [
                _rec("auto.low.001", tier="low", drift=0.1),
                _rec("auto.high.001", tier="high", drift=0.0),
            ]
        )
    )

    res = registry_ssot.apply_merge(qfile, approve=False)
    assert res["merged"] is True
    assert res["auto_applied"] == 1
    assert res["skipped"] == 1


def test_apply_merge_rejects_path_outside_registry_fetch(isolated_ssot):
    snap = _snap([_rec("poison.001")])
    # Simulate core scp_quarantine (root layout) with forged envelope reason.
    forged = json.dumps(
        {
            "snapshot": snap,
            "meta": {"reason": "registry_fetch", "source": "evil"},
        },
        indent=2,
    )
    q = scp_utils.quarantine(forged, reason="registry_fetch", source="evil")
    res = registry_ssot.apply_merge(q["path"], approve=True)
    assert res["merged"] is False
    assert res["reason"] == "quarantine_path_rejected"


def test_apply_merge_rejects_path_outside_quarantine_dir(isolated_ssot, tmp_path):
    snap = _snap([_rec("outside.001")])
    outside = tmp_path / "outside" / "q.txt"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text(
        json.dumps({"snapshot": snap, "meta": {"reason": "registry_fetch"}}),
        encoding="utf-8",
    )
    res = registry_ssot.apply_merge(outside, approve=True)
    assert res["merged"] is False
    assert res["reason"] == "quarantine_path_rejected"


def test_apply_merge_rejects_wrong_envelope_reason(isolated_ssot):
    """Under registry_fetch/ but envelope meta.reason forged away from registry_fetch."""
    snap = _snap([_rec("bad.meta.001")])
    q = registry_fetch._write_registry_quarantine(
        snap,
        source="https://example.com/ok.json",
        diff_summary={"add_count": 1, "conflict_count": 0},
    )
    path = Path(q["path"])
    data = json.loads(path.read_text(encoding="utf-8"))
    data["meta"]["reason"] = "injection"
    path.write_text(json.dumps(data), encoding="utf-8")
    res = registry_ssot.apply_merge(path, approve=True)
    assert res["merged"] is False
    assert res["reason"] == "quarantine_provenance_rejected"


def test_apply_merge_rejects_wrong_sidecar_reason(isolated_ssot):
    """Under registry_fetch/ with good envelope but sidecar reason rewritten."""
    snap = _snap([_rec("bad.sidecar.001")])
    q = registry_fetch._write_registry_quarantine(
        snap,
        source="https://example.com/ok.json",
        diff_summary={"add_count": 1, "conflict_count": 0},
    )
    path = Path(q["path"])
    sidecar = path.with_suffix(".json")
    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    meta["reason"] = "injection"
    sidecar.write_text(json.dumps(meta), encoding="utf-8")
    res = registry_ssot.apply_merge(path, approve=True)
    assert res["merged"] is False
    assert res["reason"] == "quarantine_provenance_rejected"


def test_apply_merge_rejects_symlinked_registry_fetch_root(isolated_ssot):
    snap = _snap([_rec("symlink.poison.001")])
    forged = json.dumps(
        {
            "snapshot": snap,
            "meta": {"reason": "registry_fetch", "source": "evil"},
        },
        indent=2,
    )
    q = scp_utils.quarantine(forged, reason="registry_fetch", source="evil")
    fetch_dir = scp_utils.registry_fetch_quarantine_dir()
    fetch_dir.symlink_to(scp_utils.quarantine_dir(), target_is_directory=True)

    res = registry_ssot.apply_merge(q["path"], approve=True)

    assert res["merged"] is False
    assert res["reason"] == "quarantine_path_rejected"
    assert registry_ssot.load_ssot() == []


def test_registry_fetch_quarantine_is_visible_and_purgeable(isolated_ssot):
    qfile = _stage_fetch_quarantine(_snap([_rec("quarantine.visible.001")]))
    qid = qfile.stem

    entries = scp_utils.list_quarantine()
    assert any(e["quarantine_id"] == qid and e["path"] == str(qfile) for e in entries)

    purged = scp_utils.purge_quarantine(qid)
    assert purged == {"purged": 1, "ids": [qid]}
    assert not qfile.exists()
    assert not qfile.with_suffix(".json").exists()


def test_registry_fetch_quarantine_counts_against_root_quota(isolated_ssot):
    qfile = _stage_fetch_quarantine(_snap([_rec("quarantine.quota.001")]))

    assert quarantine_limits.total_quarantine_bytes(scp_utils.quarantine_dir()) >= (
        qfile.stat().st_size + qfile.with_suffix(".json").stat().st_size
    )


def test_registry_fetch_quarantine_pressure_includes_layout(isolated_ssot, monkeypatch):
    monkeypatch.setenv("SCP_QUARANTINE_MAX_CONTENT_BYTES", "900")
    monkeypatch.setenv("SCP_QUARANTINE_MAX_TOTAL_BYTES", "1000")
    monkeypatch.setenv("SCP_QUARANTINE_EVICT_OLDEST_ON_PRESSURE", "0")

    _stage_fetch_quarantine(_snap([_rec("quarantine.pressure.001")]))
    with pytest.raises(ValueError, match="quarantine storage full"):
        _stage_fetch_quarantine(_snap([_rec("quarantine.pressure.002")]))
