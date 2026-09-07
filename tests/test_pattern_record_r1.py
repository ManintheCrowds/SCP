# PURPOSE: Tests for SCP-R1 pattern_record SSOT validation and projection.
from __future__ import annotations

from scp import pattern_record as pr


def _valid_record() -> dict:
    return {
        "pattern_id": "inj.test.001",
        "category": "injection",
        "detector": {"kind": "token_family", "normalized": "override-family"},
        "risk_tier": "low",
        "drift_score": 0.1,
        "registry_bucket": "power_words",
    }


def test_validate_pattern_record_ok():
    v = pr.validate_pattern_record(_valid_record())
    assert v["valid"] is True
    assert v["errors"] == []


def test_validate_pattern_record_rejects_bad_id():
    rec = _valid_record()
    rec["pattern_id"] = "BAD ID"
    v = pr.validate_pattern_record(rec)
    assert v["valid"] is False
    assert "invalid_pattern_id" in v["errors"]


def test_validate_anonymization_rejects_prohibited_key():
    rec = _valid_record()
    rec["raw_prompt"] = "leak"
    a = pr.validate_anonymization(rec)
    assert a["ok"] is False
    assert any("prohibited_key" in r for r in a["reasons"])


def test_migrate_v0_pattern():
    v0 = {
        "pattern_id": "inj.v0.001",
        "category": "injection",
        "detector": {"kind": "token_family", "normalized": "fam"},
        "severity": "high",
        "containment": "sanitize",
    }
    rec = pr.migrate_v0_pattern(v0)
    assert rec["risk_tier"] == "high"
    assert rec["drift_score"] == 0.0
    assert rec["registry_bucket"] == "power_words"


def test_project_to_registry_smoke():
    recs = [_valid_record()]
    proj = pr.project_to_registry(recs)
    assert "override-family" in proj["power_words"]
    assert proj["version"] == "1.0-projection"


def test_project_to_registry_preserves_semantic_and_mythic_buckets():
    semantic = pr.legacy_token_record("semantic-projection-token", bucket="semantic_aliases")
    mythic = pr.legacy_token_record("mythic-projection-token", bucket="mythic_framing")

    proj = pr.project_to_registry([semantic, mythic])

    assert "semantic-projection-token" in proj["semantic_aliases"]
    assert "mythic-projection-token" in proj["mythic_framing"]


def test_validate_snapshot_ok():
    snap = {
        "schema_revision": pr.REGISTRY_SNAPSHOT_REVISION,
        "registry_version": "2026-07-02T00:00:00Z",
        "patterns": [_valid_record()],
    }
    assert pr.validate_snapshot(snap)["valid"] is True
    assert pr.validate_snapshot_patterns(snap["patterns"])["valid"] is True


def test_validate_snapshot_rejects_unsafe_source_ref():
    rec = _valid_record()
    rec["source_ref"] = {"lang": []}

    result = pr.validate_snapshot_patterns([rec])

    assert result["valid"] is False
    assert "patterns[0].invalid_source_ref_lang" in result["errors"]
