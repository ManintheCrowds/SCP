# PURPOSE: Tests for legacy registry import and snapshot build (R2 bootstrap).
from __future__ import annotations

import json

from scp import pattern_record as pr


def test_records_from_legacy_registry_non_empty():
    registry = pr.load_packaged_threat_registry()
    records = pr.records_from_legacy_registry(registry)
    assert len(records) > 0
    pat = pr.validate_snapshot_patterns(records)
    assert pat["valid"], pat["errors"]


def test_build_registry_snapshot_validates():
    records = pr.records_from_legacy_registry(pr.load_packaged_threat_registry())
    snapshot = pr.build_registry_snapshot(records, registry_version="2026-07-03T12:00:00Z")
    assert snapshot["schema_revision"] == pr.REGISTRY_SNAPSHOT_REVISION
    assert snapshot["etag"].startswith("sha256:")
    assert snapshot["etag"] == pr.canonical_patterns_etag(records)
    env = pr.validate_snapshot(snapshot)
    assert env["valid"]


def test_canonical_patterns_etag_order_sensitive():
    records = [
        pr.legacy_token_record("authorized override", bucket="power_words"),
        pr.legacy_token_record("DAN", bucket="jailbreak_nicknames"),
    ]
    records[0]["category"] = "injection"
    records[1]["category"] = "jailbreak"
    etag_a = pr.canonical_patterns_etag(records)
    etag_b = pr.canonical_patterns_etag(list(reversed(records)))
    assert etag_a != etag_b
    assert etag_a == pr.canonical_patterns_etag([records[0], records[1]])


def test_project_to_registry_preserves_supported_bucket_counts():
    registry = pr.load_packaged_threat_registry()
    records = pr.records_from_legacy_registry(registry)
    projected = pr.project_to_registry(records)

    for bucket in (
        "power_words",
        "semantic_aliases",
        "jailbreak_nicknames",
        "mythic_framing",
        "hostile_ux",
    ):
        source = registry.get(bucket, [])
        if isinstance(source, list):
            assert len(projected.get(bucket, [])) == len(source)

    ml = registry.get("multilingual_override", {})
    if isinstance(ml, dict):
        proj_ml = projected.get("multilingual_override", {})
        for lang, tokens in ml.items():
            assert len(proj_ml.get(lang, [])) == len(tokens)
