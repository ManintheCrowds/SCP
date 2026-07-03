# PURPOSE: SCP-R5 slice A — registry load order and inspect loop after apply_merge.
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scp import pattern_record as pr
from scp import registry_paths
from scp import registry_ssot
from scp import sanitize_input


@pytest.fixture
def isolated_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    proj = tmp_path / "projection.json"
    monkeypatch.setenv("SCP_PATTERN_SSOT_PATH", str(tmp_path / "ssot.json"))
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(proj))
    monkeypatch.setenv("SCP_ANTIGEN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SCP_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    monkeypatch.delenv("SCP_REGISTRY_MERGE_DEV_AUTO", raising=False)
    return tmp_path


def _merge_token(token: str, isolated_registry: Path) -> None:
    rec = pr.legacy_token_record(token, bucket="power_words")
    snap = {
        "schema_revision": pr.REGISTRY_SNAPSHOT_REVISION,
        "registry_version": "2026-07-02T00:00:00Z",
        "patterns": [rec],
    }
    qfile = isolated_registry / "quarantine_snap.json"
    qfile.write_text(json.dumps({"snapshot": snap}), encoding="utf-8")
    res = registry_ssot.apply_merge(qfile, approve=True)
    assert res["merged"] is True


def test_inspect_uses_projection_after_merge(isolated_registry: Path) -> None:
    token = "r5inspectunique"
    _merge_token(token, isolated_registry)
    findings = sanitize_input.scan_power_words(f"please use {token} now")
    matched = [f[1] for f in findings]
    assert any(token.lower() in m.lower() for m in matched)


def test_load_packaged_when_no_projection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCP_THREAT_REGISTRY_PATH", raising=False)
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    path = registry_paths.resolve_threat_registry_path()
    assert path is not None
    assert path.name == "scp_threat_registry.json"
    data = registry_paths.load_threat_registry()
    assert isinstance(data, dict)
    assert "power_words" in data or data == {}


def test_env_override_wins_over_packaged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    custom = tmp_path / "custom_registry.json"
    custom.write_text(
        json.dumps({"power_words": ["envoverrideonlytoken"], "version": "test"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("SCP_THREAT_REGISTRY_PATH", str(custom))
    assert registry_paths.resolve_threat_registry_path() == custom
    findings = sanitize_input.scan_power_words("envoverrideonlytoken in text")
    assert findings
