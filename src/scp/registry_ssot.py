# PURPOSE: SCP-R4 SSOT store, diff, and operator-gated merge for registry fetch quarantine.
# DEPENDENCIES: pattern_record, scp_utils (audit via antigen), antigen._audit pattern
# MODIFICATION NOTES: Option C hybrid SSOT at ~/.scp/pattern_records.json

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import antigen
from . import pattern_record as pr
from . import registry_paths

DEFAULT_MAX_DRIFT = 0.15
DEFAULT_DEV_AUTO_CATEGORIES = frozenset({"injection"})


def _ssot_path() -> Path:
    env = os.environ.get("SCP_PATTERN_SSOT_PATH")
    if env:
        return Path(env)
    return Path.home() / ".scp" / "pattern_records.json"


def _projection_path() -> Path:
    return registry_paths.default_projection_path()


def _audit(event: str, **fields: Any) -> None:
    antigen._audit(event, **fields)


def load_ssot() -> list[dict]:
    path = _ssot_path()
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("patterns"), list):
        return list(data["patterns"])
    if isinstance(data, list):
        return data
    return []


def _ssot_payload(patterns: list[dict]) -> dict:
    return {
        "schema_revision": "scp.pattern_ssot.v1",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "patterns": patterns,
    }


def save_ssot(patterns: list[dict]) -> None:
    path = _ssot_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _ssot_payload(patterns)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_temp_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not path.is_file():
        raise IsADirectoryError(str(path))
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return tmp_path


def _write_json_pair_staged(first: tuple[Path, dict], second: tuple[Path, dict]) -> None:
    staged: list[tuple[Path, Path]] = []
    replaced: list[tuple[Path, bytes | None]] = []
    try:
        for path, payload in (first, second):
            content = json.dumps(payload, indent=2, ensure_ascii=False)
            staged.append((path, _write_temp_text(path, content)))
        for path, tmp_path in staged:
            old_content = path.read_bytes() if path.is_file() else None
            os.replace(tmp_path, path)
            replaced.append((path, old_content))
    except Exception:
        for path, old_content in reversed(replaced):
            if old_content is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(old_content)
        raise
    finally:
        for _path, tmp_path in staged:
            tmp_path.unlink(missing_ok=True)


def _detector_key(detector: dict) -> str:
    return json.dumps(detector, sort_keys=True, separators=(",", ":"))


def diff_snapshot(patterns: list[dict]) -> dict:
    """Diff remote snapshot vs local SSOT. Returns add/conflict/drift_max/risk_breakdown."""
    local = {p["pattern_id"]: p for p in load_ssot() if isinstance(p, dict) and p.get("pattern_id")}
    adds: list[str] = []
    conflicts: list[dict] = []
    drift_max = 0.0
    risk_breakdown: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    for rec in patterns:
        pid = rec.get("pattern_id")
        if not pid:
            continue
        tier = rec.get("risk_tier", "medium")
        if tier in risk_breakdown:
            risk_breakdown[tier] += 1
        drift = rec.get("drift_score")
        if isinstance(drift, (int, float)):
            drift_max = max(drift_max, float(drift))
        if pid not in local:
            adds.append(pid)
            continue
        local_det = _detector_key(local[pid].get("detector") or {})
        remote_det = _detector_key(rec.get("detector") or {})
        if local_det == remote_det:
            continue
        conflicts.append({"pattern_id": pid, "local_detector": local[pid].get("detector"), "remote_detector": rec.get("detector")})

    return {
        "add_count": len(adds),
        "add": adds,
        "conflict_count": len(conflicts),
        "conflicts": conflicts,
        "drift_max": drift_max,
        "risk_breakdown": risk_breakdown,
    }


def _dev_auto_enabled() -> bool:
    return os.environ.get("SCP_REGISTRY_MERGE_DEV_AUTO") == "1"


def _max_drift() -> float:
    raw = os.environ.get("SCP_REGISTRY_MAX_DRIFT")
    if raw is None:
        return DEFAULT_MAX_DRIFT
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_MAX_DRIFT


def _dev_auto_categories() -> frozenset[str]:
    raw = os.environ.get("SCP_REGISTRY_DEV_AUTO_CATEGORIES")
    if not raw:
        return DEFAULT_DEV_AUTO_CATEGORIES
    return frozenset(c.strip() for c in raw.split(",") if c.strip())


def _load_quarantine_snapshot(quarantine_path: str | Path) -> dict:
    path = Path(quarantine_path)
    if not path.is_file():
        raise ValueError("quarantine_file_not_found")
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "snapshot" in data:
        return data["snapshot"]
    if isinstance(data, dict) and data.get("schema_revision") == pr.REGISTRY_SNAPSHOT_REVISION:
        return data
    raise ValueError("invalid_quarantine_format")


def _eligible_dev_auto(rec: dict, diff_info: dict) -> bool:
    if rec.get("risk_tier") != "low":
        return False
    drift = rec.get("drift_score", 0.0)
    if not isinstance(drift, (int, float)) or float(drift) > _max_drift():
        return False
    if rec.get("category") not in _dev_auto_categories():
        return False
    pid = rec.get("pattern_id")
    if pid in {c["pattern_id"] for c in diff_info.get("conflicts", [])}:
        return False
    return True


def apply_merge(
    quarantine_path: str | Path,
    *,
    approve: bool = False,
) -> dict:
    """Merge quarantined registry snapshot into SSOT. Production requires approve=True."""
    snapshot = _load_quarantine_snapshot(quarantine_path)
    v = pr.validate_snapshot(snapshot)
    if not v["valid"]:
        return {"merged": False, "reason": "invalid_snapshot", "errors": v["errors"]}

    patterns = snapshot["patterns"]
    pv = pr.validate_snapshot_patterns(patterns)
    if not pv["valid"]:
        _audit("pattern_rejected_anonymization", quarantine_path=str(quarantine_path), error_count=len(pv["errors"]))
        return {"merged": False, "reason": "pattern_validation_failed", "errors": pv["errors"]}

    diff_info = diff_snapshot(patterns)
    if diff_info["conflict_count"] > 0 and not approve:
        return {
            "merged": False,
            "reason": "conflicts_require_operator",
            "proposal": diff_info,
        }

    dev_auto = _dev_auto_enabled()
    if not approve and not dev_auto:
        return {
            "merged": False,
            "reason": "approval_required",
            "proposal": diff_info,
        }

    local = {p["pattern_id"]: p for p in load_ssot() if p.get("pattern_id")}
    applied = 0
    auto_applied = 0
    skipped = 0

    for rec in patterns:
        pid = rec["pattern_id"]
        if pid in local:
            local_det = _detector_key(local[pid].get("detector") or {})
            remote_det = _detector_key(rec.get("detector") or {})
            if local_det == remote_det:
                continue
            if not approve:
                skipped += 1
                continue
            local[pid] = rec
            applied += 1
            continue

        if approve:
            local[pid] = rec
            applied += 1
        elif dev_auto and _eligible_dev_auto(rec, diff_info):
            local[pid] = rec
            auto_applied += 1
        else:
            skipped += 1

    if applied == 0 and auto_applied == 0:
        return {"merged": False, "reason": "nothing_to_merge", "proposal": diff_info}

    merged_list = list(local.values())
    mv = pr.validate_snapshot_patterns(merged_list)
    if not mv["valid"]:
        _audit(
            "local_ssot_validation_failed",
            quarantine_path=str(quarantine_path),
            error_count=len(mv["errors"]),
        )
        return {"merged": False, "reason": "local_ssot_validation_failed", "errors": mv["errors"]}
    projection = pr.project_to_registry(merged_list)
    proj_path = _projection_path()
    _write_json_pair_staged((proj_path, projection), (_ssot_path(), _ssot_payload(merged_list)))

    if auto_applied:
        _audit(
            "merge_auto_applied",
            quarantine_path=str(quarantine_path),
            applied=applied,
            auto_applied=auto_applied,
            skipped=skipped,
        )
    else:
        _audit(
            "merge_operator_approved",
            quarantine_path=str(quarantine_path),
            applied=applied,
            skipped=skipped,
        )

    return {
        "merged": True,
        "applied": applied,
        "auto_applied": auto_applied,
        "skipped": skipped,
        "projection_path": str(proj_path),
        "ssot_path": str(_ssot_path()),
    }
