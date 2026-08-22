# PURPOSE: SCP-R4 SSOT store, diff, and operator-gated merge for registry fetch quarantine.
# DEPENDENCIES: pattern_record, scp_utils (audit via antigen), antigen._audit pattern
# MODIFICATION NOTES: AppSec 2026-08-03 — confine quarantine_path + require registry_fetch provenance

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import antigen
from . import operator_consent
from . import pattern_record as pr
from . import registry_paths
from . import scp_utils

REGISTRY_FETCH_REASON = "registry_fetch"

DEFAULT_MAX_DRIFT = 0.15
DEFAULT_DEV_AUTO_CATEGORIES = frozenset({"injection"})


class SsotCorruptError(ValueError):
    """Raised when an on-disk SSOT file exists but cannot be loaded safely."""


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
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        # Fail closed: never pretend a corrupt/unreadable store is empty —
        # that would let apply_merge wipe local patterns on the next write.
        raise SsotCorruptError(f"corrupt or unreadable SSOT at {path}: {exc}") from exc
    if isinstance(data, dict) and isinstance(data.get("patterns"), list):
        return list(data["patterns"])
    if isinstance(data, list):
        return data
    raise SsotCorruptError(f"invalid SSOT shape at {path}")


def _write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _restore_projection(path: Path, previous_text: str | None) -> None:
    """Best-effort undo of a projection write after SSOT commit failure."""
    try:
        if previous_text is None:
            path.unlink(missing_ok=True)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.restore.tmp")
        try:
            tmp.write_text(previous_text, encoding="utf-8")
            os.replace(tmp, path)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
    except OSError:
        pass


def save_ssot(patterns: list[dict]) -> None:
    path = _ssot_path()
    payload = {
        "schema_revision": "scp.pattern_ssot.v1",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "patterns": patterns,
    }
    _write_json_atomic(path, payload)


def _detector_key(detector: dict) -> str:
    return json.dumps(detector, sort_keys=True, separators=(",", ":"))


def diff_snapshot(
    patterns: list[dict],
    *,
    local_patterns: list[dict] | None = None,
) -> dict:
    """Diff remote snapshot vs local SSOT. Returns add/conflict/drift_max/risk_breakdown."""
    if local_patterns is None:
        local_patterns = load_ssot()
    local = {
        p["pattern_id"]: p
        for p in local_patterns
        if isinstance(p, dict) and p.get("pattern_id")
    }
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
    if operator_consent.mcp_transport_active():
        return False
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


def _path_under_registry_fetch(path: Path) -> bool:
    """True iff path resolves under {QUARANTINE_DIR}/registry_fetch/."""
    try:
        resolved = path.resolve()
        fetch_path = scp_utils.registry_fetch_quarantine_dir()
        quarantine_root = scp_utils.quarantine_dir().resolve()
        if fetch_path.is_symlink():
            return False
        fetch_root = fetch_path.resolve()
    except OSError:
        return False
    try:
        if fetch_root == quarantine_root or not fetch_root.is_relative_to(quarantine_root):
            return False
        return resolved.is_relative_to(fetch_root)
    except (ValueError, AttributeError):
        # Python <3.9 fallback unused; keep defensive.
        try:
            if fetch_root == quarantine_root:
                return False
            resolved.relative_to(fetch_root)
            fetch_root.relative_to(quarantine_root)
            return True
        except ValueError:
            return False


def _sidecar_meta_reason(content_path: Path) -> str | None:
    """Read sibling {stem}.json reason written by scp_utils.quarantine."""
    meta_path = content_path.with_suffix(".json")
    if not meta_path.is_file():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(meta, dict):
        return None
    reason = meta.get("reason")
    return reason if isinstance(reason, str) else None


def _load_quarantine_snapshot(quarantine_path: str | Path) -> dict:
    path = Path(quarantine_path)
    if not _path_under_registry_fetch(path):
        raise ValueError("quarantine_path_rejected")
    if not path.is_file():
        raise ValueError("quarantine_file_not_found")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError("invalid_quarantine_format") from exc

    if not isinstance(data, dict) or "snapshot" not in data:
        raise ValueError("invalid_quarantine_format")
    meta = data.get("meta")
    if not isinstance(meta, dict) or meta.get("reason") != REGISTRY_FETCH_REASON:
        raise ValueError("quarantine_provenance_rejected")
    if _sidecar_meta_reason(path) != REGISTRY_FETCH_REASON:
        raise ValueError("quarantine_provenance_rejected")

    snapshot = data["snapshot"]
    if not isinstance(snapshot, dict):
        raise ValueError("invalid_quarantine_format")
    return snapshot


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
    """Merge quarantined registry snapshot into SSOT. Production requires approve=True.

    Only accepts paths under ``{SCP_QUARANTINE_DIR}/registry_fetch/`` produced by
    ``scp_fetch_registry`` (envelope + sidecar reason=registry_fetch).
    """
    try:
        snapshot = _load_quarantine_snapshot(quarantine_path)
    except ValueError as exc:
        reason = str(exc) or "quarantine_path_rejected"
        if reason not in (
            "quarantine_path_rejected",
            "quarantine_file_not_found",
            "invalid_quarantine_format",
            "quarantine_provenance_rejected",
        ):
            reason = "quarantine_path_rejected"
        return {"merged": False, "reason": reason}
    v = pr.validate_snapshot(snapshot)
    if not v["valid"]:
        return {"merged": False, "reason": "invalid_snapshot", "errors": v["errors"]}

    patterns = snapshot["patterns"]
    pv = pr.validate_snapshot_patterns(patterns)
    if not pv["valid"]:
        _audit("pattern_rejected_anonymization", quarantine_path=str(quarantine_path), error_count=len(pv["errors"]))
        return {"merged": False, "reason": "pattern_validation_failed", "errors": pv["errors"]}

    try:
        local_patterns = load_ssot()
        diff_info = diff_snapshot(patterns, local_patterns=local_patterns)
    except SsotCorruptError as exc:
        return {"merged": False, "reason": "ssot_corrupt", "error": str(exc)}
    if diff_info["conflict_count"] > 0 and not approve:
        return {
            "merged": False,
            "reason": "conflicts_require_operator",
            "proposal": diff_info,
        }

    if approve and not operator_consent.consent_attested(operator_consent.MERGE_CONSENT_ENV):
        return {
            "merged": False,
            "reason": "consent_required",
            "env": operator_consent.MERGE_CONSENT_ENV,
            "proposal": diff_info,
        }

    dev_auto = _dev_auto_enabled()
    if not approve and not dev_auto:
        return {
            "merged": False,
            "reason": "approval_required",
            "proposal": diff_info,
        }

    local = {p["pattern_id"]: p for p in local_patterns if p.get("pattern_id")}
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

    # Projection first so SSOT is not committed without a successful projection
    # write; roll projection back if SSOT then fails (avoid split-brain).
    projection = pr.project_to_registry(merged_list)
    proj_path = _projection_path()
    previous_projection: str | None = None
    if proj_path.is_file():
        try:
            previous_projection = proj_path.read_text(encoding="utf-8")
        except OSError:
            previous_projection = None
    _write_json_atomic(proj_path, projection)
    try:
        save_ssot(merged_list)
    except Exception:
        _restore_projection(proj_path, previous_projection)
        raise

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
