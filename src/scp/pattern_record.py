# PURPOSE: SCP-R1 pattern_record SSOT — validate, anonymize, migrate v0, project to legacy registry.
# DEPENDENCIES: none (pure validation/projection)
# MODIFICATION NOTES: Option C hybrid; see SCP_R1_THREAT_PATTERN_SCHEMA.md

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PATTERN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
RISK_TIERS = frozenset({"low", "medium", "high", "critical"})
DETECTOR_KINDS = frozenset({"token_family", "regex_family", "semantic_alias", "structural"})
CONTAINMENT_ACTIONS = frozenset({"sanitize", "quarantine", "block"})
REGISTRY_SNAPSHOT_REVISION = "scp.registry_snapshot.v1"
_SOURCE_REF_KEYS = frozenset({"lang"})
_SOURCE_REF_LANG_RE = re.compile(r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$")

_CATEGORY_DEFAULT_BUCKET: dict[str, str] = {
    "injection": "power_words",
    "jailbreak": "jailbreak_nicknames",
    "hostile_ux": "hostile_ux",
    "reversal": "power_words",
}

_LEGACY_REGISTRY_META_KEYS = frozenset({"version", "updated", "_comment"})

_LEGACY_BUCKET_CATEGORY: dict[str, str] = {
    "power_words": "injection",
    "semantic_aliases": "injection",
    "bitcoin_inscription_override": "injection",
    "bitcoin_tx_mempool_override": "injection",
    "jailbreak_nicknames": "jailbreak",
    "mythic_framing": "jailbreak",
    "hostile_ux": "hostile_ux",
    "multilingual_override": "injection",
}


class RegistrySnapshotError(ValueError):
    """Raised when snapshot validation fails during build."""


def canonical_patterns_etag(records: list[dict]) -> str:
    """Content address of patterns[] — matches registry_contribute._canonical_patterns_hash."""
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def build_registry_snapshot(
    records: list[dict],
    *,
    registry_version: str | None = None,
) -> dict:
    """Build scp.registry_snapshot.v1 envelope; fail closed if invalid."""
    version = registry_version or (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    snapshot = {
        "schema_revision": REGISTRY_SNAPSHOT_REVISION,
        "registry_version": version,
        "etag": canonical_patterns_etag(records),
        "patterns": records,
    }
    env = validate_snapshot(snapshot)
    if not env["valid"]:
        raise RegistrySnapshotError(f"invalid snapshot envelope: {env['errors']}")
    pat = validate_snapshot_patterns(records)
    if not pat["valid"]:
        raise RegistrySnapshotError(f"invalid snapshot patterns: {pat['errors']}")
    return snapshot


def records_from_legacy_registry(registry: dict) -> list[dict]:
    """Import packaged scp_threat_registry.json buckets into pattern_record list."""
    records: list[dict] = []
    seen_ids: set[str] = set()

    for bucket, value in registry.items():
        if bucket in _LEGACY_REGISTRY_META_KEYS:
            continue
        category = _LEGACY_BUCKET_CATEGORY.get(bucket)
        if category is None:
            continue

        if bucket == "multilingual_override":
            if not isinstance(value, dict):
                continue
            for lang, tokens in value.items():
                if not isinstance(tokens, list):
                    continue
                for token in tokens:
                    if not isinstance(token, str) or not token.strip():
                        continue
                    rec = legacy_token_record(token.strip(), bucket=bucket)
                    rec["category"] = category
                    rec["source_ref"] = {"lang": str(lang)}
                    pid = rec["pattern_id"]
                    if pid in seen_ids:
                        continue
                    seen_ids.add(pid)
                    records.append(rec)
            continue

        if not isinstance(value, list):
            continue
        for token in value:
            if not isinstance(token, str) or not token.strip():
                continue
            rec = legacy_token_record(token.strip(), bucket=bucket)
            rec["category"] = category
            pid = rec["pattern_id"]
            if pid in seen_ids:
                continue
            seen_ids.add(pid)
            records.append(rec)

    records.sort(key=lambda r: r.get("pattern_id", ""))
    return records


def load_packaged_threat_registry() -> dict:
    """Load default packaged scp_threat_registry.json."""
    path = _pkg_dir / "scp_threat_registry.json"
    return json.loads(path.read_text(encoding="utf-8"))

_PROHIBITED_KEYS = {
    "raw_prompt", "raw_log", "raw_logs", "chat_log", "chatlog", "transcript",
    "victim_prompt", "pii", "personal_data", "raw", "logs", "conversation",
    "exploit", "working_payload", "reproduction",
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_CREDENTIAL_URL_RE = re.compile(r"https?://[^\s]+[@?][^\s]+", re.I)

_pkg_dir = Path(__file__).resolve().parent


def _walk_keys(obj: Any, prefix: str = "") -> list[str]:
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(f"{prefix}.{k}" if prefix else k)
            keys.extend(_walk_keys(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            keys.extend(_walk_keys(item, f"{prefix}[{i}]"))
    return keys


def validate_pattern_record(record: dict) -> dict:
    """Return {valid: bool, errors: list[str]}."""
    errors: list[str] = []
    if not isinstance(record, dict):
        return {"valid": False, "errors": ["record_must_be_object"]}

    pid = record.get("pattern_id")
    if not isinstance(pid, str) or not PATTERN_ID_RE.match(pid):
        errors.append("invalid_pattern_id")

    category = record.get("category")
    if not isinstance(category, str) or not category.strip():
        errors.append("invalid_category")

    detector = record.get("detector")
    if not isinstance(detector, dict):
        errors.append("invalid_detector")
    else:
        kind = detector.get("kind")
        if kind not in DETECTOR_KINDS:
            errors.append("invalid_detector_kind")
        norm = detector.get("normalized")
        if norm is not None and (not isinstance(norm, str) or len(norm) > 2048):
            errors.append("invalid_detector_normalized")

    risk = record.get("risk_tier")
    if risk not in RISK_TIERS:
        errors.append("invalid_risk_tier")

    containment = record.get("containment")
    if containment is not None and containment not in CONTAINMENT_ACTIONS:
        errors.append("invalid_containment")

    drift = record.get("drift_score")
    if drift is not None:
        if not isinstance(drift, (int, float)) or drift < 0.0 or drift > 1.0:
            errors.append("invalid_drift_score")

    bucket = record.get("registry_bucket")
    if bucket is not None and (not isinstance(bucket, str) or not bucket.strip()):
        errors.append("invalid_registry_bucket")

    source_ref = record.get("source_ref")
    if source_ref is not None:
        if not isinstance(source_ref, dict):
            errors.append("invalid_source_ref")
        else:
            extra_keys = set(source_ref) - _SOURCE_REF_KEYS
            if extra_keys:
                errors.append("invalid_source_ref")
            lang = source_ref.get("lang")
            if lang is not None and (
                not isinstance(lang, str) or not _SOURCE_REF_LANG_RE.match(lang)
            ):
                errors.append("invalid_source_ref_lang")

    return {"valid": len(errors) == 0, "errors": errors}


def validate_anonymization(record: dict) -> dict:
    """Deny-list check per R1 spec. Returns {ok: bool, reasons: list[str]}."""
    reasons: list[str] = []
    for key_path in _walk_keys(record):
        leaf = key_path.split(".")[-1].split("[")[0]
        if leaf.lower() in _PROHIBITED_KEYS:
            reasons.append(f"prohibited_key:{leaf}")

    blob = json.dumps(record, ensure_ascii=False)
    if _EMAIL_RE.search(blob):
        reasons.append("pii_email_detected")
    if _CREDENTIAL_URL_RE.search(blob):
        reasons.append("credential_url_detected")

    detector = record.get("detector") if isinstance(record, dict) else None
    if isinstance(detector, dict):
        norm = detector.get("normalized")
        if isinstance(norm, str) and len(norm) > 512:
            reasons.append("normalized_too_long_possible_raw_prompt")

    return {"ok": len(reasons) == 0, "reasons": reasons}


def migrate_v0_pattern(p: dict) -> dict:
    """Map interim v0 bundle pattern to pattern_record."""
    severity = p.get("severity", "medium")
    if severity not in RISK_TIERS:
        severity = "medium"
    category = p.get("category", "injection")
    out: dict[str, Any] = {
        "pattern_id": p["pattern_id"],
        "category": category,
        "detector": dict(p.get("detector") or {}),
        "risk_tier": severity,
        "drift_score": 0.0,
        "registry_bucket": _CATEGORY_DEFAULT_BUCKET.get(category, "power_words"),
    }
    if p.get("containment"):
        out["containment"] = p["containment"]
    return out


def validate_snapshot(snapshot: dict) -> dict:
    """Validate scp.registry_snapshot.v1 envelope."""
    errors: list[str] = []
    if not isinstance(snapshot, dict):
        return {"valid": False, "errors": ["snapshot_must_be_object"]}
    if snapshot.get("schema_revision") != REGISTRY_SNAPSHOT_REVISION:
        errors.append("invalid_schema_revision")
    if not isinstance(snapshot.get("registry_version"), str):
        errors.append("invalid_registry_version")
    patterns = snapshot.get("patterns")
    if not isinstance(patterns, list) or len(patterns) == 0:
        errors.append("invalid_patterns_array")
    return {"valid": len(errors) == 0, "errors": errors}


def validate_snapshot_patterns(patterns: list[dict]) -> dict:
    """Validate each pattern_record + anonymization."""
    errors: list[str] = []
    for i, rec in enumerate(patterns):
        v = validate_pattern_record(rec)
        if not v["valid"]:
            errors.extend([f"patterns[{i}].{e}" for e in v["errors"]])
        a = validate_anonymization(rec)
        if not a["ok"]:
            errors.extend([f"patterns[{i}].{r}" for r in a["reasons"]])
    return {"valid": len(errors) == 0, "errors": errors}


def _token_for_projection(record: dict) -> str | None:
    detector = record.get("detector") or {}
    norm = detector.get("normalized")
    if isinstance(norm, str) and norm.strip():
        return norm.strip()
    return None


def project_to_registry(records: list[dict]) -> dict:
    """Compile pattern_record list into legacy scp_threat_registry.json bucket shape."""
    buckets: dict[str, Any] = {
        "power_words": [],
        "jailbreak_nicknames": [],
        "hostile_ux": [],
        "bitcoin_inscription_override": [],
        "bitcoin_tx_mempool_override": [],
        "multilingual_override": {},
    }
    seen: dict[str, set[str]] = {k: set() for k in buckets if isinstance(buckets[k], list)}

    for rec in records:
        token = _token_for_projection(rec)
        if not token:
            continue
        bucket = rec.get("registry_bucket") or _CATEGORY_DEFAULT_BUCKET.get(
            rec.get("category", ""), "power_words"
        )
        if bucket == "multilingual_override":
            lang = rec.get("source_ref", {}).get("lang", "en") if isinstance(rec.get("source_ref"), dict) else "en"
            lang_map = buckets["multilingual_override"]
            if not isinstance(lang_map, dict):
                lang_map = {}
                buckets["multilingual_override"] = lang_map
            lang_map.setdefault(lang, [])
            if token not in lang_map[lang]:
                lang_map[lang].append(token)
        elif bucket in seen:
            if token not in seen[bucket]:
                seen[bucket].add(token)
                buckets[bucket].append(token)

    return {
        "version": "1.0-projection",
        "updated": "projection",
        "_comment": "Compiled from pattern_record SSOT; not authoritative wire format.",
        **buckets,
    }


def legacy_token_record(token: str, bucket: str = "power_words") -> dict:
    """Legacy registry string -> pattern_record (import helper)."""
    h8 = hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]
    return {
        "pattern_id": f"legacy.{bucket}.{h8}",
        "category": "injection",
        "detector": {"kind": "token_family", "normalized": token},
        "risk_tier": "medium",
        "drift_score": 0.0,
        "registry_bucket": bucket,
    }
