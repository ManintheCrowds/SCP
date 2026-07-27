# PURPOSE: SCP-R3 outbound contribute flow — anonymize, stage, operator-gated publish.
# DEPENDENCIES: pattern_record, antigen, antigen_nostr, antigen_l402, scp_utils, sanitize_input
# MODIFICATION NOTES: Antigen reuse track; see SCP_R3_CONTRIBUTE_FLOW.md
#
# Nostr transport requires HTTPS payload_urls in the signed bundle (fail-closed payload_url_required)
# even when transport=nostr only — minimal spec extension for build_announcement_event.

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import requests

from . import antigen
from . import antigen_l402 as l402
from . import antigen_nostr as nostr
from . import http_policy
from . import operator_consent
from . import pattern_record as pr
from . import sanitize_input
from . import scp_utils

_CATEGORY_ABBREV: dict[str, str] = {
    "injection": "inj",
    "jailbreak": "jb",
    "hostile_ux": "hux",
    "reversal": "rev",
}

_VALID_CATEGORIES = frozenset(pr._CATEGORY_DEFAULT_BUCKET.keys())
_CONTRIB_PATTERN_ID_RE = re.compile(r"^contrib\.([a-z0-9._-]+)\.([0-9a-f]{8})$")
_CONTRIB_RECORD_KEYS = frozenset(
    {
        "pattern_id",
        "category",
        "detector",
        "risk_tier",
        "drift_score",
        "registry_bucket",
        "containment",
        "source_ref",
    }
)
_CONTRIB_DETECTOR_KEYS = frozenset({"kind", "normalized"})
_CONTRIB_SOURCE_REF_KEYS = frozenset({"lang"})
_SOURCE_REF_LANG_RE = re.compile(r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$")
_DEFAULT_ISSUER = antigen._pubkey_hex(
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
)


class ContributeError(Exception):
    def __init__(self, reason: str, *, reasons: list[str] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.reasons = reasons or []


def _category_abbrev(category: str) -> str:
    return _CATEGORY_ABBREV.get(category, category[:3].lower())


def _finding_types(classification: dict) -> list[str]:
    findings = classification.get("findings") or {}
    types: list[str] = []
    for name, items in findings.items():
        if items:
            types.append(name)
    for cat in classification.get("categories") or []:
        if cat not in types:
            types.append(cat)
    return sorted(set(types))


def _hash8(category: str, risk_tier: str, finding_types: list[str]) -> str:
    material = f"{category}:{risk_tier}:{','.join(finding_types)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:8]


def _strip_raw(raw: str) -> list[str]:
    reasons: list[str] = []
    if pr._EMAIL_RE.search(raw):
        reasons.append("pii_email_detected")
    if pr._CREDENTIAL_URL_RE.search(raw):
        reasons.append("credential_url_detected")
    try:
        obj = json.loads(raw)
        for key_path in pr._walk_keys(obj):
            leaf = key_path.split(".")[-1].split("[")[0]
            if leaf.lower() in pr._PROHIBITED_KEYS:
                reasons.append(f"prohibited_key:{leaf}")
    except json.JSONDecodeError:
        pass
    return reasons


def _resolve_category(raw: str, category: str | None, classification: dict) -> str:
    if category and category in _VALID_CATEGORIES:
        return category
    cats = classification.get("categories") or []
    for preferred in ("injection", "jailbreak", "reversal", "hostile_ux"):
        if preferred in cats:
            return preferred
    tier = classification.get("tier")
    if tier in _VALID_CATEGORIES:
        return tier
    if category and category in _VALID_CATEGORIES:
        return category
    return "injection"


def anonymize_raw_content(
    raw: str,
    *,
    category: str,
    risk_tier: str = "medium",
) -> dict:
    """Rule-only pipeline: classify, strip, abstract, validate → pattern_record."""
    if risk_tier not in pr.RISK_TIERS:
        raise ContributeError("invalid_risk_tier", reasons=["invalid_risk_tier"])

    strip_reasons = _strip_raw(raw)
    if strip_reasons:
        antigen._audit(
            "pattern_rejected_anonymization",
            pattern_count=0,
            error_count=len(strip_reasons),
        )
        raise ContributeError("anonymization_failed", reasons=strip_reasons)

    classification = sanitize_input.classify(raw)
    resolved_category = _resolve_category(raw, category, classification)
    finding_types = _finding_types(classification)
    digest8 = _hash8(resolved_category, risk_tier, finding_types)
    abbrev = _category_abbrev(resolved_category)

    record: dict[str, Any] = {
        "pattern_id": f"contrib.{abbrev}.{digest8}",
        "category": resolved_category,
        "detector": {
            "kind": "token_family",
            "normalized": f"{resolved_category}-family-{digest8}",
        },
        "risk_tier": risk_tier,
        "drift_score": 0.0,
        "registry_bucket": pr._CATEGORY_DEFAULT_BUCKET.get(resolved_category, "power_words"),
    }

    v = pr.validate_pattern_record(record)
    if not v["valid"]:
        antigen._audit(
            "pattern_rejected_anonymization",
            pattern_ids=[record.get("pattern_id", "")],
            error_count=len(v["errors"]),
        )
        raise ContributeError("anonymization_failed", reasons=v["errors"])

    a = pr.validate_anonymization(record)
    if not a["ok"]:
        antigen._audit(
            "pattern_rejected_anonymization",
            pattern_ids=[record["pattern_id"]],
            error_count=len(a["reasons"]),
        )
        raise ContributeError("anonymization_failed", reasons=a["reasons"])

    return record


def _parse_patterns_json(patterns_json: str) -> list[dict]:
    data = json.loads(patterns_json)
    if isinstance(data, dict) and "patterns" in data:
        data = data["patterns"]
    if not isinstance(data, list) or not data:
        raise ContributeError("invalid_patterns_json", reasons=["patterns_must_be_non_empty_list"])
    return data


def _validate_contribute_abstraction(rec: dict) -> list[str]:
    """Contribute-outbound gate: patterns_json must match raw-path abstracted shape."""
    reasons: list[str] = []
    if not isinstance(rec, dict):
        return ["record_must_be_object"]

    for key in sorted(set(rec) - _CONTRIB_RECORD_KEYS):
        reasons.append(f"unknown_field:{key}")

    pid = rec.get("pattern_id", "")
    if not isinstance(pid, str):
        return ["pattern_id_not_contrib_abstract"]
    match = _CONTRIB_PATTERN_ID_RE.match(pid)
    if not match:
        return ["pattern_id_not_contrib_abstract"]

    abbrev, hash8 = match.group(1), match.group(2)
    category = rec.get("category")
    if not isinstance(category, str) or category not in _VALID_CATEGORIES:
        reasons.append("invalid_category_for_contribute")
    elif _category_abbrev(category) != abbrev:
        reasons.append("pattern_id_category_mismatch")

    detector = rec.get("detector")
    if not isinstance(detector, dict) or detector.get("kind") != "token_family":
        reasons.append("detector_must_be_token_family")
    else:
        for key in sorted(set(detector) - _CONTRIB_DETECTOR_KEYS):
            reasons.append(f"unknown_detector_field:{key}")
        if isinstance(category, str) and category in _VALID_CATEGORIES:
            expected_norm = f"{category}-family-{hash8}"
            if detector.get("normalized") != expected_norm:
                reasons.append("normalized_not_abstracted")

    source_ref = rec.get("source_ref")
    if source_ref is not None:
        if not isinstance(source_ref, dict):
            reasons.append("invalid_source_ref")
        else:
            for key in sorted(set(source_ref) - _CONTRIB_SOURCE_REF_KEYS):
                reasons.append(f"unknown_source_ref_field:{key}")
            lang = source_ref.get("lang")
            if lang is not None and (
                not isinstance(lang, str) or not _SOURCE_REF_LANG_RE.match(lang)
            ):
                reasons.append("invalid_source_ref_lang")
    return reasons


def _validate_structured_records(records: list[dict]) -> None:
    reasons: list[str] = []
    for i, rec in enumerate(records):
        v = pr.validate_pattern_record(rec)
        if not v["valid"]:
            reasons.extend([f"patterns[{i}].{e}" for e in v["errors"]])
        a = pr.validate_anonymization(rec)
        if not a["ok"]:
            reasons.extend([f"patterns[{i}].{r}" for r in a["reasons"]])
        for reason in _validate_contribute_abstraction(rec):
            reasons.append(f"patterns[{i}].{reason}")
    if reasons:
        ids = [str(r.get("pattern_id", "")) for r in records if isinstance(r, dict)]
        antigen._audit(
            "pattern_rejected_anonymization",
            pattern_ids=[i for i in ids if i],
            error_count=len(reasons),
        )
        raise ContributeError("anonymization_failed", reasons=reasons)


def _canonical_patterns_hash(records: list[dict]) -> str:
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _build_snapshot(records: list[dict]) -> dict:
    registry_version = (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    return {
        "schema_revision": pr.REGISTRY_SNAPSHOT_REVISION,
        "registry_version": registry_version,
        "etag": _canonical_patterns_hash(records),
        "patterns": records,
    }


def _stage_contribution(
    bundle: dict,
    snapshot: dict,
    *,
    pattern_ids: list[str],
    bundle_preview_hash: str,
) -> dict:
    meta = {
        "reason": "registry_contribute",
        "schema_revision": snapshot.get("schema_revision"),
        "registry_version": snapshot.get("registry_version"),
        "etag": snapshot.get("etag"),
        "pattern_count": len(pattern_ids),
        "pattern_ids": pattern_ids,
        "bundle_preview_hash": bundle_preview_hash,
    }
    envelope = {"bundle": bundle, "snapshot": snapshot, "meta": meta}
    content = json.dumps(envelope, indent=2, ensure_ascii=False)
    q = scp_utils.quarantine(content, reason="registry_contribute", source="registry_contribute")
    antigen._audit(
        "registry_contribute_quarantine",
        quarantine_id=q["quarantine_id"],
        pattern_count=len(pattern_ids),
        bundle_preview_hash=bundle_preview_hash,
    )
    return q


def _to_bundle_patterns(records: list[dict]) -> list[dict]:
    """Map pattern_record SSOT fields to scp.pattern_bundle.v0 pattern shape."""
    out: list[dict] = []
    for rec in records:
        pat: dict[str, Any] = {
            "pattern_id": rec["pattern_id"],
            "category": rec["category"],
            "detector": dict(rec.get("detector") or {}),
            "severity": rec.get("risk_tier", rec.get("severity", "medium")),
        }
        if rec.get("containment"):
            pat["containment"] = rec["containment"]
        out.append(pat)
    return out


def prepare_contribution(
    *,
    patterns_json: str | None = None,
    raw_content: str | None = None,
    category: str | None = None,
    risk_tier: str = "medium",
    https_url: str | None = None,
    issuer_pubkey: str | None = None,
) -> dict:
    """Build bundle, snapshot, and staging quarantine (no network I/O)."""
    has_patterns = patterns_json is not None and patterns_json.strip() != ""
    has_raw = raw_content is not None and raw_content.strip() != ""
    if has_patterns and has_raw:
        raise ContributeError("invalid_input", reasons=["patterns_json_and_raw_content_mutually_exclusive"])
    if not has_patterns and not has_raw:
        raise ContributeError("invalid_input", reasons=["patterns_json_or_raw_content_required"])
    if has_raw and not category:
        raise ContributeError("invalid_input", reasons=["category_required_for_raw_content"])

    warnings: list[str] = []
    if has_raw:
        records = [anonymize_raw_content(raw_content or "", category=category or "", risk_tier=risk_tier)]
    else:
        records = _parse_patterns_json(patterns_json or "")
        _validate_structured_records(records)

    pattern_ids = [str(r["pattern_id"]) for r in records]
    digest8 = pattern_ids[0].rsplit(".", 1)[-1] if pattern_ids else "00000000"
    antigen_id = f"contrib.{digest8}"
    pubkey = issuer_pubkey or os.environ.get("SCP_CONTRIBUTE_ISSUER_PUBKEY") or _DEFAULT_ISSUER

    payload_urls = [https_url] if https_url else None
    bundle_patterns = _to_bundle_patterns(records)
    bundle = antigen.export_bundle(
        bundle_patterns,
        antigen_id=antigen_id,
        issuer_pubkey=pubkey,
        sign=False,
        bundle_version=0,
        payload_urls=payload_urls,
    )
    verify = antigen.verify_bundle(
        bundle,
        allowlist=[pubkey.lower()],
        require_signature=False,
    )
    if not verify["ok"]:
        raise ContributeError("bundle_verification_failed", reasons=verify["errors"])

    snapshot = _build_snapshot(records)
    bundle_preview_hash = bundle["manifest"]["payload_content_hash"]
    q = _stage_contribution(
        bundle,
        snapshot,
        pattern_ids=pattern_ids,
        bundle_preview_hash=bundle_preview_hash,
    )

    proposal = {
        "pattern_count": len(records),
        "pattern_ids": pattern_ids,
        "anonymization_warnings": warnings,
        "bundle_preview_hash": bundle_preview_hash,
        "quarantine_path": q["path"],
    }
    return {
        "proposal": proposal,
        "quarantine_path": q["path"],
        "bundle": bundle,
        "snapshot": snapshot,
        "bundle_preview_hash": bundle_preview_hash,
    }


def _nostr_payload_url(https_url: str) -> str:
    """Map localhost HTTP POST targets to HTTPS for kind-30078 payload_urls."""
    parsed = urlparse(https_url)
    if parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost"):
        return urlunparse(parsed._replace(scheme="https"))
    return https_url


def _resolve_contribute_host_allowlist() -> list[str]:
    env = os.environ.get("SCP_CONTRIBUTE_HOST_ALLOWLIST", "")
    return [a.strip() for a in env.split(",") if a.strip()]


def post_registry_snapshot(
    url: str,
    snapshot: dict,
    *,
    tls_verify: bool = True,
    session: requests.Session | None = None,
) -> dict:
    """POST registry_snapshot.v1 JSON to operator-supplied HTTPS endpoint.

    Consent gates *whether* to publish; SCP_CONTRIBUTE_HOST_ALLOWLIST gates *where*
    (fail-closed unless regtest localhost hardening is enabled).
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")
    ):
        raise ContributeError("url_must_be_https")

    if l402.regtest_fetch_hardening_enabled():
        try:
            l402.assert_localhost_fetch_url(url)
        except ValueError:
            raise ContributeError("fetch_url_not_localhost")
    else:
        hosts = _resolve_contribute_host_allowlist()
        if not http_policy.host_allowed(url, hosts):
            raise ContributeError("host_not_on_allowlist")

    sess = http_policy.outbound_session(session)
    headers = {"Content-Type": "application/json"}
    try:
        resp = sess.post(
            url,
            data=json.dumps(snapshot, separators=(",", ":"), ensure_ascii=False),
            headers=headers,
            timeout=30,
            verify=tls_verify,
            allow_redirects=False,
        )
    except requests.RequestException:
        raise ContributeError("https_post_failed")

    etag = resp.headers.get("ETag") or snapshot.get("etag")
    if etag and not str(etag).startswith("sha256:"):
        etag = f"sha256:{etag}"
    antigen._audit(
        "registry_contribute_https_post",
        status=resp.status_code,
        etag=etag,
    )
    return {"status": resp.status_code, "etag": etag}


def _consent_attested() -> bool:
    return os.environ.get("SCP_CONTRIBUTE_CONSENT") == "1"


def _opt_in_log_path() -> Path:
    override = os.environ.get("SCP_CONTRIBUTE_OPT_IN_LOG", "").strip()
    if override:
        return Path(override)
    return Path.home() / ".scp" / "contribute_opt_in.jsonl"


def append_contribute_opt_in_log(
    *,
    pattern_ids: list[str],
    transport: str,
    operator_note: str | None = None,
) -> None:
    """Append operator-local opt-in record (R6); no payload bodies or PII."""
    entry: dict[str, Any] = {
        "schema_revision": "scp.contribute_opt_in.v1",
        "at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "pattern_ids": list(pattern_ids),
        "transport": transport,
    }
    if operator_note:
        entry["operator_note"] = operator_note[:500]
    log_path = _opt_in_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _proposal_response(prepared: dict) -> dict:
    return {
        "ok": True,
        "submitted": False,
        "proposal": prepared["proposal"],
    }


def _publish_failure(error: str, *, quarantine_path: str | None) -> dict:
    out: dict[str, Any] = {
        "ok": False,
        "error": error,
        "submitted": False,
        "local_staging_preserved": True,
    }
    if quarantine_path:
        out["quarantine_path"] = quarantine_path
    return out


def _partial_publish_failure(
    *,
    quarantine_path: str | None,
    https_out: dict,
    nostr_failure_reason: str,
    nostr_failure_detail: str | None = None,
) -> dict:
    out: dict[str, Any] = {
        "ok": False,
        "error": "partial_publish",
        "submitted": False,
        "partial_publish": True,
        "https": {"status": https_out["status"], "etag": https_out.get("etag")},
        "nostr_failure_reason": nostr_failure_reason,
        "local_staging_preserved": True,
    }
    if nostr_failure_detail:
        out["nostr_failure_detail"] = nostr_failure_detail[:200]
    if quarantine_path:
        out["quarantine_path"] = quarantine_path
    return out


def _build_and_publish_nostr(
    *,
    records: list[dict],
    digest8: str,
    https_url: str,
    seckey_hex: str | None,
    relays: list[str] | None,
    relay_transport: nostr.RelayTransport | None,
    dry_run: bool,
) -> dict:
    key = seckey_hex or nostr.seckey_from_env()
    if not key:
        raise ContributeError("seckey_required")
    signed = antigen.export_bundle(
        _to_bundle_patterns(records),
        antigen_id=f"contrib.{digest8}",
        seckey_hex=key,
        sign=True,
        bundle_version=0,
        payload_urls=[_nostr_payload_url(https_url)],
    )
    try:
        # CLI: SCP_CONTRIBUTE_CONSENT already gated submit. MCP: also require
        # SCP_ANTIGEN_PUBLISH_CONSENT so contribute cannot bypass publish dual-gate.
        skip_publish_consent = not operator_consent.mcp_transport_active()
        out = nostr.publish_announcement(
            signed,
            seckey_hex=key,
            relays=relays,
            transport=relay_transport,
            dry_run=dry_run,
            approve=not dry_run,
            skip_consent_check=skip_publish_consent,
        )
    except (ValueError, RuntimeError) as exc:
        detail = str(exc)[:200] if str(exc) else None
        raise ContributeError(
            "publish_failed",
            reasons=[detail] if detail else [],
        ) from exc
    if dry_run:
        return out
    if not out.get("published"):
        reason = str(out.get("reason") or "publish_failed")
        detail = str(out.get("env") or out.get("reason") or "")[:200] or None
        raise ContributeError(
            reason,
            reasons=[detail] if detail else [],
        )
    return out


def submit_contribution(
    *,
    patterns_json: str | None = None,
    raw_content: str | None = None,
    category: str | None = None,
    risk_tier: str = "medium",
    transport: str,
    https_url: str | None = None,
    relays: list[str] | None = None,
    approve: bool = False,
    dry_run: bool | None = None,
    seckey_hex: str | None = None,
    tls_verify: bool = True,
    issuer_pubkey: str | None = None,
    session: requests.Session | None = None,
    relay_transport: nostr.RelayTransport | None = None,
) -> dict:
    """Public entry: proposal (approve=false) or operator-gated publish."""
    if transport not in ("nostr", "https", "both"):
        return {"ok": False, "error": "invalid_transport", "submitted": False}

    if transport in ("https", "both") and not https_url:
        return {"ok": False, "error": "https_url_required", "submitted": False}

    if transport in ("nostr", "both") and not https_url:
        return {"ok": False, "error": "payload_url_required", "submitted": False}

    effective_dry_run = dry_run if dry_run is not None else (not approve)

    try:
        prepared = prepare_contribution(
            patterns_json=patterns_json,
            raw_content=raw_content,
            category=category,
            risk_tier=risk_tier,
            https_url=https_url,
            issuer_pubkey=issuer_pubkey,
        )
    except ContributeError as exc:
        return {
            "ok": False,
            "error": exc.reason,
            "reasons": exc.reasons,
            "submitted": False,
        }
    except json.JSONDecodeError:
        return {"ok": False, "error": "invalid_patterns_json", "submitted": False}

    quarantine_path = prepared["quarantine_path"]

    if not approve or effective_dry_run:
        return _proposal_response(prepared)

    if not _consent_attested():
        return _publish_failure("consent_required", quarantine_path=quarantine_path)

    bundle = prepared["bundle"]
    snapshot = prepared["snapshot"]
    bundle_hash = bundle["manifest"]["payload_content_hash"]
    result: dict[str, Any] = {
        "ok": True,
        "submitted": True,
        "bundle_hash": bundle_hash,
    }

    records = snapshot["patterns"]
    digest8 = prepared["proposal"]["pattern_ids"][0].rsplit(".", 1)[-1]
    nostr_url = https_url or ""

    if transport == "both":
        try:
            _build_and_publish_nostr(
                records=records,
                digest8=digest8,
                https_url=nostr_url,
                seckey_hex=seckey_hex,
                relays=relays,
                relay_transport=relay_transport,
                dry_run=True,
            )
        except ContributeError as exc:
            return _publish_failure(exc.reason, quarantine_path=quarantine_path)

    https_out: dict | None = None
    if transport in ("https", "both"):
        try:
            https_out = post_registry_snapshot(
                nostr_url,
                snapshot,
                tls_verify=tls_verify,
                session=session,
            )
        except ContributeError as exc:
            return _publish_failure(
                "https_post_failed" if exc.reason == "https_post_failed" else exc.reason,
                quarantine_path=quarantine_path,
            )
        if https_out["status"] not in (200, 201, 204):
            return _publish_failure("https_post_failed", quarantine_path=quarantine_path)
        result["https"] = {"status": https_out["status"], "etag": https_out.get("etag")}

    if transport in ("nostr", "both"):
        try:
            nostr_out = _build_and_publish_nostr(
                records=records,
                digest8=digest8,
                https_url=nostr_url,
                seckey_hex=seckey_hex,
                relays=relays,
                relay_transport=relay_transport,
                dry_run=False,
            )
        except ContributeError as exc:
            if transport == "both" and https_out is not None:
                detail = exc.reasons[0] if exc.reasons else None
                return _partial_publish_failure(
                    quarantine_path=quarantine_path,
                    https_out=https_out,
                    nostr_failure_reason=exc.reason,
                    nostr_failure_detail=detail,
                )
            return _publish_failure(exc.reason, quarantine_path=quarantine_path)
        result["nostr"] = {
            "event_id": nostr_out.get("event_id", ""),
            "relays": nostr_out.get("relays", []),
        }

    append_contribute_opt_in_log(
        pattern_ids=prepared["proposal"]["pattern_ids"],
        transport=transport,
    )
    return result
