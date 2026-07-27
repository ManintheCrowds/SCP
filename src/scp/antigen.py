# PURPOSE: SCP-ANT1 Antigen P0 — local signed bundle export/import (sign/verify/hash +
#   quarantine-then-policy-gated-merge). No payments, no nostr relay, no auto-merge (P1+).
# DEPENDENCIES: scp.scp_utils (quarantine), scp._schnorr (BIP-340 fallback);
#   optional coincurve (stronger schnorr) and jsonschema (schema cross-check).
# MODIFICATION NOTES: Implements docs/superpowers/specs/2026-04-12-scp-antigen-l402-design.md
#   sections 10 (P0) and 11.4 (verify -> quarantine -> gated merge; auto-reject rules).
#   Bundle format: scp.pattern_bundle.v0 (schemas/antigen-bundle.v0.schema.json).

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from . import scp_utils
from . import operator_consent

SCHEMA_REVISION = "scp.pattern_bundle.v0"
SUPPORTED_PAYLOAD_FORMATS = ("application/json",)  # jsonl/gzip deferred to P1+
DEFAULT_MAX_PAYLOAD_BYTES = 262144  # 256 KiB; override via SCP_ANTIGEN_MAX_PAYLOAD_BYTES
MAX_FREE_TIER_SUMMARY = 500
MAX_NOTES = 2000
MAX_NORMALIZED = 2048

_pkg_dir = Path(__file__).resolve().parent
_SCHEMA_PATH = _pkg_dir / "schemas" / "antigen-bundle.v0.schema.json"

_ANTIGEN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_HEX_PUBKEY_RE = re.compile(r"^[0-9a-f]{64}$")
_NPUB_RE = re.compile(r"^npub1[02-9ac-hj-np-z]{6,}$")
_SIG_RE = re.compile(r"^[0-9a-f]{128}$")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Closed-schema enforcement in code (so additionalProperties:false holds without optional jsonschema).
_ALLOWED_MANIFEST_KEYS = {
    "schema_revision", "antigen_id", "bundle_version", "issuer_pubkey", "issued_at",
    "expires_at", "payload_content_hash", "payload_format", "payload_urls",
    "free_tier_summary", "risk_tags", "signature", "cosignatures",
}
_ALLOWED_PAYLOAD_KEYS = {"patterns", "notes"}
_ALLOWED_PATTERN_KEYS = {"pattern_id", "category", "detector", "severity", "containment"}
_ALLOWED_DETECTOR_KEYS = {"kind", "normalized"}

# Defense-in-depth: payload key names that signal raw logs / PII and must never ship (D invariant).
_PROHIBITED_KEYS = {
    "raw_prompt", "raw_log", "raw_logs", "chat_log", "chatlog", "transcript",
    "victim_prompt", "pii", "personal_data", "raw", "logs", "conversation",
    "exploit", "working_payload", "reproduction",
}


# --------------------------------------------------------------------------- audit

def _audit_path() -> Path:
    env = os.environ.get("SCP_ANTIGEN_AUDIT_LOG")
    if env:
        return Path(env)
    return scp_utils._quarantine_dir().parent / "antigen_audit.jsonl"


def _audit(event: str, **fields) -> None:
    """Append-only audit. Rejected imports log the payload HASH only, never content (D invariant)."""
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "event": event}
    rec.update(fields)
    path = _audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")


# --------------------------------------------------------------------------- crypto

def _canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_payload_hash(payload: dict) -> str:
    """Content address of a payload, as 'sha256:<64hex>' (digest equals the nostr 'x' tag)."""
    return "sha256:" + _sha256_hex(_canonical_bytes(payload))


def _signable_manifest(manifest: dict) -> dict:
    # Signature is over the manifest EXCLUDING the signature/cosignatures fields.
    return {k: v for k, v in manifest.items() if k not in ("signature", "cosignatures")}


def _manifest_digest(manifest: dict) -> bytes:
    return hashlib.sha256(_canonical_bytes(_signable_manifest(manifest))).digest()


def _sign_schnorr(msg32: bytes, seckey: bytes) -> bytes:
    try:
        import coincurve  # optional, stronger/faster
        return coincurve.PrivateKey(seckey).sign_schnorr(msg32)
    except Exception:
        from . import _schnorr
        return _schnorr.schnorr_sign(msg32, seckey)


def _pubkey_hex(seckey: bytes) -> str:
    try:
        import coincurve
        # x-only public key (BIP-340), 32 bytes
        return coincurve.PublicKeyXOnly.from_secret(seckey).format().hex()
    except Exception:
        from . import _schnorr
        return _schnorr.pubkey_gen(seckey).hex()


def _verify_schnorr(msg32: bytes, pubkey_hex: str, sig_hex: str) -> bool:
    if not _HEX_PUBKEY_RE.match(pubkey_hex) or not _SIG_RE.match(sig_hex):
        return False
    pubkey = bytes.fromhex(pubkey_hex)
    sig = bytes.fromhex(sig_hex)
    try:
        import coincurve
        try:
            return bool(coincurve.PublicKeyXOnly(pubkey).verify(sig, msg32))
        except Exception:
            return False
    except ImportError:
        from . import _schnorr
        return _schnorr.schnorr_verify(msg32, pubkey, sig)


# --------------------------------------------------------------------------- export

def export_bundle(
    patterns: list[dict],
    *,
    antigen_id: str,
    issuer_pubkey: str | None = None,
    seckey_hex: str | None = None,
    free_tier_summary: str | None = None,
    risk_tags: list[str] | None = None,
    notes: str | None = None,
    payload_urls: list[str] | None = None,
    bundle_version: int = 0,
    sign: bool = False,
) -> dict:
    """Build a scp.pattern_bundle.v0 bundle. If sign=True, seckey_hex must be set and the
    issuer_pubkey is derived from it; the manifest is Schnorr-signed (BIP-340)."""
    if not _ANTIGEN_ID_RE.match(antigen_id):
        raise ValueError("antigen_id must match ^[a-z0-9][a-z0-9._-]{2,127}$")
    if not patterns:
        raise ValueError("patterns must be a non-empty list")

    payload: dict = {"patterns": patterns}
    if notes is not None:
        payload["notes"] = notes

    manifest: dict = {
        "schema_revision": SCHEMA_REVISION,
        "antigen_id": antigen_id,
        "bundle_version": int(bundle_version),
        "issued_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "payload_content_hash": compute_payload_hash(payload),
        "payload_format": "application/json",
    }
    if risk_tags:
        manifest["risk_tags"] = list(risk_tags)
    if free_tier_summary is not None:
        manifest["free_tier_summary"] = free_tier_summary
    if payload_urls:
        manifest["payload_urls"] = list(payload_urls)

    if sign:
        if not seckey_hex or not _HEX_PUBKEY_RE.match(seckey_hex):
            raise ValueError("sign=True requires a 64-hex seckey_hex")
        seckey = bytes.fromhex(seckey_hex)
        manifest["issuer_pubkey"] = _pubkey_hex(seckey)
        digest = _manifest_digest(manifest)
        manifest["signature"] = {"alg": "schnorr-secp256k1", "sig": _sign_schnorr(digest, seckey).hex()}
    else:
        if not issuer_pubkey:
            raise ValueError("issuer_pubkey required when sign=False")
        manifest["issuer_pubkey"] = issuer_pubkey

    bundle = {"manifest": manifest, "payload": payload}
    _audit("export", antigen_id=antigen_id, payload_hash=manifest["payload_content_hash"],
           signed=bool(sign))
    return bundle


# --------------------------------------------------------------------------- validation

def _structural_errors(bundle: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(bundle, dict) or "manifest" not in bundle or "payload" not in bundle:
        return ["malformed_bundle"]
    m, p = bundle["manifest"], bundle["payload"]
    if not isinstance(m, dict) or not isinstance(p, dict):
        return ["malformed_bundle"]

    if m.get("schema_revision") != SCHEMA_REVISION:
        errors.append("unsupported_schema_revision")
    for field in ("antigen_id", "issuer_pubkey", "issued_at", "payload_content_hash", "payload_format"):
        if field not in m:
            errors.append(f"missing_manifest_field:{field}")
    if "antigen_id" in m and not _ANTIGEN_ID_RE.match(str(m["antigen_id"])):
        errors.append("bad_antigen_id")
    if "issuer_pubkey" in m:
        pk = str(m["issuer_pubkey"])
        if not (_HEX_PUBKEY_RE.match(pk) or _NPUB_RE.match(pk)):
            errors.append("bad_issuer_pubkey")
    if "payload_content_hash" in m and not re.match(r"^sha256:[0-9a-f]{64}$", str(m["payload_content_hash"])):
        errors.append("bad_payload_content_hash_format")
    if m.get("payload_format") not in SUPPORTED_PAYLOAD_FORMATS:
        errors.append("unsupported_payload_format")

    # Closed schema: reject unknown keys even without the optional jsonschema dep.
    if set(m) - _ALLOWED_MANIFEST_KEYS:
        errors.append("unknown_manifest_key")
    if set(p) - _ALLOWED_PAYLOAD_KEYS:
        errors.append("unknown_payload_key")

    # Bounded free-string fields (raw-dump defense; reasons carry no field VALUE).
    if isinstance(m.get("free_tier_summary"), str) and len(m["free_tier_summary"]) > MAX_FREE_TIER_SUMMARY:
        errors.append("free_tier_summary_too_long")
    if isinstance(p.get("notes"), str) and len(p["notes"]) > MAX_NOTES:
        errors.append("notes_too_long")

    patterns = p.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        errors.append("empty_patterns")
    else:
        for pat in patterns:
            if not isinstance(pat, dict):
                errors.append("bad_pattern")
                continue
            if set(pat) - _ALLOWED_PATTERN_KEYS:
                errors.append("unknown_pattern_key")
            for field in ("pattern_id", "category", "detector"):
                if field not in pat:
                    errors.append("missing_pattern_field")
            det = pat.get("detector")
            if isinstance(det, dict):
                if set(det) - _ALLOWED_DETECTOR_KEYS:
                    errors.append("unknown_detector_key")
                if det.get("kind") not in ("token_family", "regex_family", "semantic_alias", "structural"):
                    errors.append("bad_detector_kind")
                if isinstance(det.get("normalized"), str) and len(det["normalized"]) > MAX_NORMALIZED:
                    errors.append("detector_normalized_too_long")
    return errors


def _jsonschema_errors(bundle: dict) -> list[str]:
    try:
        import jsonschema  # optional cross-check
    except ImportError:
        return []
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.validate(bundle, schema)
        return []
    except jsonschema.ValidationError as exc:
        # Emit only the schema KEYWORD (e.g. 'maxLength', 'additionalProperties'); NEVER exc.message,
        # which embeds the offending instance value and would leak payload content on the reject path.
        return [f"jsonschema_invalid:{exc.validator}"]
    except Exception:
        return ["jsonschema_error"]


def _prohibited_content_errors(payload: dict, max_bytes: int) -> list[str]:
    errors: list[str] = []
    raw = _canonical_bytes(payload)
    if len(raw) > max_bytes:
        errors.append("payload_over_size_cap")

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if str(k).lower() in _PROHIBITED_KEYS:
                    errors.append("prohibited_key")  # fixed code; never echo the key name (hash-only contract)
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str):
            if _EMAIL_RE.search(node):
                errors.append("pii_email_in_payload")
            if "PRIVATE KEY" in node or "BEGIN RSA" in node:
                errors.append("secret_material_in_payload")

    walk(payload)
    return sorted(set(errors))


def _manifest_content_errors(manifest: dict) -> list[str]:
    """The manifest is the PUBLIC broadcast surface; its free_tier_summary must carry no PII/secret."""
    errors: list[str] = []
    summary = manifest.get("free_tier_summary")
    if isinstance(summary, str):
        if _EMAIL_RE.search(summary):
            errors.append("pii_email_in_summary")
        if "PRIVATE KEY" in summary:
            errors.append("secret_material_in_summary")
    return errors


def _load_allowlist(allowlist: list[str] | None) -> set[str]:
    if allowlist is not None:
        return {a.strip().lower() for a in allowlist if a.strip()}
    env = os.environ.get("SCP_ANTIGEN_ISSUER_ALLOWLIST")
    if env:
        return {a.strip().lower() for a in env.split(",") if a.strip()}
    file_env = os.environ.get("SCP_ANTIGEN_ALLOWLIST_FILE")
    if file_env and Path(file_env).is_file():
        try:
            data = json.loads(Path(file_env).read_text(encoding="utf-8"))
            if isinstance(data, list):
                return {str(a).strip().lower() for a in data if str(a).strip()}
        except (json.JSONDecodeError, OSError):
            return set()
    return set()


def verify_bundle(
    bundle: dict,
    *,
    allowlist: list[str] | None = None,
    require_signature: bool = True,
    max_payload_bytes: int | None = None,
) -> dict:
    """Verify a bundle against all P0 auto-reject rules (spec 11.4). Returns
    {ok, errors, payload_hash, issuer_pubkey}. Fails closed: empty allowlist rejects all issuers,
    and require_signature defaults True because P0 has no nostr transport to authenticate the issuer
    (an unsigned bundle's issuer_pubkey is unauthenticated). Pass require_signature=False only when
    delivery is over an already-authenticated channel."""
    max_bytes = max_payload_bytes if max_payload_bytes is not None else int(
        os.environ.get("SCP_ANTIGEN_MAX_PAYLOAD_BYTES", DEFAULT_MAX_PAYLOAD_BYTES)
    )
    errors = _structural_errors(bundle)
    if errors and "malformed_bundle" in errors:
        return {"ok": False, "errors": errors, "payload_hash": None, "issuer_pubkey": None}

    manifest = bundle["manifest"]
    payload = bundle["payload"]
    payload_hash = manifest.get("payload_content_hash")
    issuer = str(manifest.get("issuer_pubkey", "")).lower()

    errors += _jsonschema_errors(bundle)

    # Hash: recompute and compare (content addressing).
    actual_hash = compute_payload_hash(payload)
    if payload_hash != actual_hash:
        errors.append("hash_mismatch")

    # Signature: verify if present; require if policy demands.
    sig = manifest.get("signature")
    if sig is not None:
        if not isinstance(sig, dict) or sig.get("alg") != "schnorr-secp256k1" or not _SIG_RE.match(str(sig.get("sig", ""))):
            errors.append("bad_signature_field")
        elif not _HEX_PUBKEY_RE.match(issuer):
            errors.append("signature_requires_hex_pubkey")
        elif not _verify_schnorr(_manifest_digest(manifest), issuer, sig["sig"]):
            errors.append("invalid_signature")
    elif require_signature:
        errors.append("signature_required_but_absent")

    # Issuer allowlist (fail closed).
    allow = _load_allowlist(allowlist)
    if issuer not in allow:
        errors.append("issuer_not_on_allowlist")

    # Content safety (size cap + prohibited keys/PII in payload, and PII/secret in the public summary).
    errors += _prohibited_content_errors(payload, max_bytes)
    errors += _manifest_content_errors(manifest)

    errors = sorted(set(errors))
    return {"ok": len(errors) == 0, "errors": errors, "payload_hash": payload_hash, "issuer_pubkey": issuer}


# --------------------------------------------------------------------------- import / merge

def _load_bundle(bundle_or_path) -> dict:
    if isinstance(bundle_or_path, (str, Path)):
        return json.loads(Path(bundle_or_path).read_text(encoding="utf-8"))
    if isinstance(bundle_or_path, dict):
        return bundle_or_path
    raise TypeError("bundle_or_path must be a dict, str, or Path")


def import_bundle(
    bundle_or_path,
    *,
    allowlist: list[str] | None = None,
    require_signature: bool = True,
    source: str = "antigen_import",
) -> dict:
    """Verify -> quarantine (NO auto-merge). On reject, log the payload HASH only (D invariant).
    Returns {accepted, rejected, reasons, payload_hash, quarantine_id?, merge_proposal?}."""
    bundle = _load_bundle(bundle_or_path)
    result = verify_bundle(bundle, allowlist=allowlist, require_signature=require_signature)

    if not result["ok"]:
        _audit("import_rejected", payload_hash=result.get("payload_hash"), reasons=result["errors"])
        return {
            "accepted": False,
            "rejected": True,
            "reasons": result["errors"],
            "payload_hash": result.get("payload_hash"),
        }

    # Accepted: quarantine the payload before any merge (reuse the SCP primitive).
    q = scp_utils.quarantine(
        content=_canonical_bytes(bundle["payload"]).decode("utf-8"),
        reason="antigen_import_pending_merge",
        source=source,
    )
    manifest = bundle["manifest"]
    proposal = {
        "antigen_id": manifest["antigen_id"],
        "issuer_pubkey": manifest["issuer_pubkey"],
        "pattern_count": len(bundle["payload"]["patterns"]),
        "target": "imported_antigens",
        "auto_merge": False,
        "next": "call merge_to_registry(bundle, approve=True) to merge after human/policy review",
    }
    _audit("import_accepted", payload_hash=result["payload_hash"],
           quarantine_id=q["quarantine_id"], antigen_id=manifest["antigen_id"])
    return {
        "accepted": True,
        "rejected": False,
        "reasons": [],
        "payload_hash": result["payload_hash"],
        "quarantine_id": q["quarantine_id"],
        "merged": False,
        "merge_proposal": proposal,
    }


def _resolve_registry_path(registry_path: str | Path | None) -> Path:
    """Operator-controlled merge target. Never defaults to the installed package directory
    (that holds the curated registry and may be read-only / version-controlled)."""
    if registry_path is not None:
        return Path(registry_path)
    env = os.environ.get("SCP_THREAT_REGISTRY_PATH")
    if env:
        return Path(env)
    # Operator-scoped default outside the package tree.
    return Path.home() / ".scp" / "imported_antigens_registry.json"


def merge_to_registry(
    bundle_or_path,
    *,
    approve: bool = False,
    registry_path: str | Path | None = None,
    allowlist: list[str] | None = None,
    require_signature: bool = True,
) -> dict:
    """Policy/human-gated merge into the local registry's 'imported_antigens' namespace.
    NEVER auto-merges: approve=False returns a proposal only. Re-verifies before writing, then
    QUARANTINES the payload before the registry write (spec 11.4 quarantine-then-merge sequence).
    Non-destructive: only the 'imported_antigens' key is touched (reversible)."""
    bundle = _load_bundle(bundle_or_path)
    result = verify_bundle(bundle, allowlist=allowlist, require_signature=require_signature)
    if not result["ok"]:
        _audit("merge_rejected", payload_hash=result.get("payload_hash"), reasons=result["errors"])
        return {"merged": False, "reason": "verification_failed", "errors": result["errors"]}

    manifest = bundle["manifest"]
    if not approve:
        return {
            "merged": False,
            "reason": "approval_required",
            "proposal": {
                "antigen_id": manifest["antigen_id"],
                "issuer_pubkey": manifest["issuer_pubkey"],
                "pattern_count": len(bundle["payload"]["patterns"]),
                "target": "imported_antigens",
            },
        }

    if not operator_consent.consent_attested(operator_consent.MERGE_CONSENT_ENV):
        return {
            "merged": False,
            "reason": "consent_required",
            "env": operator_consent.MERGE_CONSENT_ENV,
            "proposal": {
                "antigen_id": manifest["antigen_id"],
                "issuer_pubkey": manifest["issuer_pubkey"],
                "pattern_count": len(bundle["payload"]["patterns"]),
                "target": "imported_antigens",
            },
        }

    # Quarantine before merge (structural enforcement of the spec 11.4 sequence).
    q = scp_utils.quarantine(
        content=_canonical_bytes(bundle["payload"]).decode("utf-8"),
        reason="antigen_merge_approved",
        source="antigen_merge",
    )
    path = _resolve_registry_path(registry_path)
    registry: dict = {}
    if path.is_file():
        try:
            registry = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"merged": False, "reason": "registry_unparseable", "registry_path": str(path)}
    imported = registry.setdefault("imported_antigens", [])
    key = f"{manifest['issuer_pubkey']}:{manifest['antigen_id']}"
    imported[:] = [e for e in imported if e.get("key") != key]  # replace prior version (idempotent)
    imported.append({
        "key": key,
        "antigen_id": manifest["antigen_id"],
        "issuer_pubkey": manifest["issuer_pubkey"],
        "payload_content_hash": manifest["payload_content_hash"],
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "patterns": bundle["payload"]["patterns"],
    })
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(registry, indent=2, ensure_ascii=False), encoding="utf-8")
    _audit("merge_applied", payload_hash=manifest["payload_content_hash"],
           antigen_id=manifest["antigen_id"], registry_path=str(path), quarantine_id=q["quarantine_id"])
    return {"merged": True, "registry_path": str(path), "antigen_id": manifest["antigen_id"],
            "imported_count": len(imported), "quarantine_id": q["quarantine_id"]}
