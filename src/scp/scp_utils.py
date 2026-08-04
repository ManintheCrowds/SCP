# PURPOSE: SCP utilities - inspect, sanitize, contain, quarantine.
# Standalone package; no harness dependency.

import hashlib
import importlib.metadata
import json
import os
import re
import time
import uuid
from pathlib import Path

from . import sanitize_input
from . import mask_secrets as mask_secrets_mod
from . import quarantine_limits
from . import scp_limits
from . import scp_structural
from . import scp_semantic_judge
from . import encounter_auto_log

_QUARANTINE_ID_RE = re.compile(r"^[a-f0-9-]{1,36}$")

# Layout used only by registry_fetch → apply_merge; not exposed on core MCP scp_quarantine.
REGISTRY_FETCH_LAYOUT = "registry_fetch"
_ALLOWED_QUARANTINE_LAYOUTS = frozenset({REGISTRY_FETCH_LAYOUT})

_pkg_dir = Path(__file__).resolve().parent


def _quarantine_dir() -> Path:
    env = os.environ.get("SCP_QUARANTINE_DIR")
    if env:
        return Path(env)
    return _pkg_dir.parent.parent / "scp_quarantine"


def quarantine_dir() -> Path:
    """Public accessor for the configured quarantine root."""
    return _quarantine_dir()


def registry_fetch_quarantine_dir() -> Path:
    """Directory that only scp_fetch_registry may write into for merge eligibility."""
    return _quarantine_dir() / REGISTRY_FETCH_LAYOUT


def inspect(content: str, context: str | None = None) -> dict:
    scp_limits.assert_within_limit(content, what="inspect content")
    result = sanitize_input.classify(content)
    if result is None:
        return {"tier": "clean", "findings": {}, "risk_score": 0.0, "categories": [], "error": "classify failed"}

    structural = scp_structural.run_all(content)
    if structural.get("anomalies"):
        result.setdefault("findings", {})["structural_anomalies"] = structural["anomalies"]
        result.setdefault("categories", []).append("structural_anomalies")
        risk_boost = structural.get("risk_boost", 0.0)
        if result.get("tier") == "clean" and risk_boost > 0:
            result["risk_score"] = min(0.7, result.get("risk_score", 0.0) + risk_boost)
            result["tier"] = "reversal"
        else:
            result["risk_score"] = min(1.0, result.get("risk_score", 0.0) + risk_boost)
    result["structural"] = structural

    tier = result.get("tier", "clean")
    hook_meta = encounter_auto_log.maybe_log_encounter(content, tier)
    if hook_meta:
        result["encounter_auto_log"] = hook_meta

    return result


def _run_redact_phrases(text: str) -> tuple[str, bool]:
    findings = sanitize_input.scan_override_phrases(text) + sanitize_input.scan_reversal_phrases(text)
    if not findings:
        return text, False
    findings.sort(key=lambda x: x[0], reverse=True)
    result = text
    for pos, phrase in findings:
        result = result[:pos] + "[REDACTED]" + result[pos + len(phrase) :]
    return result, True


def sanitize(content: str, mode: str = "strip_unicode") -> dict:
    scp_limits.assert_within_limit(content, what="sanitize content")
    changes = []
    sanitized = content
    if mode in ("strip_unicode", "full"):
        sanitized = sanitize_input.sanitize(sanitized)
        if sanitized != content:
            changes.append("stripped_hidden_unicode")
    if mode in ("redact_phrases", "full"):
        redacted, changed = _run_redact_phrases(sanitized)
        if changed:
            sanitized = redacted
            changes.append("redacted_phrases")
    return {"sanitized": sanitized, "changes": changes}


def _max_consecutive_backticks(text: str) -> int:
    max_run = 0
    cur = 0
    for c in text:
        if c == "`":
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 0
    return max_run


def _contain_markdown_fence(content: str) -> str:
    fence_len = max(3, _max_consecutive_backticks(content) + 1)
    fence = "`" * fence_len
    # Info string must not contain backticks; "scp" marks provenance for parsers.
    return f"{fence}scp\n{content}\n{fence}"


def _cdata_escape(text: str) -> str:
    return text.replace("]]>", "]]]]><![CDATA[>")


def _contain_xml_tag(content: str) -> str:
    inner = _cdata_escape(content)
    return f"<data><![CDATA[{inner}]]></data>"


def contain(content: str, wrapper: str = "markdown_fence") -> str:
    scp_limits.assert_within_limit(content, what="contain content")
    if wrapper == "markdown_fence":
        return _contain_markdown_fence(content)
    if wrapper == "xml_tag":
        return _contain_xml_tag(content)
    raise ValueError(
        f"unsupported containment wrapper: {wrapper!r}; use 'markdown_fence' or 'xml_tag'"
    )


def quarantine(
    content: str,
    reason: str,
    source: str,
    *,
    layout: str | None = None,
) -> dict:
    """Quarantine content. ``layout`` is internal-only (e.g. registry_fetch); MCP must not pass it."""
    root = _quarantine_dir()
    if layout is None:
        qdir = root
    elif layout in _ALLOWED_QUARANTINE_LAYOUTS:
        qdir = root / layout
    else:
        raise ValueError(f"unsupported quarantine layout: {layout!r}")
    qdir.mkdir(parents=True, exist_ok=True)
    qid = str(uuid.uuid4())[:8]
    meta = {"quarantine_id": qid, "reason": reason, "source": source}
    meta_json = json.dumps(meta, indent=2)
    content_bytes = len(content.encode("utf-8", errors="replace"))
    meta_bytes = len(meta_json.encode("utf-8"))
    # Quota accounts against the quarantine root (all layouts).
    quarantine_limits.prepare_quarantine_write(root, content_bytes, meta_bytes)
    content_path = qdir / f"{qid}.txt"
    meta_path = qdir / f"{qid}.json"
    content_path.write_text(content, encoding="utf-8", errors="replace")
    meta_path.write_text(meta_json, encoding="utf-8")
    return {"quarantine_id": qid, "path": str(content_path)}


def list_quarantine() -> list[dict]:
    qdir = _quarantine_dir()
    if not qdir.exists():
        return []
    entries = []
    for meta_path in qdir.glob("*.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            qid = meta.get("quarantine_id") or meta_path.stem
            content_path = qdir / f"{qid}.txt"
            entries.append({
                "quarantine_id": qid,
                "reason": meta.get("reason", ""),
                "source": meta.get("source", ""),
                "path": str(content_path) if content_path.exists() else "",
            })
        except (json.JSONDecodeError, OSError):
            continue
    return entries


def purge_quarantine(quarantine_id: str | None = None, older_than_days: int | None = None) -> dict:
    qdir = _quarantine_dir()
    if not qdir.exists():
        return {"purged": 0, "ids": []}
    if quarantine_id is not None and not _QUARANTINE_ID_RE.match(quarantine_id):
        raise ValueError("quarantine_id must be UUID-like")
    cutoff = time.time() - (older_than_days * 86400) if older_than_days else None
    purged = []
    if quarantine_id:
        meta_path = qdir / f"{quarantine_id}.json"
        content_path = qdir / f"{quarantine_id}.txt"
        if meta_path.exists() or content_path.exists():
            if cutoff:
                mtime = meta_path.stat().st_mtime if meta_path.exists() else content_path.stat().st_mtime
                if mtime >= cutoff:
                    return {"purged": 0, "ids": []}
            meta_path.unlink(missing_ok=True)
            content_path.unlink(missing_ok=True)
            purged.append(quarantine_id)
    else:
        for meta_path in list(qdir.glob("*.json")):
            qid = meta_path.stem
            if cutoff:
                try:
                    if meta_path.stat().st_mtime >= cutoff:
                        continue
                except OSError:
                    continue
            content_path = qdir / f"{qid}.txt"
            meta_path.unlink(missing_ok=True)
            content_path.unlink(missing_ok=True)
            purged.append(qid)
    return {"purged": len(purged), "ids": purged}


def mask_secrets(content: str) -> dict:
    scp_limits.assert_within_limit(content, what="mask_secrets content")
    masked = mask_secrets_mod.mask(content)
    count = masked.count("[REDACTED]") + masked.count("[EMAIL_REDACTED]")
    return {"masked": masked, "redacted_count": count}


def get_policy_provenance(registry_path: Path | None = None) -> dict:
    """Version and optional threat-registry fingerprint for agent-visible policy provenance."""
    out: dict = {
        "scp_mcp_version": "unknown",
        "scp_module_path": str(Path(__file__).resolve()),
    }
    try:
        out["scp_mcp_version"] = importlib.metadata.version("scp-mcp")
    except importlib.metadata.PackageNotFoundError:
        pass
    if registry_path is not None and registry_path.is_file():
        try:
            raw = registry_path.read_bytes()
            out["registry_path"] = str(registry_path.resolve())
            out["registry_sha256_16"] = hashlib.sha256(raw).hexdigest()[:16]
            out["registry_size_bytes"] = len(raw)
        except OSError:
            out["registry_error"] = "unreadable"
    return out


def run_pipeline(content: str, sink: str, options: dict | None = None) -> dict:
    options = options or {}
    steps: list[dict] = []
    report = inspect(content, context=sink)
    tier = report.get("tier", "clean")
    risk_score = report.get("risk_score", 0.0)
    steps.append(
        {
            "name": "inspect",
            "ok": True,
            "detail": {"tier": tier},
        }
    )

    semantic_enabled = options.get("semantic_judge") or os.environ.get("SCP_SEMANTIC_JUDGE") == "1"
    if tier == "clean" and sink in ("handoff", "state") and semantic_enabled:
        judge_result = scp_semantic_judge.judge(content, sink)
        report["semantic_judge"] = judge_result
        steps.append(
            {
                "name": "semantic_judge",
                "ok": True,
                "detail": {"suspicious": bool(judge_result.get("suspicious"))},
            }
        )
        if judge_result.get("suspicious"):
            tier = "reversal"
            risk_score = 0.7
            report["tier"] = tier
            report["risk_score"] = risk_score

    if tier == "injection":
        blocked = True
        if options.get("quarantine_on_block"):
            try:
                q = quarantine(content, reason="injection", source=sink)
            except (OSError, ValueError) as exc:
                report["quarantine_error"] = str(exc)
                steps.append(
                    {
                        "name": "quarantine",
                        "ok": False,
                        "detail": str(exc),
                    }
                )
            else:
                report["quarantine_id"] = q.get("quarantine_id")
                steps.append(
                    {
                        "name": "quarantine",
                        "ok": True,
                        "detail": {"quarantine_id": q.get("quarantine_id")},
                    }
                )
        else:
            steps.append(
                {
                    "name": "quarantine",
                    "ok": False,
                    "detail": "skipped",
                }
            )
        steps.append(
            {
                "name": "contain",
                "ok": False,
                "detail": "skipped_injection_blocked",
            }
        )
        return {"result": None, "blocked": blocked, "report": report, "steps": steps}

    if tier == "reversal":
        san = sanitize(content, mode="strip_unicode")
        content = san["sanitized"]
        report["sanitized"] = True
        steps.append(
            {
                "name": "sanitize",
                "ok": True,
                "detail": {"changes": san["changes"]},
            }
        )

    wrapper = options.get("wrapper", "markdown_fence")
    contained = contain(content, wrapper=wrapper)
    steps.append(
        {
            "name": "contain",
            "ok": True,
            "detail": {"wrapper": wrapper},
        }
    )
    return {"result": contained, "blocked": False, "report": report, "steps": steps}
