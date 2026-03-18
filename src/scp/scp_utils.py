# PURPOSE: SCP utilities - inspect, sanitize, contain, quarantine.
# Standalone package; no harness dependency.

import json
import os
import re
import time
import uuid
from pathlib import Path

from . import sanitize_input
from . import mask_secrets as mask_secrets_mod
from . import scp_structural
from . import scp_semantic_judge

_QUARANTINE_ID_RE = re.compile(r"^[a-f0-9-]{1,36}$")

_pkg_dir = Path(__file__).resolve().parent


def _quarantine_dir() -> Path:
    env = os.environ.get("SCP_QUARANTINE_DIR")
    if env:
        return Path(env)
    return _pkg_dir.parent.parent / "scp_quarantine"


def inspect(content: str, context: str | None = None) -> dict:
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


def contain(content: str, wrapper: str = "markdown_fence") -> str:
    if wrapper == "markdown_fence":
        return f"```\n{content}\n```"
    if wrapper == "xml_tag":
        return f"<data>\n{content}\n</data>"
    return content


def quarantine(content: str, reason: str, source: str) -> dict:
    qdir = _quarantine_dir()
    qdir.mkdir(parents=True, exist_ok=True)
    qid = str(uuid.uuid4())[:8]
    meta = {"quarantine_id": qid, "reason": reason, "source": source}
    content_path = qdir / f"{qid}.txt"
    meta_path = qdir / f"{qid}.json"
    content_path.write_text(content, encoding="utf-8", errors="replace")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
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
    masked = mask_secrets_mod.mask(content)
    count = masked.count("[REDACTED]") + masked.count("[EMAIL_REDACTED]")
    return {"masked": masked, "redacted_count": count}


def run_pipeline(content: str, sink: str, options: dict | None = None) -> dict:
    options = options or {}
    report = inspect(content, context=sink)
    tier = report.get("tier", "clean")
    risk_score = report.get("risk_score", 0.0)

    semantic_enabled = options.get("semantic_judge") or os.environ.get("SCP_SEMANTIC_JUDGE") == "1"
    if tier == "clean" and sink in ("handoff", "state") and semantic_enabled:
        judge_result = scp_semantic_judge.judge(content, sink)
        report["semantic_judge"] = judge_result
        if judge_result.get("suspicious"):
            tier = "reversal"
            risk_score = 0.7
            report["tier"] = tier
            report["risk_score"] = risk_score

    if tier == "injection":
        blocked = True
        if options.get("quarantine_on_block"):
            q = quarantine(content, reason="injection", source=sink)
            report["quarantine_id"] = q.get("quarantine_id")
        return {"result": None, "blocked": blocked, "report": report}

    if tier == "reversal":
        san = sanitize(content, mode="strip_unicode")
        content = san["sanitized"]
        report["sanitized"] = True

    contained = contain(content, wrapper=options.get("wrapper", "markdown_fence"))
    return {"result": contained, "blocked": False, "report": report}
