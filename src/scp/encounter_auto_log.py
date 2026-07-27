# PURPOSE: Auto-append SCP injection/reversal detections to encounter bestiary (EP-4 / R2).
# DEPENDENCIES: ENCOUNTER_BESTIARY_DIR or default under operator harness docs/
# MODIFICATION NOTES: Called from scp_utils.inspect; never raises; no second SCP inspect.

from __future__ import annotations

import hashlib
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MAX_CONTENT_LENGTH = 10_000
_MAX_SOURCE_LENGTH = 256

_INJECTION_CFG = {
    "encounter_type": "prompt_injection_attempt",
    "entity_id": "SIREN",
    "severity": "high",
}
_REVERSAL_CFG = {
    "encounter_type": "goal_hijack",
    "entity_id": "LOKI",
    "severity": "medium",
}


def _session_source() -> str:
    model = os.environ.get("AGENT_MODEL", "unknown")
    conv = os.environ.get("CONVERSATION_ID", uuid.uuid4().hex)
    boot = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    raw = f"{model}:{boot}:{conv}"
    return f"scp_auto:{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


def _encounter_dir() -> Path | None:
    env = os.environ.get("ENCOUNTER_BESTIARY_DIR")
    if env:
        base = Path(env)
    else:
        for candidate in (
            Path.cwd() / "docs" / "encounter_bestiary",
            Path(__file__).resolve().parent.parent.parent / "docs" / "encounter_bestiary",
        ):
            if candidate.parent.name == "docs":
                base = candidate
                break
        else:
            return None
    try:
        resolved = base.resolve()
    except OSError:
        return None
    if resolved.name != "encounter_bestiary" or resolved.parent.name != "docs":
        return None
    return resolved


def _sanitize_for_log(content: str, tier: str) -> str:
    """Redact secrets then truncate for durable encounter logs."""
    from . import mask_secrets

    redacted = mask_secrets.mask(content)
    if tier == "injection":
        preview = redacted[:500]
        return f"[auto] SCP injection-tier detection (preview truncated)\n{preview}"
    return f"[auto] SCP reversal-tier detection\n{redacted[:2000]}"


def maybe_log_encounter(
    raw_content: str,
    tier: str,
    *,
    enabled: bool | None = None,
) -> dict | None:
    """Append encounter row when tier is injection or reversal. Returns meta or None."""
    if tier not in ("injection", "reversal"):
        return None
    if enabled is None:
        enabled = os.environ.get("SCP_ENCOUNTER_AUTO_LOG") == "1"
    if not enabled:
        return None

    base = _encounter_dir()
    if base is None:
        return None

    cfg = _INJECTION_CFG if tier == "injection" else _REVERSAL_CFG
    body = _sanitize_for_log(raw_content, tier)
    if len(body) > _MAX_CONTENT_LENGTH:
        body = body[:_MAX_CONTENT_LENGTH]

    source = _session_source().replace("|", "_")[:_MAX_SOURCE_LENGTH]
    evidence_hash = hashlib.sha256(raw_content.encode()).hexdigest()
    target_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    target_path = base / f"{target_date}_encounters.md"

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = (
        f"### {timestamp} | {source} | {cfg['encounter_type']} | "
        f"{cfg['entity_id']} | {cfg['severity']}\n"
        f"evidence_hash: {evidence_hash}\n{body}\n\n"
    )

    try:
        base.mkdir(parents=True, exist_ok=True)
        if target_path.exists():
            with open(target_path, "a", encoding="utf-8") as f:
                f.write(entry)
        else:
            header = f"# Encounters {target_date}\n\n"
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(header + entry)
    except OSError:
        return None

    return {
        "path": str(target_path),
        "entity_id": cfg["entity_id"],
        "encounter_type": cfg["encounter_type"],
        "evidence_hash": evidence_hash,
    }
