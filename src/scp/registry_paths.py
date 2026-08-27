# PURPOSE: SCP-R5 normative threat registry path resolution and load.
# DEPENDENCIES: pathlib, json, os
# MODIFICATION NOTES: Load order per SCP_R5_MCP_INTEGRATION.md slice A.

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_PKG_DIR = Path(__file__).resolve().parent
_PACKAGED_REGISTRY = _PKG_DIR / "scp_threat_registry.json"


def default_projection_path() -> Path:
    """Write target for apply_merge projection (env override or ~/.scp default)."""
    env = os.environ.get("SCP_THREAT_REGISTRY_PATH")
    if env:
        return Path(env)
    return Path.home() / ".scp" / "threat_registry_projection.json"


def resolve_threat_registry_path() -> Path | None:
    """Resolve registry JSON path: env (if exists) → projection → packaged."""
    env = os.environ.get("SCP_THREAT_REGISTRY_PATH")
    if env:
        p = Path(env)
        if p.is_file():
            return p
    proj = default_projection_path()
    if proj.is_file():
        return proj
    if _PACKAGED_REGISTRY.is_file():
        return _PACKAGED_REGISTRY
    return None


def _load_registry_file(path: Path) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) and data else None


def _merge_unique(base: list[Any], overlay: list[Any]) -> list[Any]:
    out: list[Any] = []
    seen: set[str] = set()
    for item in [*base, *overlay]:
        key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _overlay_projection(base: dict, projection: dict) -> dict:
    merged = dict(base)
    for key, value in projection.items():
        if key in ("version", "updated", "_comment"):
            continue
        current = merged.get(key)
        if isinstance(current, list) and isinstance(value, list):
            merged[key] = _merge_unique(current, value)
        elif isinstance(current, dict) and isinstance(value, dict):
            lang_map = dict(current)
            for lang, phrases in value.items():
                if isinstance(phrases, list):
                    prior = lang_map.get(lang, [])
                    lang_map[lang] = _merge_unique(prior if isinstance(prior, list) else [], phrases)
                elif phrases:
                    lang_map[lang] = phrases
            merged[key] = lang_map
        elif value:
            merged[key] = value
    merged["version"] = projection.get("version", base.get("version"))
    merged["updated"] = projection.get("updated", base.get("updated"))
    merged["_comment"] = projection.get("_comment", base.get("_comment", ""))
    return merged


def load_threat_registry() -> dict:
    """Load threat registry JSON; reload on each call (no sticky cache).

    Generated projections augment the packaged registry. Invalid or empty
    higher-priority files are skipped so local file corruption does not
    silently disable built-in detectors.
    """
    candidates: list[Path] = []
    env = os.environ.get("SCP_THREAT_REGISTRY_PATH")
    if env:
        candidates.append(Path(env))
    projection = default_projection_path()
    if projection not in candidates:
        candidates.append(projection)
    candidates.append(_PACKAGED_REGISTRY)

    packaged = _load_registry_file(_PACKAGED_REGISTRY) or {}
    for path in candidates:
        if not path.is_file():
            continue
        data = _load_registry_file(path)
        if data is None:
            continue
        if data.get("version") == "1.0-projection" and packaged:
            return _overlay_projection(packaged, data)
        return data
    return packaged


def clear_threat_registry_cache() -> None:
    """No-op: load is uncached; kept for test compatibility."""
