# PURPOSE: SCP-R5 normative threat registry path resolution and load.
# DEPENDENCIES: pathlib, json, os
# MODIFICATION NOTES: Load order per SCP_R5_MCP_INTEGRATION.md slice A.

from __future__ import annotations

import json
import os
from pathlib import Path

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


def _threat_registry_candidates() -> list[Path]:
    """Candidate load order; invalid earlier files must not disable packaged rules."""
    paths: list[Path] = []
    env = os.environ.get("SCP_THREAT_REGISTRY_PATH")
    if env:
        p = Path(env)
        if p.is_file():
            paths.append(p)
    else:
        proj = default_projection_path()
        if proj.is_file():
            paths.append(proj)
    if _PACKAGED_REGISTRY.is_file() and _PACKAGED_REGISTRY not in paths:
        paths.append(_PACKAGED_REGISTRY)
    return paths


def _load_registry_file(path: Path) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) and data else None


def _merge_list_values(base: object, overlay: object) -> list:
    merged: list = []
    seen: set[str] = set()
    for value in (base, overlay):
        if not isinstance(value, list):
            continue
        for item in value:
            key = json.dumps(item, sort_keys=True, ensure_ascii=False)
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
    return merged


def _merge_dict_list_values(base: object, overlay: object) -> dict:
    if not isinstance(base, dict) and not isinstance(overlay, dict):
        return {}
    keys = set(base if isinstance(base, dict) else {}) | set(
        overlay if isinstance(overlay, dict) else {}
    )
    merged: dict = {}
    for key in sorted(keys):
        base_value = base.get(key) if isinstance(base, dict) else None
        overlay_value = overlay.get(key) if isinstance(overlay, dict) else None
        if isinstance(base_value, list) or isinstance(overlay_value, list):
            merged[key] = _merge_list_values(base_value, overlay_value)
        elif overlay_value is not None:
            merged[key] = overlay_value
        else:
            merged[key] = base_value
    return merged


def _overlay_generated_projection(data: dict) -> dict:
    if data.get("version") != "1.0-projection" or not _PACKAGED_REGISTRY.is_file():
        return data
    packaged = _load_registry_file(_PACKAGED_REGISTRY)
    if packaged is None:
        return data

    merged = dict(packaged)
    for key, value in data.items():
        base_value = merged.get(key)
        if isinstance(base_value, list) or isinstance(value, list):
            merged[key] = _merge_list_values(base_value, value)
        elif isinstance(base_value, dict) or isinstance(value, dict):
            merged[key] = _merge_dict_list_values(base_value, value)
        else:
            merged[key] = value
    return merged


def load_threat_registry() -> dict:
    """Load threat registry JSON; reload on each call (no sticky cache)."""
    for path in _threat_registry_candidates():
        data = _load_registry_file(path)
        if data is not None:
            return _overlay_generated_projection(data)
    return {}


def clear_threat_registry_cache() -> None:
    """No-op: load is uncached; kept for test compatibility."""
