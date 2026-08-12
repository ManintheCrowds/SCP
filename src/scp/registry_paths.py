# PURPOSE: SCP-R5 normative threat registry path resolution and load.
# DEPENDENCIES: pathlib, json, os
# MODIFICATION NOTES: Load order per SCP_R5_MCP_INTEGRATION.md slice A.

from __future__ import annotations

import json
import os
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent
_PACKAGED_REGISTRY = _PKG_DIR / "scp_threat_registry.json"
_PROJECTION_VERSION = "1.0-projection"


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


def _read_registry(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _merge_unique_lists(base: list, overlay: list) -> list:
    merged: list = []
    seen: set[str] = set()
    for item in base + overlay:
        key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def _overlay_projection(base: dict, projection: dict) -> dict:
    merged = dict(base)
    for key, value in projection.items():
        if key in {"version", "updated", "_comment"}:
            merged[key] = value
            continue
        current = merged.get(key)
        if isinstance(current, list) and isinstance(value, list):
            merged[key] = _merge_unique_lists(current, value)
        elif isinstance(current, dict) and isinstance(value, dict):
            nested = dict(current)
            for nested_key, nested_value in value.items():
                current_value = nested.get(nested_key)
                if isinstance(current_value, list) and isinstance(nested_value, list):
                    nested[nested_key] = _merge_unique_lists(current_value, nested_value)
                else:
                    nested[nested_key] = nested_value
            merged[key] = nested
        else:
            merged[key] = value
    return merged


def load_threat_registry() -> dict:
    """Load threat registry JSON; reload on each call (no sticky cache)."""
    path = resolve_threat_registry_path()
    if path is None:
        return {}
    data = _read_registry(path)
    if data.get("version") != _PROJECTION_VERSION:
        return data
    packaged = _read_registry(_PACKAGED_REGISTRY)
    return _overlay_projection(packaged, data) if packaged else data


def clear_threat_registry_cache() -> None:
    """No-op: load is uncached; kept for test compatibility."""
