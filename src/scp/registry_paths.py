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


def _read_registry(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _merge_lists(base: object, overlay: object) -> list:
    merged: list = []
    seen: set[str] = set()
    for values in (base, overlay):
        if not isinstance(values, list):
            continue
        for value in values:
            marker = json.dumps(value, sort_keys=True, ensure_ascii=False)
            if marker not in seen:
                seen.add(marker)
                merged.append(value)
    return merged


def _overlay_projection(packaged: dict, projection: dict) -> dict:
    merged = dict(packaged)
    for key, value in projection.items():
        base_value = merged.get(key)
        if isinstance(value, list):
            merged[key] = _merge_lists(base_value, value)
        elif isinstance(value, dict):
            if isinstance(base_value, dict):
                nested = dict(base_value)
                for nested_key, nested_value in value.items():
                    nested[nested_key] = _merge_lists(nested.get(nested_key), nested_value)
                merged[key] = nested
            else:
                merged[key] = value
        else:
            merged[key] = value
    return merged


def load_threat_registry() -> dict:
    """Load threat registry JSON; reload on each call (no sticky cache)."""
    path = resolve_threat_registry_path()
    if path is None:
        return {}
    data = _read_registry(path)
    if data.get("version") == "1.0-projection" and path != _PACKAGED_REGISTRY:
        return _overlay_projection(_read_registry(_PACKAGED_REGISTRY), data)
    return data


def clear_threat_registry_cache() -> None:
    """No-op: load is uncached; kept for test compatibility."""
