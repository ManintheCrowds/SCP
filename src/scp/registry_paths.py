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
_REGISTRY_META_KEYS = frozenset({"version", "updated", "_comment"})


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


def _overlay_projection(packaged: dict, projection: dict) -> dict:
    """Overlay projection buckets onto the packaged registry without dropping shipped rules."""
    merged = {
        key: (list(value) if isinstance(value, list) else value)
        for key, value in packaged.items()
    }
    for key, value in projection.items():
        if key in _REGISTRY_META_KEYS:
            continue
        if isinstance(value, list):
            base = merged.get(key)
            bucket = list(base) if isinstance(base, list) else []
            seen = {str(item) for item in bucket}
            for item in value:
                marker = str(item)
                if marker not in seen:
                    seen.add(marker)
                    bucket.append(item)
            merged[key] = bucket
            continue
        if isinstance(value, dict):
            base_map = merged.get(key)
            bucket_map = {
                lang: list(tokens) if isinstance(tokens, list) else tokens
                for lang, tokens in base_map.items()
            } if isinstance(base_map, dict) else {}
            for lang, tokens in value.items():
                if not isinstance(tokens, list):
                    bucket_map[lang] = tokens
                    continue
                existing = bucket_map.get(lang)
                bucket = list(existing) if isinstance(existing, list) else []
                seen = {str(item) for item in bucket}
                for item in tokens:
                    marker = str(item)
                    if marker not in seen:
                        seen.add(marker)
                        bucket.append(item)
                bucket_map[lang] = bucket
            merged[key] = bucket_map
            continue
        if key not in merged:
            merged[key] = value
    return merged


def load_threat_registry() -> dict:
    """Load threat registry JSON; projections augment packaged rules instead of replacing them."""
    path = resolve_threat_registry_path()
    if path is None:
        return {}
    data = _read_registry(path)
    if data.get("version") != _PROJECTION_VERSION:
        return data
    packaged = _read_registry(_PACKAGED_REGISTRY) if _PACKAGED_REGISTRY.is_file() else {}
    return _overlay_projection(packaged, data)


def clear_threat_registry_cache() -> None:
    """No-op: load is uncached; kept for test compatibility."""
