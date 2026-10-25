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
_LIST_BUCKETS = frozenset(
    {
        "power_words",
        "semantic_aliases",
        "jailbreak_nicknames",
        "mythic_framing",
        "hostile_ux",
        "bitcoin_inscription_override",
        "bitcoin_tx_mempool_override",
    }
)


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


def _load_registry_file(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _merge_unique(base: list, extra: list) -> list:
    merged = list(base)
    for item in extra:
        if item not in merged:
            merged.append(item)
    return merged


def _merge_multilingual_override(base: object, extra: object) -> dict:
    merged: dict = {}
    if isinstance(base, dict):
        for lang, phrases in base.items():
            if isinstance(phrases, list):
                merged[lang] = list(phrases)
    if isinstance(extra, dict):
        for lang, phrases in extra.items():
            if not isinstance(phrases, list):
                continue
            current = merged.get(lang, [])
            merged[lang] = _merge_unique(current, phrases)
    return merged


def _extend_packaged_registry(projection: dict) -> dict:
    """Generated projections add local SSOT patterns; they must not erase packaged gates."""
    if projection.get("version") != _PROJECTION_VERSION:
        return projection

    packaged = _load_registry_file(_PACKAGED_REGISTRY)
    if not packaged:
        return projection

    merged = dict(packaged)
    for key, value in projection.items():
        if key in _LIST_BUCKETS:
            base = packaged.get(key, [])
            merged[key] = _merge_unique(
                base if isinstance(base, list) else [],
                value if isinstance(value, list) else [],
            )
        elif key == "multilingual_override":
            merged[key] = _merge_multilingual_override(packaged.get(key), value)
        else:
            merged[key] = value
    return merged


def load_threat_registry() -> dict:
    """Load threat registry JSON; reload on each call (no sticky cache)."""
    path = resolve_threat_registry_path()
    if path is None:
        return {}
    data = _load_registry_file(path)
    if not data:
        return {}
    return _extend_packaged_registry(data)


def clear_threat_registry_cache() -> None:
    """No-op: load is uncached; kept for test compatibility."""
