# PURPOSE: SCP-R5 normative threat registry path resolution and load.
# DEPENDENCIES: pathlib, json, os
# MODIFICATION NOTES: Load order per SCP_R5_MCP_INTEGRATION.md slice A.

from __future__ import annotations

import json
import os
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent
_PACKAGED_REGISTRY = _PKG_DIR / "scp_threat_registry.json"
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


def _read_registry_json(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _append_unique(existing: list, incoming: list) -> list:
    result = list(existing)
    seen = {item for item in result if isinstance(item, str)}
    for item in incoming:
        if isinstance(item, str) and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _merge_multilingual(base: dict, overlay: dict) -> dict:
    result = {key: list(value) for key, value in base.items() if isinstance(value, list)}
    for lang, tokens in overlay.items():
        if not isinstance(tokens, list):
            continue
        current = result.get(lang, [])
        result[lang] = _append_unique(current, tokens)
    return result


def _merge_projection_with_packaged(projection: dict) -> dict:
    packaged = _read_registry_json(_PACKAGED_REGISTRY) if _PACKAGED_REGISTRY.is_file() else {}
    merged = dict(packaged)
    for key, value in projection.items():
        if key in _LIST_BUCKETS and isinstance(value, list):
            current = merged.get(key, [])
            merged[key] = _append_unique(current if isinstance(current, list) else [], value)
        elif key == "multilingual_override" and isinstance(value, dict):
            current = merged.get(key, {})
            merged[key] = _merge_multilingual(current if isinstance(current, dict) else {}, value)
        else:
            merged[key] = value
    return merged


def load_threat_registry() -> dict:
    """Load threat registry JSON; reload on each call (no sticky cache)."""
    path = resolve_threat_registry_path()
    if path is None:
        return {}
    data = _read_registry_json(path)
    if data.get("version") == "1.0-projection":
        return _merge_projection_with_packaged(data)
    return data


def clear_threat_registry_cache() -> None:
    """No-op: load is uncached; kept for test compatibility."""
