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
    paths: list[Path] = []
    env = os.environ.get("SCP_THREAT_REGISTRY_PATH")
    if env:
        p = Path(env)
        if p.is_file():
            paths.append(p)
    proj = default_projection_path()
    if proj.is_file() and proj not in paths:
        paths.append(proj)
    if _PACKAGED_REGISTRY.is_file() and _PACKAGED_REGISTRY not in paths:
        paths.append(_PACKAGED_REGISTRY)
    return paths


def load_threat_registry() -> dict:
    """Load threat registry JSON; reload on each call (no sticky cache)."""
    for path in _threat_registry_candidates():
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, dict) and data:
            return data
    return {}


def clear_threat_registry_cache() -> None:
    """No-op: load is uncached; kept for test compatibility."""
