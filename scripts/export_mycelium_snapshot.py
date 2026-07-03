#!/usr/bin/env python3
# PURPOSE: Export scp.registry_snapshot.v1 + latest.json for scp-mycelium-registry bootstrap.
# DEPENDENCIES: scp.pattern_record
"""CLI: python scripts/export_mycelium_snapshot.py --version 0.1.0 --out-dir ../scp-mycelium-registry"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from scp import pattern_record as pr

DEFAULT_REGISTRY = _REPO_ROOT / "src" / "scp" / "scp_threat_registry.json"
GITHUB_ORG = "ManintheCrowds"
GITHUB_REPO = "scp-mycelium-registry"


def _registry_raw_url(version: str) -> str:
    return (
        f"https://raw.githubusercontent.com/{GITHUB_ORG}/{GITHUB_REPO}/"
        f"v{version}/snapshots/v{version}/registry.json"
    )


def export_snapshot(
    *,
    version: str,
    out_dir: Path,
    registry_path: Path,
    registry_version: str | None = None,
) -> dict:
    """Write snapshots/v{version}/registry.json and latest.json; return snapshot dict."""
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    records = pr.records_from_legacy_registry(registry)
    if not records:
        raise SystemExit("no pattern records imported from legacy registry")

    snapshot = pr.build_registry_snapshot(records, registry_version=registry_version)
    snap_dir = out_dir / "snapshots" / f"v{version}"
    snap_dir.mkdir(parents=True, exist_ok=True)
    snap_path = snap_dir / "registry.json"
    snap_path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    published_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    pointer = {
        "schema_revision": "scp.registry_pointer.v1",
        "version": version,
        "registry_url": _registry_raw_url(version),
        "etag": snapshot["etag"],
        "published_at": published_at,
    }
    latest_path = out_dir / "latest.json"
    latest_path.write_text(json.dumps(pointer, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"wrote {snap_path} ({len(records)} patterns, etag={snapshot['etag']})")
    print(f"wrote {latest_path}")
    return snapshot


def main() -> None:
    parser = argparse.ArgumentParser(description="Export mycelium registry snapshot for R2 bootstrap")
    parser.add_argument("--version", default="0.1.0", help="Semver release (e.g. 0.1.0)")
    parser.add_argument("--out-dir", type=Path, required=True, help="Output repo root directory")
    parser.add_argument(
        "--registry",
        type=Path,
        default=DEFAULT_REGISTRY,
        help="Legacy scp_threat_registry.json path",
    )
    parser.add_argument(
        "--registry-version",
        default=None,
        help="ISO8601 registry_version field (default: now UTC)",
    )
    args = parser.parse_args()
    export_snapshot(
        version=args.version,
        out_dir=args.out_dir,
        registry_path=args.registry,
        registry_version=args.registry_version,
    )


if __name__ == "__main__":
    main()
