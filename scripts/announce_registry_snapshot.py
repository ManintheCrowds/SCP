#!/usr/bin/env python3
# PURPOSE: Publish nostr kind 30078 discovery announcement for a registry snapshot (R2 step 7).
# DEPENDENCIES: scp.antigen, scp.antigen_nostr, scp.registry_contribute, scp.pattern_record
"""CLI: python scripts/announce_registry_snapshot.py --version 0.1.0 --dry-run --json

Examples:
  python scripts/announce_registry_snapshot.py --version 0.1.0 --dry-run
  python scripts/announce_registry_snapshot.py --payload-url URL --publish
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import requests

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from scp import antigen
from scp import antigen_nostr as nostr
from scp import pattern_record as pr
from scp import registry_contribute as rc

GITHUB_ORG = "ManintheCrowds"
GITHUB_REPO = "scp-mycelium-registry"


def _registry_raw_url(version: str) -> str:
    return (
        f"https://raw.githubusercontent.com/{GITHUB_ORG}/{GITHUB_REPO}/"
        f"v{version}/snapshots/v{version}/registry.json"
    )


def _fail(message: str, code: int = 1) -> None:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(code)


def _resolve_seckey(seckey_hex: str | None) -> str:
    key = (seckey_hex or nostr.seckey_from_env() or "").strip().lower()
    if not key:
        _fail("NOSTR_SECKEY or --seckey-hex required")
    return key


def _fetch_snapshot(payload_url: str, *, session: requests.Session | None = None) -> dict:
    http = session or requests.Session()
    resp = http.get(payload_url, timeout=30)
    resp.raise_for_status()
    snapshot = resp.json()
    if snapshot.get("schema_revision") != pr.REGISTRY_SNAPSHOT_REVISION:
        _fail(f"unexpected schema_revision: {snapshot.get('schema_revision')}")
    patterns = snapshot.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        _fail("snapshot has no patterns[]")
    return snapshot


def announce_snapshot(
    *,
    payload_url: str,
    version: str,
    seckey_hex: str | None = None,
    relays: list[str] | None = None,
    dry_run: bool = True,
    relay_transport: nostr.RelayTransport | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Build signed bundle and publish nostr kind 30078 discovery announcement."""
    key = _resolve_seckey(seckey_hex)
    issuer_pubkey = antigen._pubkey_hex(bytes.fromhex(key))
    snapshot = _fetch_snapshot(payload_url, session=session)
    records = snapshot["patterns"]
    bundle_patterns = rc._to_bundle_patterns(records)
    antigen_id = f"registry.v{version}".lower().replace("_", "-")
    signed = antigen.export_bundle(
        bundle_patterns,
        antigen_id=antigen_id,
        seckey_hex=key,
        sign=True,
        bundle_version=0,
        payload_urls=[payload_url],
    )
    pub = nostr.publish_announcement(
        signed,
        seckey_hex=key,
        relays=relays,
        transport=relay_transport,
        dry_run=dry_run,
        approve=not dry_run,
        skip_consent_check=True,  # operator CLI; consent is running this script
    )
    event = pub.get("event") or {}
    return {
        "ok": True,
        "dry_run": dry_run,
        "signed": pub.get("signed", not dry_run),
        "payload_url": payload_url,
        "antigen_id": antigen_id,
        "issuer_pubkey": issuer_pubkey,
        "event_id": pub.get("event_id") or event.get("id", ""),
        "published": pub.get("published", False),
        "relays": pub.get("relays", []),
        "pattern_count": len(records),
        "etag": snapshot.get("etag"),
    }


def _emit(result: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2))
        return
    for key, value in result.items():
        print(f"{key}: {value}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Announce scp-mycelium-registry snapshot on nostr (kind 30078)")
    parser.add_argument("--version", default="0.1.0", help="Semver for antigen_id and default URL")
    parser.add_argument("--payload-url", default=None, help="HTTPS raw snapshot URL (default: tag-scoped GitHub raw)")
    parser.add_argument("--seckey-hex", default=None, help="Nostr seckey (default: NOSTR_SECKEY env)")
    parser.add_argument("--dry-run", action="store_true", help="Sign only; do not publish (default unless --publish)")
    parser.add_argument("--publish", action="store_true", help="Publish to relays (requires NOSTR_SECKEY)")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    payload_url = args.payload_url or _registry_raw_url(args.version)
    dry_run = not args.publish

    result = announce_snapshot(
        payload_url=payload_url,
        version=args.version,
        seckey_hex=args.seckey_hex,
        dry_run=dry_run,
    )
    _emit(result, as_json=args.json)


if __name__ == "__main__":
    main()
