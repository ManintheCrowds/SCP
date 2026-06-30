# PURPOSE: CLI for SCP-ANT1 Antigen P0 — export / verify / import / merge signed bundles.
# DEPENDENCIES: scp.antigen
# MODIFICATION NOTES: Thin argparse wrapper; all logic lives in antigen.py. No auto-merge
#   (merge requires --approve). Usage: python -m scp.antigen_cli <command> ...

import argparse
import json
import sys
from pathlib import Path

from . import antigen
from . import antigen_nostr as nostr


def _read_patterns(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "patterns" in data:
        data = data["patterns"]
    if not isinstance(data, list):
        raise ValueError("patterns file must be a JSON list or {patterns: [...]}")
    return data


def _split_allowlist(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [a.strip() for a in value.split(",") if a.strip()]


def _cmd_export(args) -> dict:
    bundle = antigen.export_bundle(
        _read_patterns(args.patterns_file),
        antigen_id=args.antigen_id,
        issuer_pubkey=args.issuer_pubkey,
        seckey_hex=args.seckey_hex,
        free_tier_summary=args.summary,
        risk_tags=_split_allowlist(args.risk_tags),
        notes=args.notes,
        bundle_version=args.bundle_version,
        sign=args.sign,
    )
    if args.out:
        Path(args.out).write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    return bundle


def _cmd_verify(args) -> dict:
    return antigen.verify_bundle(
        antigen._load_bundle(args.bundle),
        allowlist=_split_allowlist(args.allowlist),
        require_signature=args.require_signature,
    )


def _cmd_import(args) -> dict:
    return antigen.import_bundle(
        args.bundle,
        allowlist=_split_allowlist(args.allowlist),
        require_signature=args.require_signature,
    )


def _cmd_merge(args) -> dict:
    return antigen.merge_to_registry(
        args.bundle,
        approve=args.approve,
        registry_path=args.registry,
        allowlist=_split_allowlist(args.allowlist),
        require_signature=args.require_signature,
    )


def _cmd_publish(args) -> dict:
    bundle = antigen._load_bundle(args.bundle)
    seckey = args.seckey_hex or nostr.seckey_from_env()
    relays = _split_allowlist(args.relays)
    return nostr.publish_announcement(
        bundle,
        seckey_hex=seckey,
        relays=relays,
        dry_run=args.dry_run,
    )


def _cmd_discover(args) -> dict | list[dict]:
    announcements = nostr.discover_announcements(
        allowlist=_split_allowlist(args.allowlist),
        relays=_split_allowlist(args.relays),
        antigen_id=args.antigen_id,
        since=args.since,
        until=args.until,
    )
    if not args.fetch:
        return [nostr.announcement_to_dict(a) for a in announcements]

    results = []
    for ann in announcements:
        results.append({
            "announcement": nostr.announcement_to_dict(ann),
            "import": nostr.import_from_announcement(ann, allowlist=_split_allowlist(args.allowlist)),
        })
    return results


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="scp.antigen_cli", description="SCP-ANT1 antigen P0 tool")
    sub = p.add_subparsers(dest="command", required=True)

    pe = sub.add_parser("export", help="build a signed antigen bundle")
    pe.add_argument("--antigen-id", required=True)
    pe.add_argument("--patterns-file", required=True)
    pe.add_argument("--issuer-pubkey")
    pe.add_argument("--seckey-hex")
    pe.add_argument("--sign", action="store_true")
    pe.add_argument("--summary")
    pe.add_argument("--risk-tags")
    pe.add_argument("--notes")
    pe.add_argument("--bundle-version", type=int, default=0)
    pe.add_argument("--out")
    pe.set_defaults(func=_cmd_export)

    pv = sub.add_parser("verify", help="verify a bundle (no side effects)")
    pv.add_argument("--bundle", required=True)
    pv.add_argument("--allowlist")
    pv.add_argument("--require-signature", action=argparse.BooleanOptionalAction, default=True)
    pv.set_defaults(func=_cmd_verify)

    pi = sub.add_parser("import", help="verify then quarantine (NO merge)")
    pi.add_argument("--bundle", required=True)
    pi.add_argument("--allowlist")
    pi.add_argument("--require-signature", action=argparse.BooleanOptionalAction, default=True)
    pi.set_defaults(func=_cmd_import)

    pm = sub.add_parser("merge", help="gated merge into local registry (requires --approve)")
    pm.add_argument("--bundle", required=True)
    pm.add_argument("--approve", action="store_true")
    pm.add_argument("--registry")
    pm.add_argument("--allowlist")
    pm.add_argument("--require-signature", action=argparse.BooleanOptionalAction, default=True)
    pm.set_defaults(func=_cmd_merge)

    pp = sub.add_parser("publish", help="publish antigen announcement to nostr relays (kind 30078)")
    pp.add_argument("--bundle", required=True)
    pp.add_argument("--seckey-hex")
    pp.add_argument("--relays")
    pp.add_argument("--dry-run", action="store_true")
    pp.set_defaults(func=_cmd_publish)

    pd = sub.add_parser("discover", help="subscribe to allowlisted issuer announcements")
    pd.add_argument("--allowlist")
    pd.add_argument("--relays")
    pd.add_argument("--antigen-id")
    pd.add_argument("--since", type=int)
    pd.add_argument("--until", type=int)
    pd.add_argument("--fetch", action="store_true", help="fetch+import to quarantine (no merge)")
    pd.set_defaults(func=_cmd_discover)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        out = args.func(args)
    except Exception as exc:  # surface errors as JSON for scriptability
        print(json.dumps({"error": str(exc)}))
        return 1
    if args.command == "discover" and isinstance(out, list):
        for line in out:
            print(json.dumps(line, ensure_ascii=False))
        if out and isinstance(out[0], dict):
            if any(
                isinstance(item.get("import"), dict) and item["import"].get("rejected")
                for item in out
                if "import" in item
            ):
                return 2
        return 0
    print(json.dumps(out, indent=2, ensure_ascii=False))
    # Non-zero exit when a verify/import/merge did not succeed, for CI/scripts.
    if isinstance(out, dict) and (out.get("ok") is False or out.get("rejected") is True):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
