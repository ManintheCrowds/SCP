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
from . import registry_contribute
from . import registry_fetch
from . import registry_ssot


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


def _cmd_fetch(args) -> dict:
    bare = args.hash[7:] if args.hash.startswith("sha256:") else args.hash
    token = args.l402_token or nostr.l402.l402_token_from_env()
    try:
        payload = nostr.fetch_payload(args.url, bare, l402_token=token)
    except nostr.FetchError as exc:
        out: dict = {"ok": False, "error": exc.reason}
        if exc.status is not None:
            out["status"] = exc.status
        if exc.l402 is not None:
            out["l402"] = exc.l402
        return out
    return {"ok": True, "payload": payload, "payload_hash": f"sha256:{bare}"}


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
    token = args.l402_token or nostr.l402.l402_token_from_env()
    for ann in announcements:
        results.append({
            "announcement": nostr.announcement_to_dict(ann),
            "import": nostr.import_from_announcement(
                ann, allowlist=_split_allowlist(args.allowlist), l402_token=token
            ),
        })
    return results


def _cmd_registry_fetch(args) -> dict:
    return registry_fetch.fetch_registry(
        args.source,
        _split_allowlist(args.allowlist),
        if_none_match=args.if_none_match,
        tls_verify=args.tls_verify,
        relays=_split_allowlist(args.relays),
    )


def _cmd_registry_apply(args) -> dict:
    return registry_ssot.apply_merge(args.quarantine_path, approve=args.approve)


def _cmd_contribute(args) -> dict:
    raw_content = None
    patterns_json = None
    if args.raw_file:
        raw_content = Path(args.raw_file).read_text(encoding="utf-8")
    if args.patterns_file:
        patterns_json = Path(args.patterns_file).read_text(encoding="utf-8")
    return registry_contribute.submit_contribution(
        patterns_json=patterns_json,
        raw_content=raw_content,
        category=args.category,
        risk_tier=args.risk_tier,
        transport=args.transport,
        https_url=args.https_url,
        relays=_split_allowlist(args.relays),
        approve=args.approve,
        dry_run=args.dry_run,
        seckey_hex=args.seckey_hex,
        tls_verify=args.tls_verify,
    )


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
    pd.add_argument("--l402-token", help="operator-supplied L402 macaroon:preimage (or SCP_ANTIGEN_L402_TOKEN)")
    pd.set_defaults(func=_cmd_discover)

    pf = sub.add_parser("fetch", help="fetch HTTPS payload with optional L402 token (no merge)")
    pf.add_argument("url")
    pf.add_argument("--hash", required=True, help="expected sha256 bare hex or sha256: prefix")
    pf.add_argument("--l402-token", help="operator-supplied L402 macaroon:preimage (or SCP_ANTIGEN_L402_TOKEN)")
    pf.set_defaults(func=_cmd_fetch)

    prg = sub.add_parser("registry", help="R4 shared registry fetch/merge")
    prg_sub = prg.add_subparsers(dest="registry_command", required=True)

    prf = prg_sub.add_parser("fetch", help="fetch registry snapshot to quarantine (no merge)")
    prf.add_argument("source", help="HTTPS URL or nostr event id (64-hex)")
    prf.add_argument("--allowlist", required=True)
    prf.add_argument("--if-none-match")
    prf.add_argument("--no-tls-verify", dest="tls_verify", action="store_false", default=True)
    prf.add_argument("--relays")
    prf.set_defaults(func=_cmd_registry_fetch)

    pra = prg_sub.add_parser("apply", help="merge quarantined registry snapshot (requires --approve)")
    pra.add_argument("quarantine_path")
    pra.add_argument("--approve", action="store_true")
    pra.set_defaults(func=_cmd_registry_apply)

    pc = sub.add_parser("contribute", help="R3 outbound contribute (proposal or publish)")
    src = pc.add_mutually_exclusive_group(required=True)
    src.add_argument("--raw-file", help="flagged text for anonymization pipeline")
    src.add_argument("--patterns-file", help="JSON list or {patterns:[]} of pattern_record")
    pc.add_argument("--category", help="required with --raw-file")
    pc.add_argument("--risk-tier", default="medium", choices=["low", "medium", "high", "critical"])
    pc.add_argument("--transport", required=True, choices=["nostr", "https", "both"])
    pc.add_argument("--https-url", help="POST target when transport is https or both")
    pc.add_argument("--relays", help="comma-separated WSS URLs for nostr publish")
    pc.add_argument("--approve", action="store_true", help="operator gate for network publish")
    pc.add_argument("--dry-run", action="store_true", help="force proposal-only (no network)")
    pc.add_argument("--seckey-hex", help="nostr signing key (or NOSTR_SECKEY env)")
    pc.add_argument("--no-tls-verify", dest="tls_verify", action="store_false", default=True)
    pc.set_defaults(func=_cmd_contribute)

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
    # Non-zero exit when a verify/import/merge/fetch did not succeed, for CI/scripts.
    if isinstance(out, dict) and (
        out.get("ok") is False or out.get("rejected") is True
        or (out.get("merged") is False and out.get("reason"))
    ):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
