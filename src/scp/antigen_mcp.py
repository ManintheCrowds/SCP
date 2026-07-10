# PURPOSE: Opt-in MCP server for SCP-ANT1 Antigen P0 tools (export/verify/import/merge).
# GUARDRAIL: merge requires explicit approve=True (human gate); never auto-merges.
# DEPENDENCIES: scp.antigen
# MODIFICATION NOTES: Kept SEPARATE from scp_mcp.py so the OpenHarness scp_mcp_v1 tool
#   contract (tests/test_mcp_contract_v1.py) stays exact/conformant. Run: python -m scp.antigen_mcp

"""SCP Antigen MCP Server. Exposes antigen_export, antigen_verify, antigen_import, antigen_merge."""

import json

from mcp.server.fastmcp import FastMCP

from . import antigen as antigen_mod
from . import antigen_l402 as l402_mod
from . import antigen_nostr as nostr_mod
from . import registry_contribute as registry_contribute_mod
from . import registry_fetch as registry_fetch_mod
from . import registry_ssot as registry_ssot_mod

mcp = FastMCP("SCP-Antigen")


def _err(e: Exception) -> str:
    return json.dumps({"error": str(e)})


def _parse_allowlist(allowlist: str | None) -> list[str] | None:
    if not allowlist:
        return None
    return [a.strip() for a in allowlist.split(",") if a.strip()]


@mcp.tool()
def scp_antigen_export(patterns_json: str, antigen_id: str, issuer_pubkey: str | None = None,
                       seckey_hex: str | None = None, sign: bool = False,
                       free_tier_summary: str | None = None, risk_tags: str | None = None,
                       notes: str | None = None, bundle_version: int = 0) -> str:
    """Build a scp.pattern_bundle.v0 bundle from a JSON list of patterns. If sign=True, seckey_hex
    is required and issuer_pubkey is derived. Returns the bundle {manifest, payload}."""
    try:
        patterns = json.loads(patterns_json)
        if isinstance(patterns, dict) and "patterns" in patterns:
            patterns = patterns["patterns"]
        return json.dumps(antigen_mod.export_bundle(
            patterns, antigen_id=antigen_id, issuer_pubkey=issuer_pubkey, seckey_hex=seckey_hex,
            sign=sign, free_tier_summary=free_tier_summary,
            risk_tags=_parse_allowlist(risk_tags), notes=notes, bundle_version=bundle_version))
    except json.JSONDecodeError:
        return _err(ValueError("patterns_json must be valid JSON"))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_antigen_verify(bundle_json: str, allowlist: str | None = None,
                       require_signature: bool = True) -> str:
    """Verify a bundle against all P0 auto-reject rules (schema, hash, signature, issuer allowlist,
    size cap, prohibited keys). No side effects. allowlist is comma-separated and FAIL-CLOSED (empty
    allowlist rejects all issuers). require_signature defaults True (no transport auth in P0).
    Returns {ok, errors, payload_hash, issuer_pubkey}."""
    try:
        return json.dumps(antigen_mod.verify_bundle(
            json.loads(bundle_json), allowlist=_parse_allowlist(allowlist),
            require_signature=require_signature))
    except json.JSONDecodeError:
        return _err(ValueError("bundle_json must be valid JSON"))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_antigen_import(bundle_json: str, allowlist: str | None = None,
                       require_signature: bool = True) -> str:
    """Verify then quarantine a bundle. NEVER auto-merges. On reject, logs the payload hash only.
    require_signature defaults True. Returns {accepted, rejected, reasons, payload_hash,
    quarantine_id?, merge_proposal?}."""
    try:
        return json.dumps(antigen_mod.import_bundle(
            json.loads(bundle_json), allowlist=_parse_allowlist(allowlist),
            require_signature=require_signature))
    except json.JSONDecodeError:
        return _err(ValueError("bundle_json must be valid JSON"))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_antigen_merge(bundle_json: str, approve: bool = False, allowlist: str | None = None,
                      require_signature: bool = True) -> str:
    """Policy/human-gated merge into the local registry's 'imported_antigens' namespace. approve
    defaults to False (proposal only) — the human gate. Re-verifies before writing; non-destructive.
    Returns {merged, ...} or {merged: False, reason: 'approval_required', proposal}."""
    try:
        return json.dumps(antigen_mod.merge_to_registry(
            json.loads(bundle_json), approve=approve, allowlist=_parse_allowlist(allowlist),
            require_signature=require_signature))
    except json.JSONDecodeError:
        return _err(ValueError("bundle_json must be valid JSON"))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_antigen_publish(bundle_json: str, seckey_hex: str | None = None, relays: str | None = None,
                        dry_run: bool = False) -> str:
    """Publish a verified antigen bundle as a nostr kind-30078 announcement. seckey_hex or NOSTR_SECKEY
    required unless dry_run. relays is comma-separated WSS URLs (defaults from SCP_ANTIGEN_RELAYS)."""
    try:
        key = seckey_hex or nostr_mod.seckey_from_env()
        return json.dumps(nostr_mod.publish_announcement(
            json.loads(bundle_json),
            seckey_hex=key,
            relays=_parse_allowlist(relays),
            dry_run=dry_run,
        ))
    except json.JSONDecodeError:
        return _err(ValueError("bundle_json must be valid JSON"))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_antigen_discover(allowlist: str | None = None, relays: str | None = None,
                         antigen_id: str | None = None, since: int | None = None,
                         until: int | None = None) -> str:
    """Subscribe to allowlisted issuer pubkey announcements on nostr relays. Returns JSON list of
    hash+summary+url metadata only. Empty allowlist fails closed (returns [])."""
    try:
        anns = nostr_mod.discover_announcements(
            allowlist=_parse_allowlist(allowlist),
            relays=_parse_allowlist(relays),
            antigen_id=antigen_id,
            since=since,
            until=until,
        )
        return json.dumps([nostr_mod.announcement_to_dict(a) for a in anns])
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_antigen_fetch(url: str, expected_hash: str, allowlist: str | None = None,
                      l402_token: str | None = None) -> str:
    """Fetch HTTPS payload and verify sha256 (expected_hash is bare 64-hex or sha256: prefix).
    Does NOT pay on 402 — surfaces l402 metadata. Optional l402_token is operator-supplied
    macaroon:preimage for retry after human-paid invoice. Does NOT auto-import.
    Host allowlist: non-hex entries in allowlist and/or SCP_ANTIGEN_FETCH_HOST_ALLOWLIST
    (fail-closed before network I/O)."""
    try:
        bare = expected_hash[7:] if expected_hash.startswith("sha256:") else expected_hash
        token = l402_token or l402_mod.l402_token_from_env()
        hosts = _parse_allowlist(allowlist)
        payload = nostr_mod.fetch_payload(
            url, bare, l402_token=token, host_allowlist=hosts
        )
        return json.dumps({"ok": True, "payload": payload, "payload_hash": f"sha256:{bare}"})
    except nostr_mod.FetchError as e:
        out: dict = {"ok": False, "error": e.reason}
        if e.status is not None:
            out["status"] = e.status
        if e.l402 is not None:
            out["l402"] = e.l402
        return json.dumps(out)
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_fetch_registry(
    source: str,
    allowlist: str,
    if_none_match: str | None = None,
    tls_verify: bool = True,
    relays: str | None = None,
) -> str:
    """Fetch shared threat registry snapshot (HTTPS URL or nostr event id). Quarantines only;
    merged is always false. allowlist is comma-separated hosts and/or issuer pubkeys (fail closed)."""
    try:
        return json.dumps(registry_fetch_mod.fetch_registry(
            source,
            _parse_allowlist(allowlist),
            if_none_match=if_none_match,
            tls_verify=tls_verify,
            relays=_parse_allowlist(relays),
        ))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_contribute_pattern(
    transport: str,
    patterns_json: str | None = None,
    raw_content: str | None = None,
    category: str | None = None,
    risk_tier: str = "medium",
    https_url: str | None = None,
    relays: str | None = None,
    approve: bool = False,
    dry_run: bool | None = None,
    seckey_hex: str | None = None,
    tls_verify: bool = True,
) -> str:
    """Prepare or publish anonymized threat patterns (R3 contribute). approve=false → proposal only,
    zero network I/O. transport: nostr | https | both. raw_content requires category."""
    try:
        return json.dumps(registry_contribute_mod.submit_contribution(
            patterns_json=patterns_json,
            raw_content=raw_content,
            category=category,
            risk_tier=risk_tier,
            transport=transport,
            https_url=https_url,
            relays=_parse_allowlist(relays),
            approve=approve,
            dry_run=dry_run,
            seckey_hex=seckey_hex,
            tls_verify=tls_verify,
        ))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_apply_registry_quarantine(quarantine_path: str, approve: bool = False) -> str:
    """Operator-gated merge of a quarantined registry snapshot into local SSOT + projection.
    approve defaults False (proposal only). Dev auto-low-risk via SCP_REGISTRY_MERGE_DEV_AUTO=1."""
    try:
        return json.dumps(registry_ssot_mod.apply_merge(quarantine_path, approve=approve))
    except Exception as e:
        return _err(e)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
