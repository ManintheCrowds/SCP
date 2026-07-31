# PURPOSE: Opt-in MCP server for SCP-ANT1 Antigen P0 tools (export/verify/import/merge).
# GUARDRAIL: merge/publish require approve + env consent; hosts/relays env-only;
#   bundle_json must be a JSON object (never a path string — AppSec 2026-07-30).
# DEPENDENCIES: scp.antigen
# MODIFICATION NOTES: AppSec 2026-07-30 — reject non-object bundle_json (path type-confusion);
#   AppSec 2026-07-28 — registry TLS verify env-only (no MCP tls_verify)

"""SCP Antigen MCP Server. Exposes antigen_export, antigen_verify, antigen_import, antigen_merge."""

import json

from mcp.server.fastmcp import FastMCP

from . import antigen as antigen_mod
from . import antigen_nostr as nostr_mod
from . import http_policy
from . import operator_consent
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


def _parse_pubkey_allowlist(allowlist: str | None) -> list[str] | None:
    """MCP allowlist = issuer pubkeys only (hosts ignored / stripped)."""
    raw = _parse_allowlist(allowlist)
    if raw is None:
        return None
    return http_policy.pubkey_entries(raw) or []


def _parse_bundle_object(bundle_json: str) -> dict:
    """Parse MCP bundle_json as a JSON object only (no path strings).

    PURPOSE: Fail closed on type confusion — json.loads of a JSON string yields
    a Python str that _load_bundle historically treated as a filesystem path.
    """
    obj = json.loads(bundle_json)
    if not isinstance(obj, dict):
        raise ValueError("bundle_json must be a JSON object")
    return obj


@mcp.tool()
def scp_antigen_export(patterns_json: str, antigen_id: str, issuer_pubkey: str | None = None,
                       seckey_hex: str | None = None, sign: bool = False,
                       free_tier_summary: str | None = None, risk_tags: str | None = None,
                       notes: str | None = None, bundle_version: int = 0) -> str:
    """Build a scp.pattern_bundle.v0 bundle. MCP rejects seckey_hex; sign via CLI only."""
    with operator_consent.mcp_transport_scope():
        try:
            if seckey_hex:
                return json.dumps({
                    "error": "seckey_hex_not_allowed_on_mcp",
                })
            patterns = json.loads(patterns_json)
            if isinstance(patterns, dict) and "patterns" in patterns:
                patterns = patterns["patterns"]
            return json.dumps(antigen_mod.export_bundle(
                patterns, antigen_id=antigen_id, issuer_pubkey=issuer_pubkey, seckey_hex=None,
                sign=sign, free_tier_summary=free_tier_summary,
                risk_tags=_parse_allowlist(risk_tags), notes=notes, bundle_version=bundle_version))
        except json.JSONDecodeError:
            return _err(ValueError("patterns_json must be valid JSON"))
        except Exception as e:
            return _err(e)


@mcp.tool()
def scp_antigen_verify(bundle_json: str, allowlist: str | None = None,
                       require_signature: bool = True) -> str:
    """Verify a bundle against all P0 auto-reject rules. Signature always required on MCP."""
    _ = require_signature
    with operator_consent.mcp_transport_scope():
        try:
            return json.dumps(antigen_mod.verify_bundle(
                _parse_bundle_object(bundle_json), allowlist=_parse_pubkey_allowlist(allowlist),
                require_signature=True))
        except json.JSONDecodeError:
            return _err(ValueError("bundle_json must be valid JSON"))
        except Exception as e:
            return _err(e)


@mcp.tool()
def scp_antigen_import(bundle_json: str, allowlist: str | None = None,
                       require_signature: bool = True) -> str:
    """Verify then quarantine a bundle. NEVER auto-merges. Signature always required on MCP."""
    _ = require_signature
    with operator_consent.mcp_transport_scope():
        try:
            return json.dumps(antigen_mod.import_bundle(
                _parse_bundle_object(bundle_json), allowlist=_parse_pubkey_allowlist(allowlist),
                require_signature=True))
        except json.JSONDecodeError:
            return _err(ValueError("bundle_json must be valid JSON"))
        except Exception as e:
            return _err(e)


@mcp.tool()
def scp_antigen_merge(bundle_json: str, approve: bool = False, allowlist: str | None = None) -> str:
    """Merge into imported_antigens. approve=false → proposal. Live merge needs
    SCP_REGISTRY_MERGE_CONSENT=1. Signature always required on MCP."""
    with operator_consent.mcp_transport_scope():
        try:
            return json.dumps(antigen_mod.merge_to_registry(
                _parse_bundle_object(bundle_json), approve=approve,
                allowlist=_parse_pubkey_allowlist(allowlist),
                require_signature=True))
        except json.JSONDecodeError:
            return _err(ValueError("bundle_json must be valid JSON"))
        except Exception as e:
            return _err(e)


@mcp.tool()
def scp_antigen_publish(bundle_json: str, relays: str | None = None,
                        dry_run: bool = False, approve: bool = False) -> str:
    """Publish kind-30078. dry_run = unsigned preview. Live needs approve + 
    SCP_ANTIGEN_PUBLISH_CONSENT=1. No MCP seckey_hex. Relays ⊆ SCP_ANTIGEN_RELAY_ALLOWLIST."""
    with operator_consent.mcp_transport_scope():
        try:
            return json.dumps(nostr_mod.publish_announcement(
                _parse_bundle_object(bundle_json),
                seckey_hex=None,
                relays=_parse_allowlist(relays),
                dry_run=dry_run,
                approve=approve,
                allow_env_seckey=True,
            ))
        except json.JSONDecodeError:
            return _err(ValueError("bundle_json must be valid JSON"))
        except Exception as e:
            return _err(e)


@mcp.tool()
def scp_antigen_discover(allowlist: str | None = None, relays: str | None = None,
                         antigen_id: str | None = None, since: int | None = None,
                         until: int | None = None) -> str:
    """Subscribe to allowlisted issuer pubkey announcements. Relays ⊆ SCP_ANTIGEN_RELAY_ALLOWLIST."""
    with operator_consent.mcp_transport_scope():
        try:
            anns = nostr_mod.discover_announcements(
                allowlist=_parse_pubkey_allowlist(allowlist),
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
    """Fetch HTTPS payload + verify hash. Never auto-loads SCP_ANTIGEN_L402_TOKEN.
    Hosts from SCP_ANTIGEN_FETCH_HOST_ALLOWLIST only (allowlist arg ignored for hosts)."""
    with operator_consent.mcp_transport_scope():
        try:
            bare = expected_hash[7:] if expected_hash.startswith("sha256:") else expected_hash
            _ = allowlist
            payload = nostr_mod.fetch_payload(
                url,
                bare,
                l402_token=l402_token,
                host_allowlist=None,
                allow_env_l402_token=False,
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
    relays: str | None = None,
) -> str:
    """Fetch registry snapshot. HTTPS hosts from env; allowlist = issuer pubkeys for nostr.
    TLS verify from SCP_REGISTRY_TLS_VERIFY only (default on); no agent tls_verify arg."""
    with operator_consent.mcp_transport_scope():
        try:
            return json.dumps(registry_fetch_mod.fetch_registry(
                source,
                _parse_allowlist(allowlist),
                if_none_match=if_none_match,
                tls_verify=http_policy.env_tls_verify(),
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
) -> str:
    """R3 contribute. MCP refuses seckey_hex. Needs SCP_CONTRIBUTE_CONSENT;
    nostr/both also needs SCP_ANTIGEN_PUBLISH_CONSENT under MCP.
    TLS verify from SCP_REGISTRY_TLS_VERIFY only (default on)."""
    with operator_consent.mcp_transport_scope():
        try:
            if seckey_hex:
                return json.dumps({
                    "ok": False,
                    "error": "seckey_hex_not_allowed_on_mcp",
                    "submitted": False,
                })
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
                seckey_hex=None,
                tls_verify=http_policy.env_tls_verify(),
            ))
        except Exception as e:
            return _err(e)


@mcp.tool()
def scp_apply_registry_quarantine(quarantine_path: str, approve: bool = False) -> str:
    """Merge quarantined snapshot. Live merge needs SCP_REGISTRY_MERGE_CONSENT=1. No DEV_AUTO on MCP."""
    with operator_consent.mcp_transport_scope():
        try:
            return json.dumps(registry_ssot_mod.apply_merge(quarantine_path, approve=approve))
        except Exception as e:
            return _err(e)


def main():
    operator_consent.mark_mcp_transport()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
