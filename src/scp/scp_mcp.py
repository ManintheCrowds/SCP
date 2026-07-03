# PURPOSE: MCP server for Secure Contain Protect (SCP).
# GUARDRAIL: No shutdown, suicide, or self-termination tools.

"""
SCP MCP Server. Exposes inspect, sanitize, contain, quarantine, validate_output, mask_secrets, run_pipeline.
v1.1 optional: scp_registry_summary, scp_registry_section (read-only).
"""

import json
import os
import re

from mcp.server.fastmcp import FastMCP

from . import registry_paths
from . import scp_utils

mcp = FastMCP("SCP")

_DEBUG_META_ENV = "SCP_DEBUG_META"
_REGISTRY_SECTION_ALLOWLIST_ENV = "SCP_REGISTRY_SECTION_ALLOWLIST"
_MAX_REGISTRY_SECTION_CHARS = 4096
_DEFAULT_REGISTRY_SECTION_MAX_CHARS = 2048
_REGISTRY_SECTION_NAME_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
_DEFAULT_REGISTRY_SECTION_ALLOWLIST: frozenset[str] = frozenset(
    {
        "version",
        "updated",
        "power_words",
        "multilingual_override",
        "jailbreak_nicknames",
        "mythic_framing",
        "hostile_ux",
        "bitcoin_inscription_override",
        "bitcoin_tx_mempool_override",
    }
)


def _registry_section_allowlist() -> frozenset[str]:
    raw = os.environ.get(_REGISTRY_SECTION_ALLOWLIST_ENV)
    if raw is not None and raw.strip():
        return frozenset(p.strip() for p in raw.split(",") if p.strip())
    return _DEFAULT_REGISTRY_SECTION_ALLOWLIST


def _bounded_allowlist_keys_for_error() -> list[str]:
    return sorted(_registry_section_allowlist())[:32]


def _debug_meta_enabled() -> bool:
    return os.environ.get(_DEBUG_META_ENV, "0") == "1"


def _error(code: str, message: str, details: dict | None = None) -> str:
    payload: dict = {"error": {"code": code, "message": message}}
    if details:
        payload["error"]["details"] = details
    return json.dumps(payload)


def _err(e: Exception) -> str:
    return json.dumps({"error": str(e)})


@mcp.tool()
def scp_inspect(content: str, context: str | None = None) -> str:
    """Inspect content for injection, reversal, or hostile patterns. Returns {tier, findings, risk_score, categories}."""
    try:
        return json.dumps(scp_utils.inspect(content, context=context))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_sanitize(content: str, mode: str = "strip_unicode") -> str:
    """Sanitize content. mode: strip_unicode | redact_phrases | full. Returns {sanitized, changes}."""
    try:
        return json.dumps(scp_utils.sanitize(content, mode=mode))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_contain(content: str, wrapper: str = "markdown_fence") -> str:
    """Wrap content so it is treated as data. wrapper: markdown_fence | xml_tag. Returns {contained}."""
    try:
        contained = scp_utils.contain(content, wrapper=wrapper)
        return json.dumps({"contained": contained})
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_quarantine(content: str, reason: str, source: str) -> str:
    """Quarantine suspect content to isolated storage. Returns {quarantine_id, path}."""
    try:
        return json.dumps(scp_utils.quarantine(content, reason=reason, source=source))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_list_quarantine() -> str:
    """List quarantine entries. Returns [{quarantine_id, reason, source, path}]."""
    try:
        return json.dumps(scp_utils.list_quarantine())
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_purge_quarantine(quarantine_id: str | None = None, older_than_days: int | None = None) -> str:
    """Purge quarantine: one by id, or all if id omitted. Optional older_than_days for retention."""
    try:
        return json.dumps(scp_utils.purge_quarantine(quarantine_id=quarantine_id, older_than_days=older_than_days))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_validate_output(content: str, tool_name: str | None = None) -> str:
    """Validate tool output before use. Returns {safe, findings}."""
    try:
        result = scp_utils.inspect(content, context="tool_output")
        tier = result.get("tier", "clean")
        return json.dumps({"safe": tier != "injection", "findings": result})
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_mask_secrets(content: str) -> str:
    """Redact credentials and PII from content. Returns {masked, redacted_count}."""
    try:
        return json.dumps(scp_utils.mask_secrets(content))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_run_pipeline(content: str, sink: str = "handoff", options: str | None = None) -> str:
    """Run inspect -> sanitize -> contain. For injection tier, block. sink: handoff | state | llm_context | tool_output.
    options: JSON string with quarantine_on_block, wrapper, semantic_judge (bool).
    Returns {result, blocked, report}."""
    try:
        opts = json.loads(options) if options else {}
        return json.dumps(scp_utils.run_pipeline(content, sink=sink, options=opts))
    except json.JSONDecodeError:
        return _err(ValueError("options must be valid JSON"))
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_registry_summary() -> str:
    """Read-only: threat registry file path, fingerprint, and per-section entry counts (if present)."""
    try:
        p = registry_paths.resolve_threat_registry_path()
        if not p:
            return _error(
                "not_found",
                "Threat registry file not found",
                {"hint": "Set SCP_THREAT_REGISTRY_PATH or apply a registry merge projection"},
            )
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        summary: dict = {}
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list):
                    summary[k] = len(v)
                elif isinstance(v, dict):
                    summary[k] = len(v)
                else:
                    summary[k] = 1
        path_out = str(p.resolve()) if _debug_meta_enabled() else "redacted"
        return json.dumps({"registry_path": path_out, "sections": summary})
    except Exception as e:
        return _err(e)


@mcp.tool()
def scp_registry_section(section: str, max_chars: int = _DEFAULT_REGISTRY_SECTION_MAX_CHARS) -> str:
    """Read-only: one allowlisted section of the threat registry as JSON text (strict cap)."""
    try:
        if not isinstance(section, str) or not _REGISTRY_SECTION_NAME_RE.match(section):
            return _error("invalid_input", "Invalid registry section identifier")
        allow = _registry_section_allowlist()
        if section not in allow:
            return _error(
                "invalid_input",
                "Threat registry section not allowlisted for excerpt",
                {"section": section, "allowlisted_sections": _bounded_allowlist_keys_for_error()},
            )
        p = registry_paths.resolve_threat_registry_path()
        if not p:
            return _error("not_found", "Threat registry file not found")
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(data, dict) or section not in data:
            return _error(
                "invalid_input",
                "Threat registry section not found or empty",
                {"section": section},
            )
        try:
            mc = int(max_chars)
        except (TypeError, ValueError):
            return _error("invalid_input", "max_chars must be an integer")
        if mc < 1:
            return _error("invalid_input", "max_chars must be at least 1")
        safe_chars = min(mc, _MAX_REGISTRY_SECTION_CHARS)
        full = json.dumps({section: data[section]}, ensure_ascii=False)
        truncated = len(full) > safe_chars
        excerpt = full if not truncated else full[:safe_chars] + "…"
        return json.dumps({"section": section, "excerpt": excerpt, "truncated": truncated})
    except Exception as e:
        return _err(e)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
