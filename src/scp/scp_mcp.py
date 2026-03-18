# PURPOSE: MCP server for Secure Contain Protect (SCP).
# GUARDRAIL: No shutdown, suicide, or self-termination tools.

"""
SCP MCP Server. Exposes inspect, sanitize, contain, quarantine, validate_output, mask_secrets, run_pipeline.
"""

import json

from mcp.server.fastmcp import FastMCP

from . import scp_utils

mcp = FastMCP("SCP")


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


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
