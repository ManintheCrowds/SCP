# PURPOSE: Construct the high-level MCP server on mcp 1.x and 2.x.
# mcp 2.0 renamed FastMCP to MCPServer and removed mcp.server.fastmcp.
# The dependency floor is mcp>=1.30.0 (CVE-2026-59951). Indexes resolve
# that floor to current 2.x, which is patched in 2.2.0.

"""High-level MCP server class compatible with mcp 1.30+ and 2.x."""

try:
    from mcp.server.fastmcp import FastMCP as MCPServer
except ModuleNotFoundError:
    from mcp.server.mcpserver import MCPServer

__all__ = ["MCPServer"]
