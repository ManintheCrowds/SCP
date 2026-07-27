# PURPOSE: Operator env attestation helpers (mirror SCP_CONTRIBUTE_CONSENT dual-gate).
# DEPENDENCIES: os
# MODIFICATION NOTES: AppSec 2026-07-24 — shared by antigen publish / registry merge

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

PUBLISH_CONSENT_ENV = "SCP_ANTIGEN_PUBLISH_CONSENT"
MERGE_CONSENT_ENV = "SCP_REGISTRY_MERGE_CONSENT"
MCP_TRANSPORT_ENV = "SCP_MCP_TRANSPORT"


def consent_attested(env_var: str) -> bool:
    """True only when operator set env_var exactly to '1' (agent cannot forge by default)."""
    return os.environ.get(env_var) == "1"


def mcp_transport_active() -> bool:
    """True when running under antigen/registry MCP (set by antigen_mcp entrypoint)."""
    return os.environ.get(MCP_TRANSPORT_ENV) == "1"


def mark_mcp_transport() -> None:
    """Call from MCP server main so library gates can detect MCP."""
    os.environ[MCP_TRANSPORT_ENV] = "1"


@contextmanager
def mcp_transport_scope() -> Iterator[None]:
    """Scoped MCP transport flag for individual tool invocations (test-safe)."""
    prev = os.environ.get(MCP_TRANSPORT_ENV)
    mark_mcp_transport()
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(MCP_TRANSPORT_ENV, None)
        else:
            os.environ[MCP_TRANSPORT_ENV] = prev
