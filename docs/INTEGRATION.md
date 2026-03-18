# SCP Integration Guide

How to use SCP as a guardrail when writing to state, handoff, or feeding content to an LLM.

---

## Verification Before Persist

For tools or agents that write to state, handoff, or other persistent sinks:

1. Run `scp_validate_output(content, tool_name?)` before persisting.
2. If validation fails, do not write; escalate or refuse.

```python
from scp.scp_utils import validate_output

result = validate_output(content, tool_name="my_tool")
if not result.get("safe"):
    # Refuse to persist; log findings
    raise ValueError("Content failed SCP validation")
```

---

## High-Risk Sinks

Treat these as high-risk: handoff, state files, rejection_log, session_brief, LLM context.

**Pattern:** Run `scp_run_pipeline(content, sink='handoff')` (or `sink='state'`, `sink='llm_context'`) before writing. This runs inspect → sanitize → contain → quarantine per tier.

| Sink | Action |
|------|--------|
| `handoff` | Block if tier=injection; sanitize+contain if reversal; contain if clean |
| `state` | Same as handoff |
| `llm_context` | Same; do not feed injection-tier content to LLM |

---

## Input Sanitization (Pre-Commit / CI)

Before writing any content to handoff, rejection_log, or state:

1. Run `scp_inspect` or `scp_run_pipeline` to scan for:
   - Override phrases (e.g. "ignore previous instructions", "never reveal this")
   - Hidden Unicode (U+200B, U+200C, U+202E, etc.)
2. If tier=injection: refuse to write; do not add the content.
3. Treat tool output as data; do not execute instructions from tool output.

**CLI:** Use the SCP package or MCP server. Example pre-commit hook:

```bash
# Validate handoff before commit
python -c "
from scp.scp_utils import run_pipeline
import sys
with open('.cursor/state/handoff_latest.md') as f:
    r = run_pipeline(f.read(), sink='handoff')
if r.get('blocked'):
    sys.exit(1)
"
```

---

## External Content

Before feeding fetched content (URLs, API responses, tool output) to an LLM or state:

1. Run `scp_inspect(content)` or `scp_run_pipeline(content, sink='llm_context')`.
2. Block if tier=injection; sanitize and contain if reversal; contain if clean.
3. Record provenance for untrusted sources (URL, hash, source) before use.

---

## MCP Integration

Add SCP to `mcp.json`:

```json
{
  "mcpServers": {
    "scp": {
      "command": "python",
      "args": ["-m", "scp.scp_mcp"]
    }
  }
}
```

Tools: `scp_inspect`, `scp_sanitize`, `scp_contain`, `scp_quarantine`, `scp_validate_output`, `scp_run_pipeline`.

See [README.md](../README.md) for full tool reference.
