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

### Core server (v1.0 + v1.1 optional)

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

**v1.0 tools:** `scp_inspect`, `scp_sanitize`, `scp_contain`, `scp_quarantine`, `scp_list_quarantine`, `scp_purge_quarantine`, `scp_validate_output`, `scp_mask_secrets`, `scp_run_pipeline`.

**v1.1 optional (read-only):** `scp_registry_summary`, `scp_registry_section`.

### Dual-server mycelium (SCP-R5)

Enable mesh extension alongside core:

```json
{
  "mcpServers": {
    "scp": {
      "command": "python",
      "args": ["-m", "scp.scp_mcp"]
    },
    "scp-antigen": {
      "command": "python",
      "args": ["-m", "scp.antigen_mcp"]
    }
  }
}
```

**Operator flow:**

```text
scp_fetch_registry(source, allowlist)              [scp-antigen] → quarantine_path
scp_apply_registry_quarantine(path, approve=true)  [scp-antigen] → SSOT + projection
scp_registry_summary()                             [scp] → confirm section counts
scp_inspect(content) / scp_run_pipeline            [scp] → uses updated registry
```

### Registry environment

| Variable | Purpose |
|----------|---------|
| `SCP_THREAT_REGISTRY_PATH` | Override registry JSON for inspect + v1.1 read tools (and merge projection write target) |
| `SCP_PATTERN_SSOT_PATH` | pattern_record SSOT store (`~/.scp/pattern_records.json` default) |
| `SCP_REGISTRY_SECTION_ALLOWLIST` | Comma-separated allowlist for `scp_registry_section` |
| `SCP_REGISTRY_MERGE_DEV_AUTO` | Dev-only auto-merge low-risk patterns on apply |
| `SCP_DEBUG_META` | `1` to expose resolved registry path in summary responses |

**Load order (inspect + v1.1):** env path (if exists) → `~/.scp/threat_registry_projection.json` → packaged `scp_threat_registry.json`.

### Live registry smoke (opt-in network)

Non-interactive CLI against [scp-mycelium-registry v0.1.0](https://github.com/ManintheCrowds/scp-mycelium-registry):

```powershell
cd C:\Users\Dell\Documents\GitHub\SCP
python scripts/mycelium_live_smoke.py --dry-run
python scripts/mycelium_live_smoke.py --approve-merge --json
```

Pytest (skipped unless `SCP_MYCELIUM_LIVE_E2E=1`):

```powershell
$env:SCP_MYCELIUM_LIVE_E2E = "1"
python -m pytest tests/test_mycelium_live_e2e.py -v
```

See [SCP_R6_PRIVACY_CONSENT.md](SCP_R6_PRIVACY_CONSENT.md) — Path B publish requires `SCP_CONTRIBUTE_CONSENT=1` and `SCP_CONTRIBUTE_HOST_ALLOWLIST` (destination hosts). Antigen HTTPS fetch requires `SCP_ANTIGEN_FETCH_HOST_ALLOWLIST` (env-only; MCP cannot expand hosts). Antigen publish requires `SCP_ANTIGEN_PUBLISH_CONSENT=1` (also required for MCP `scp_contribute_pattern` nostr/both). Registry merge/apply requires `SCP_REGISTRY_MERGE_CONSENT=1`. Relays for MCP require `SCP_ANTIGEN_RELAY_ALLOWLIST`.

### Nostr discovery announce (R2 step 7)

**One-time key setup** (writes `~/.scp/nostr_maintainer.sec`, prints pubkey only):

```powershell
cd C:\Users\Dell\Documents\GitHub\SCP
pip install -e ".[dev,antigen-nostr]"
python scripts/setup_mycelium_nostr_key.py --json
```

Load seckey into session (never commit):

```powershell
$env:NOSTR_SECKEY = (Get-Content $env:USERPROFILE\.scp\nostr_maintainer.sec -Raw).Trim()
python scripts/announce_registry_snapshot.py --version 0.1.0 --json
python scripts/announce_registry_snapshot.py --version 0.1.0 --publish --json
```

Paste `issuer_pubkey` into [scp-mycelium-registry GOVERNANCE](https://github.com/ManintheCrowds/scp-mycelium-registry/blob/main/GOVERNANCE.md) §Path B before relying on fetch allowlists.

See [SCP_R5_MCP_INTEGRATION.md](SCP_R5_MCP_INTEGRATION.md) and [README.md](../README.md) for full tool reference.

---

## Complementary Controls

SCP operates at the **content layer** (inspect, sanitize, contain, quarantine). For **runtime isolation** (sandboxing, privilege limits, network policy), use complementary controls:

- **NVIDIA OpenShell / NemoClaw** — Sandboxed agent runtime with Landlock, seccomp, network namespaces; declarative YAML policy. [NVIDIA NemoClaw docs](https://docs.nvidia.com/nemoclaw/)
- **Docker** — Container isolation for agent processes
- **Windows host trust (accidental execution)** — Defender, SmartScreen, WDAC or AppLocker belong to the host security owner, not to SCP. Do not add process suspend, kill, or shutdown tools to this MCP. Do not vendor third-party GPL process-watchers into this MIT tree. Untrusted files used as LLM or handoff requirements stay on the inspect → sanitize → contain path plus a human gate; they are not a background process killer.
