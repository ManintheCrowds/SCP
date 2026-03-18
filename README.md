# SCP — Secure Contain Protect

Inspect, sanitize, contain, and quarantine unknown or potentially hazardous content before persisting or feeding to LLM. MCP server for agent-native content safety.

**Guard** in the Guard–Guide–Build taxonomy. Per OWASP LLM01/LLM06.

## Pipeline

1. **Inspect** — Classify content: `injection` | `reversal` | `clean`
2. **Sanitize** — Strip hidden Unicode, redact override phrases (when tier is reversal)
3. **Contain** — Wrap content so it is treated as data (markdown fence or XML tag)
4. **Quarantine** — Move suspect content to isolated storage (when tier is injection)

## Tier-Based Actions

| Tier | Action |
|------|--------|
| injection | Block; do not persist or feed to LLM; optionally quarantine |
| reversal | Sanitize, then contain |
| clean | Pass through |

## MCP Tools

- `scp_inspect(content, context?)` — Classify without changing content
- `scp_sanitize(content, mode?)` — Strip/neutralize known bad patterns
- `scp_contain(content, wrapper?)` — Wrap content as data
- `scp_quarantine(content, reason, source)` — Isolate suspect content
- `scp_list_quarantine()` — List quarantine entries
- `scp_purge_quarantine(quarantine_id?, older_than_days?)` — Purge quarantine
- `scp_validate_output(content, tool_name?)` — Check tool output before use
- `scp_mask_secrets(content)` — Redact credentials/PII
- `scp_run_pipeline(content, sink, options?)` — One-shot for high-risk sinks

## Install

```bash
pip install -e .
# or: pip install mcp
```

## Run MCP Server

```bash
python -m scp.scp_mcp
```

Add to `mcp.json`:

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

Set `PYTHONPATH` or install the package so `scp` is importable.

## Environment

| Variable | Description |
|----------|-------------|
| `SCP_QUARANTINE_DIR` | Quarantine storage path (default: `./scp_quarantine`) |
| `OLLAMA_BASE_URL` | For semantic judge (default: `http://localhost:11434`) |
| `OLLAMA_MODEL` | For semantic judge (default: `llama3.2`) |
| `SCP_SEMANTIC_JUDGE` | Set to `1` to enable semantic judge globally |

## Threat Registry

Patterns in `scp_threat_registry.json`: power_words, multilingual_override, jailbreak_nicknames, mythic_framing, bitcoin_inscription_override. Version bump on change.

## Documentation

- [docs/REFERENCE.md](docs/REFERENCE.md) — Threat model, tier definitions, over-sanitization allowlist
- [docs/RED_TEAM_PROMPTS.md](docs/RED_TEAM_PROMPTS.md) — Self-test prompts and expected behavior
- [docs/INTEGRATION.md](docs/INTEGRATION.md) — SCP as guardrail: verification before persist, high-risk sinks
- [docs/LEARNINGS_PROMPTFOO.md](docs/LEARNINGS_PROMPTFOO.md) — promptfoo integration and inspection results
- [examples/README.md](examples/README.md) — Daggr + Gradio integration example

## Guardrail

SCP has no shutdown, suicide, or self-termination commands. SCP inspects, sanitizes, contains, and quarantines content—it does not self-destruct.

## License

MIT
