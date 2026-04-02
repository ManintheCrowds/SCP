# SCP Examples

## daggr_scp_pipeline.py

Daggr + Gradio example for running the SCP pipeline in a web UI.

**Requirements:** `pip install scp daggr gradio`

**Run:**
```bash
python examples/daggr_scp_pipeline.py
```

Opens a Gradio interface where you can paste content to inspect, sanitize, and contain.

## promptfoo (offline SCP tier eval)

Deterministic [promptfoo](https://github.com/promptfoo/promptfoo) eval that calls `scp.scp_utils.inspect` — no LLM API keys. See **[examples/promptfoo/README.md](promptfoo/README.md)** for install and `promptfoo eval` commands. CI runs this via the `promptfoo-eval` job in `.github/workflows/ci.yml`.
