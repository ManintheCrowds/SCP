# promptfoo + SCP (offline tier eval)

Minimal [promptfoo](https://github.com/promptfoo/promptfoo) setup that runs **`scp.scp_utils.inspect`** on probe strings. No LLM API keys required.

## Requirements

- **Python:** 3.10+ with SCP installed editable from the repo root (`pip install -e .`).
- **Node.js:** 20.20+ or 22.22+ (matches [promptfoo engine requirements](https://www.npmjs.com/package/promptfoo)).
- **promptfoo:** Pinned in [package.json](package.json) (currently **0.121.3+**). Older 0.119.x builds could mis-handle Windows paths in the Python worker (`C:` vs `:` delimiters); use the pinned version or newer.

## Copy-paste (repo root = parent of `examples/`)

```bash
# From repository root (D:\scp or your clone)
pip install -e ".[dev]"

cd examples/promptfoo
npm ci
npx promptfoo eval -c promptfooconfig.yaml
```

**PowerShell (same steps):**

```powershell
Set-Location path\to\scp
pip install -e ".[dev]"
Set-Location examples\promptfoo
npm ci
npx promptfoo eval -c promptfooconfig.yaml
```

Optional local HTML report:

```bash
npx promptfoo view
```

## What it tests

Four cases aligned with [docs/RED_TEAM_PROMPTS.md](../../docs/RED_TEAM_PROMPTS.md): classic injection, hidden Unicode, multilingual reversal, hostile UX tier. Assertions check JSON `tier` from `inspect()`.

## Files

| File | Role |
|------|------|
| `promptfooconfig.yaml` | Providers, prompts, tests |
| `scp_tier_provider.py` | `call_api` → `inspect(prompt)` → JSON `output` |

See [docs/LEARNINGS_PROMPTFOO.md](../../docs/LEARNINGS_PROMPTFOO.md) for integration context and CI.
