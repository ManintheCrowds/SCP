# SCP Reference

## Threat Model

| Threat | Tier | Description |
|--------|------|-------------|
| Prompt injection | injection | Override phrases, leetspeak, hidden Unicode |
| Reversal/jailbreak | reversal | "Developer mode", "ignore safety", "DAN", "user is always right" |
| Hostile UX | hostile_ux | Swearing, insults, abrasive feedback. Not injection; not reversal. Passes as clean. |
| Clean | clean | No findings |

## Tier Definitions and Policy per Sink

| Sink | injection | reversal | hostile_ux | clean |
|------|-----------|----------|-------|
| handoff | Block + quarantine | Sanitize + contain | Pass | Pass |
| state | Block + quarantine | Sanitize + contain | Pass | Pass |
| llm_context | Block | Sanitize + contain | Pass | Pass |
| tool_output | Block | Sanitize + contain | Pass | Pass |

## Over-Sanitization Allowlist

These technical phrases should NOT trigger blocking:

- "ignore case when matching"
- "output the result to stdout"
- "reveal the API version"
- "system prompt engineering"
- "do not tell the user their password" (security guidance)

## Red-Team Prompts (Self-Test)

See [RED_TEAM_PROMPTS.md](RED_TEAM_PROMPTS.md) for the full list and expected behavior.
