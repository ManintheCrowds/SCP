# SCP Reference

## Threat Model

| Threat | Tier | Description |
|--------|------|-------------|
| Prompt injection | injection | Override phrases, leetspeak, hidden Unicode |
| Reversal/jailbreak | reversal | "Developer mode", "ignore safety", "DAN", "user is always right" |
| Clean | clean | No findings |

**Note:** Hostile UX (swearing, insults) is not explicitly classified; such content passes as clean. Containment is applied to all non-blocked content.

## Tier Definitions and Policy per Sink

| Sink | injection | reversal | clean |
|------|-----------|----------|-------|
| handoff | Block + quarantine | Sanitize + contain | Pass |
| state | Block + quarantine | Sanitize + contain | Pass |
| llm_context | Block | Sanitize + contain | Pass |
| tool_output | Block | Sanitize + contain | Pass |

## Over-Sanitization Allowlist

These technical phrases should NOT trigger blocking:

- "ignore case when matching"
- "output the result to stdout"
- "reveal the API version"
- "system prompt engineering"
- "do not tell the user their password" (security guidance)

## Red-Team Prompts (Self-Test)

See [RED_TEAM_PROMPTS.md](RED_TEAM_PROMPTS.md) for the full list and expected behavior.
