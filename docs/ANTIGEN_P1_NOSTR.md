# SCP-ANT1 Antigen P1 — Nostr publish/subscribe

**Version:** scp-mcp 0.1.6 (P1b adds L402 retry — see [ANTIGEN_P1B_L402_SPIKE.md](ANTIGEN_P1B_L402_SPIKE.md))
**Kind:** `30078` (parameterized-replaceable antigen announcements)

## Overview

P1 adds decentralized discovery transport on top of P0 signed bundles:

1. **Publish** — broadcast a signed nostr event (hash + summary + HTTPS URLs only on relay).
2. **Discover** — subscribe to allowlisted issuer pubkeys on one or more relays.
3. **Fetch** — download payload over HTTPS, verify `sha256`, quarantine via `import_bundle` (no auto-merge).

Design: [ADR_ANTIGEN_DECENTRALIZATION_SUBSTRATE](https://github.com/manithecrowds/MiscRepos/blob/main/docs/agent/ADR_ANTIGEN_DECENTRALIZATION_SUBSTRATE.md) (MiscRepos).

## Install

```bash
pip install -e ".[dev,antigen-nostr]"
```

`websocket-client` is required only for live relay publish/subscribe. Build/parse/fetch work without it.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `SCP_ANTIGEN_RELAYS` | Comma-separated WSS URLs (default: `wss://relay.damus.io`, `wss://nos.lol`) |
| `SCP_ANTIGEN_ISSUER_ALLOWLIST` | Comma-separated issuer pubkeys (hex); **empty = reject all** |
| `NOSTR_SECKEY` | Publisher seckey (64-hex or `nsec1…`); never commit or log |
| `SCP_ANTIGEN_L402_TOKEN` | Operator-supplied L402 `macaroon:preimage` for paid HTTPS retry; never commit or log |
| `SCP_ANTIGEN_TLS_VERIFY` | Set to `0` to skip TLS certificate verification on HTTPS fetch (**regtest/self-signed only**; default `1`) |
| `SCP_ANTIGEN_NOSTR_INTEGRATION` | Set to `1` to run optional live-relay pytest smoke |

## CLI examples

Export and host the bundle JSON at an HTTPS URL, then add `payload_urls` to the manifest (or embed when exporting in your pipeline).

```bash
# Dry-run event build (no relay write)
python -m scp.antigen_cli publish --bundle bundle.json --seckey-hex "$NOSTR_SECKEY" --dry-run

# Publish to relays
python -m scp.antigen_cli publish --bundle bundle.json --seckey-hex "$NOSTR_SECKEY" \
  --relays "wss://relay.damus.io,wss://nos.lol"

# Discover announcements (JSON lines)
python -m scp.antigen_cli discover --allowlist "$ISSUER_PUBKEY"

# Discover + fetch + quarantine (still NO merge)
python -m scp.antigen_cli discover --allowlist "$ISSUER_PUBKEY" --fetch

# Fetch with operator-paid L402 token (after human pays 402 invoice)
python -m scp.antigen_cli fetch "$PAYLOAD_URL" --hash "$BARE_SHA256" --l402-token "$MACAROON:$PREIMAGE"
```

## MCP tools (separate server)

Run: `python -m scp.antigen_mcp`

| Tool | Role |
|------|------|
| `scp_antigen_publish` | Publish announcement |
| `scp_antigen_discover` | Subscribe / list metadata |
| `scp_antigen_fetch` | HTTPS fetch + hash verify; surfaces 402 metadata; optional `l402_token` for operator-paid retry — does **not** auto-spend |

Merge still requires `scp_antigen_merge` with `approve=True`.

## Human gates

- **No auto-merge** from relay, fetch, or discover.
- **Allowlist fail-closed** — empty allowlist rejects all issuers.
- **Payment ≠ attestation** — 402 responses do not bypass verify/quarantine.
- Do not commit `NOSTR_SECKEY`, relay auth tokens, or L402 macaroons.

## Tests

```bash
pytest tests/test_antigen_p0.py tests/test_antigen_p1_nostr.py tests/test_antigen_p1b_l402.py
pytest  # full suite
SCP_ANTIGEN_NOSTR_INTEGRATION=1 pytest tests/test_antigen_p1_nostr.py -k live
```
