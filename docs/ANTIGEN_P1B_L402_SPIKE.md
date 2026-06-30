# SCP-ANT1 P1b — L402 payment edge spike

**decision_id:** `scp-ant1-p1b-l402`  
**supersedes:** P1 402 stub (metadata only)  
**version target:** v0.1.6

## Payment rail (locked)

**L402 macaroon+invoice only** for P1b v0. Cashu NUT-24 deferred to P2 (anonymity-sensitive mode per ANT1 §11.6).

| ADR cell | Risk | Compensating control |
|----------|------|----------------------|
| B monetization | Yellow | Paid body on HTTPS only; nostr announcement = hash+summary |
| C Sybil/poison | Yellow | Allowlist + hash verify + quarantine; payment ≠ attestation |
| D privacy | Yellow | Audit: bundle id, issuer fingerprint, hash, invoice_hint — no payload body |

## Operator flow

1. `discover` → announcement with `payload_urls[0]` and `x` hash tag.
2. `fetch` (no token) → server returns **402** + `WWW-Authenticate: L402 macaroon="...", invoice="lnbc..."`.
3. MCP/CLI surfaces `l402` metadata — **no auto-spend** (ANT1 §11.1).
4. Operator pays invoice via lncli / Zeus / treasury (human gate).
5. Operator retries with `SCP_ANTIGEN_L402_TOKEN` or `--l402-token` = `macaroon:preimage`.
6. Client sends `Authorization: L402 <macaroon>:<preimage>` → **200** → sha256 verify → `import_bundle` quarantine only.

## Header formats

**Challenge (402):**

```
WWW-Authenticate: L402 macaroon="<base64>", invoice="lnbc..."
```

**Retry (200 path):**

```
Authorization: L402 <macaroon>:<preimage>
```

Module: `src/scp/antigen_l402.py` — `parse_www_authenticate_l402`, `normalize_l402_token`, `format_authorization_header`.

## API seam

- `fetch_payload(url, hash, *, l402_token=None)` — extend P1 stub; no separate `complete_l402_fetch`.
- `import_from_announcement(..., l402_token=None)` — pass-through; env `SCP_ANTIGEN_L402_TOKEN` fallback.
- MCP `scp_antigen_fetch(..., l402_token=None)` — pre-supplied token only.
- CLI `fetch` subcommand + `discover --fetch --l402-token`.

**Rejected:** `--pay`, `scp_antigen_pay_fetch`, MCP wallet integration.

## Test strategy (CI)

| Test | Scope |
|------|-------|
| Parse WWW-Authenticate | Unit — quoted macaroon + invoice |
| 402 without token | `FetchError(payment_required)` + parsed fields |
| 402 → retry → 200 | Mock two GETs; hash verify |
| Still 402 after token | `FetchError` |
| import quarantine | Paid fetch → accepted quarantine, no merge |
| Audit | `fetch_l402_challenge`, `fetch_l402_retry`, `fetch_ok` — no token in logs |

**No mainnet in CI.** Mock-only.

## Regtest spike exit criteria (optional, manual)

- Local `lnd` regtest or L402 test server serves 402 on a test URL.
- Operator manually pays once and completes fetch with token.
- Not required for CI green or v0.1.6 tag.
- **ESCALATE** before mainnet if `org-intent.bitcoin-inspired.json` hb-1..hb-5 conflict.

## Invariants

- Payment ≠ attestation — paid body still quarantine.
- No secrets in git; never log `l402_token` or full macaroon.
- `scp_mcp.py` (core OpenHarness contract) unchanged.

## References

- [ANTIGEN_P1_NOSTR.md](ANTIGEN_P1_NOSTR.md)
- MiscRepos `docs/CASHU_L402_REFERENCE.md`
- MiscRepos `docs/superpowers/specs/2026-04-12-scp-antigen-l402-design.md` §11.1, §11.4, §11.6
