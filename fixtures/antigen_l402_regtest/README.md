# SCP-ANT1 L402 regtest fixtures

Deterministic antigen payload for manual E1–E5 against the local Aperture stack.

## Regenerate

```powershell
cd C:\Users\Dell\Documents\GitHub\SCP
python scripts/gen_antigen_l402_regtest_fixture.py
```

Uses test issuer seckey `…0003` (same as `tests/test_antigen_p1b_l402.py`). **Never use this key outside regtest.**

## Files

| File | Role |
|------|------|
| `payload.json` | HTTPS body served behind L402 (patterns only) |
| `bundle.json` | Signed `scp.pattern_bundle.v0` |
| `announcement.json` | Signed nostr kind `30078` event for E4 `import_from_announcement` |
| `manifest.env` | Operator env block (`PAYLOAD_URL`, `EXPECTED_HASH_BARE`, `ISSUER_PUBKEY`, `ALLOWLIST`) |

## Docker bind mount

The regtest backend container mounts `payload.json` as `inj.l402.regtest.json` under `/antigens/`.

See MiscRepos [ANTIGEN_L402_REGTEST_RUNBOOK.md](../../../MiscRepos/local-proto/docs/ANTIGEN_L402_REGTEST_RUNBOOK.md).
