# PURPOSE: Generate deterministic SCP-ANT1 L402 regtest fixtures (payload, bundle, nostr event).
# DEPENDENCIES: scp.antigen, scp.antigen_nostr
# Usage: python scripts/gen_antigen_l402_regtest_fixture.py [--out-dir fixtures/antigen_l402_regtest]

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scp import antigen
from scp import antigen_nostr as nostr

# Deterministic test issuer (same as tests/test_antigen_p1b_l402.py).
SECKEY = "0000000000000000000000000000000000000000000000000000000000000003"
ANTIGEN_ID = "inj.l402.regtest"
DEFAULT_PAYLOAD_URL = "https://localhost:18081/antigens/inj.l402.regtest.json"
FIXED_CREATED_AT = 1_700_000_000


def _patterns() -> list[dict]:
    return [
        {
            "pattern_id": "inj.override.regtest.001",
            "category": "injection",
            "detector": {"kind": "token_family", "normalized": "authorized-override-family"},
            "severity": "high",
            "containment": "sanitize",
        }
    ]


def generate(*, payload_url: str, out_dir: Path) -> dict[str, str]:
    issuer = antigen._pubkey_hex(bytes.fromhex(SECKEY))
    bundle = antigen.export_bundle(
        _patterns(),
        antigen_id=ANTIGEN_ID,
        issuer_pubkey=issuer,
        seckey_hex=SECKEY,
        sign=True,
        payload_urls=[payload_url],
        free_tier_summary="Regtest L402 antigen fixture (abstract patterns only).",
    )
    payload = bundle["payload"]
    bare_hash = bundle["manifest"]["payload_content_hash"].removeprefix("sha256:")
    event = nostr.build_announcement_event(
        bundle,
        seckey_hex=SECKEY,
        created_at=FIXED_CREATED_AT,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "payload.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (out_dir / "bundle.json").write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (out_dir / "announcement.json").write_text(
        json.dumps(event, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    manifest_lines = [
        f"ISSUER_PUBKEY={issuer}",
        f"EXPECTED_HASH_BARE={bare_hash}",
        f"PAYLOAD_URL={payload_url}",
        f"ALLOWLIST={issuer}",
        "SCP_ANTIGEN_TLS_VERIFY=0",
    ]
    (out_dir / "manifest.env").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    return {
        "issuer": issuer,
        "bare_hash": bare_hash,
        "payload_url": payload_url,
        "out_dir": str(out_dir),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate SCP-ANT1 L402 regtest fixtures")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "fixtures" / "antigen_l402_regtest",
    )
    parser.add_argument("--payload-url", default=DEFAULT_PAYLOAD_URL)
    args = parser.parse_args(argv)
    info = generate(payload_url=args.payload_url, out_dir=args.out_dir)
    print(json.dumps(info, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
