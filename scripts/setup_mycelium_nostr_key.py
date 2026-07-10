#!/usr/bin/env python3
# PURPOSE: Generate maintainer nostr keypair for mycelium registry announce (operator-only).
# DEPENDENCIES: coincurve (antigen-nostr extra), scp.antigen
"""CLI: python scripts/setup_mycelium_nostr_key.py --json

Writes seckey to ~/.scp/nostr_maintainer.sec (mode 600). Prints issuer_pubkey only by default.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from scp import antigen

DEFAULT_SEC_PATH = Path.home() / ".scp" / "nostr_maintainer.sec"


def _default_sec_path() -> Path:
    override = os.environ.get("SCP_MYCELIUM_NOSTR_SEC_PATH", "").strip()
    if override:
        return Path(override)
    return DEFAULT_SEC_PATH


def _generate_keypair() -> tuple[str, str]:
    try:
        import coincurve
    except ImportError as exc:
        raise SystemExit(
            "coincurve required. Install: pip install -e \".[dev,antigen-nostr]\""
        ) from exc
    private = coincurve.PrivateKey()
    seckey_hex = private.secret.hex()
    pubkey_hex = antigen._pubkey_hex(private.secret)
    return seckey_hex, pubkey_hex


def _restrict_permissions(path: Path) -> None:
    if os.name == "nt":
        return
    mode = path.stat().st_mode
    path.chmod(mode & ~stat.S_IRWXG & ~stat.S_IRWXO)


def _write_private_secret(path: Path, content: str, *, force: bool) -> None:
    data = (content + "\n").encode("utf-8")
    if force:
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            _restrict_permissions(tmp)
            os.replace(tmp, path)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        _restrict_permissions(path)
        return

    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SystemExit(
            f"refusing to overwrite existing key at {path} (use --force to replace)"
        ) from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    _restrict_permissions(path)


def setup_mycelium_nostr_key(
    *,
    sec_path: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Generate keypair and write seckey file. Returns metadata (no seckey unless caller adds)."""
    target = sec_path or _default_sec_path()
    if target.exists() and not force:
        raise SystemExit(
            f"refusing to overwrite existing key at {target} (use --force to replace)"
        )

    seckey_hex, pubkey_hex = _generate_keypair()
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_private_secret(target, seckey_hex, force=force)

    return {
        "ok": True,
        "issuer_pubkey": pubkey_hex,
        "sec_path": str(target),
        "created": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate maintainer nostr key for scp-mycelium-registry announce"
    )
    parser.add_argument(
        "--sec-path",
        type=Path,
        default=None,
        help="Seckey file path (default: ~/.scp/nostr_maintainer.sec)",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite existing seckey file")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--show-seckey",
        action="store_true",
        help="Include seckey_hex in output (recovery only; avoid in logs)",
    )
    args = parser.parse_args()

    target = args.sec_path or _default_sec_path()
    if target.exists() and not args.force:
        if not args.show_seckey:
            raise SystemExit(
                f"key already exists at {target}; use --force to replace or load for announce"
            )
        seckey_hex = target.read_text(encoding="utf-8").strip().lower()
        pubkey_hex = antigen._pubkey_hex(bytes.fromhex(seckey_hex))
        result: dict[str, Any] = {
            "ok": True,
            "issuer_pubkey": pubkey_hex,
            "sec_path": str(target),
            "created": False,
        }
        if args.show_seckey:
            result["seckey_hex"] = seckey_hex
    else:
        result = setup_mycelium_nostr_key(sec_path=target, force=args.force)
        if args.show_seckey:
            result["seckey_hex"] = target.read_text(encoding="utf-8").strip().lower()

    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f"issuer_pubkey: {result['issuer_pubkey']}")
    print(f"sec_path: {result['sec_path']}")
    if result.get("created"):
        print("Load for announce: $env:NOSTR_SECKEY = (Get-Content $env:USERPROFILE\\.scp\\nostr_maintainer.sec -Raw).Trim()")


if __name__ == "__main__":
    main()
