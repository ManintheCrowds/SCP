# PURPOSE: Tests for setup_mycelium_nostr_key operator script.
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from setup_mycelium_nostr_key import setup_mycelium_nostr_key  # noqa: E402

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def test_setup_creates_key_and_pubkey_format(tmp_path: Path):
    sec_path = tmp_path / "nostr_maintainer.sec"
    result = setup_mycelium_nostr_key(sec_path=sec_path, force=False)
    assert result["ok"] is True
    assert result["created"] is True
    assert _HEX64.match(result["issuer_pubkey"])
    assert sec_path.is_file()
    seckey = sec_path.read_text(encoding="utf-8").strip()
    assert _HEX64.match(seckey)
    assert "seckey" not in json.dumps(result)


def test_setup_refuses_overwrite_without_force(tmp_path: Path):
    sec_path = tmp_path / "nostr_maintainer.sec"
    setup_mycelium_nostr_key(sec_path=sec_path, force=False)
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        setup_mycelium_nostr_key(sec_path=sec_path, force=False)


def test_setup_force_replaces(tmp_path: Path):
    sec_path = tmp_path / "nostr_maintainer.sec"
    first = setup_mycelium_nostr_key(sec_path=sec_path, force=False)
    second = setup_mycelium_nostr_key(sec_path=sec_path, force=True)
    assert first["issuer_pubkey"] != second["issuer_pubkey"]
