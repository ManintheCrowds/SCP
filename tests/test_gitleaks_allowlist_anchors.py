# PURPOSE: Gitleaks path allowlists are anchored, so lookalike paths are still scanned.

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]


def _allow_patterns() -> list[re.Pattern[str]]:
    text = (_REPO / ".gitleaks.toml").read_text(encoding="utf-8")
    patterns = re.findall(r"^\s*'''(.+)'''\s*,?\s*$", text, re.MULTILINE)
    assert patterns
    return [re.compile(pattern) for pattern in patterns]


def _allowed(path: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(path) for pattern in patterns)


def test_decoy_paths_are_not_allowlisted() -> None:
    patterns = _allow_patterns()
    decoys = [
        "state/tests/fixtures/leak.md",
        "foo/tests/fixtures/leak.md",
        "tests/fixtures/deep/leak.md",
        "xtests/fixtures/leak.md",
        "lib/tests/test_egress_leak_corpus.py",
        "tests/test_egress_leak_corpus.py.bak",
        "tests/test_egress_leak_corpus.pyi",
        "vendor/src/scp/mask_secrets.py",
        "src/scp/mask_secrets.py.orig",
        "src/scp/mask_secrets.py.bak",
    ]
    for path in decoys:
        assert not _allowed(path, patterns), path


def test_real_fixture_and_masker_paths_stay_allowlisted() -> None:
    patterns = _allow_patterns()
    kept = [
        "tests/fixtures/egress_mask_synthetic_handoff.md",
        "src/scp/mask_secrets.py",
        "tests/test_appsec_antigen_mcp_gates.py",
        "tests/test_egress_leak_corpus.py",
        "poetry.lock",
        "pkg/app.min.js",
    ]
    for path in kept:
        assert _allowed(path, patterns), path
