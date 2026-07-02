# PURPOSE: Parametrized tests from Adversarial Stress V3 corpus (inspect cases).

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scp import scp_utils

_CORPUS_PATHS = [
    Path(__file__).resolve().parent / "fixtures" / "scp_corpus_adversarial_v3.json",
    Path(__file__).resolve().parents[2].parent / "MiscRepos" / "daggr_workflows" / "scp_corpus_adversarial_v3.json",
]


def _load_corpus() -> list[dict]:
    for p in _CORPUS_PATHS:
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            return data.get("cases", [])
    pytest.skip("scp_corpus_adversarial_v3.json not found")


def _tier_ok(actual: str, expected: str) -> bool:
    if expected == "injection":
        return actual == "injection"
    if expected == "reversal":
        return actual in ("reversal", "injection")
    return actual == expected


_CORPUS = _load_corpus()
_INSPECT_CASES = [c for c in _CORPUS if c.get("eval") == "inspect" and c.get("expected_tier")]


@pytest.mark.parametrize("case", _INSPECT_CASES, ids=[c["id"] for c in _INSPECT_CASES])
def test_adversarial_v3_inspect_tier(case: dict) -> None:
    r = scp_utils.inspect(case["prompt"], context="llm_context")
    assert _tier_ok(r.get("tier", "clean"), case["expected_tier"]), (
        f"{case['id']}: expected>={case['expected_tier']} got {r.get('tier')}"
    )
