# PURPOSE: The mask-check job collects every tests/test_*.py module.

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOW = _REPO / ".github" / "workflows" / "ci.yml"
# Pre-existing failures that are not masker regressions.
_ALLOWED_IGNORE = frozenset(
    {
        "tests/test_setup_mycelium_nostr_key.py",
        "tests/test_contract_document_hash.py",
    }
)
_ROUND4 = frozenset(
    {
        "tests/test_unbalanced_quote_join.py",
        "tests/test_egress_normalize_rescan.py",
        "tests/test_mask_check_round3_files.py",
        "tests/test_mask_linear_time.py",
        "tests/test_mask_check_runner_fallback.py",
        "tests/test_gitleaks_full_range.py",
        "tests/test_log_masks_before_cap.py",
        "tests/test_plain_mask_memory.py",
    }
)


def _mask_section() -> str:
    text = _WORKFLOW.read_text(encoding="utf-8")
    return text.split("mask-check:", 1)[1].split("\n  CI:", 1)[0]


def _ignored(section: str) -> set[str]:
    return set(re.findall(r"--ignore=(\S+)", section))


def _collected(section: str, on_disk: set[str]) -> set[str]:
    ignored = _ignored(section)
    if "pytest tests/test_*.py" in section:
        return {name for name in on_disk if name not in ignored}
    return {name for name in on_disk if name in section}


def test_every_test_module_is_collected() -> None:
    section = _mask_section()
    on_disk = {f"tests/{path.name}" for path in (_REPO / "tests").glob("test_*.py")}
    ignored = _ignored(section)
    collected = _collected(section, on_disk)
    assert ignored == _ALLOWED_IGNORE
    assert collected == on_disk - _ALLOWED_IGNORE
    assert _ROUND4 <= collected
    assert _ROUND4 <= on_disk
