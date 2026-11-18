# PURPOSE: The mask-check job runs the round-3 masker tests and refuses a short collection.

from __future__ import annotations

from pathlib import Path

_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
_ROUND3 = (
    "tests/test_egress_independent_guard.py",
    "tests/test_mask_round_trip.py",
    "tests/test_mask_linear_time.py",
    "tests/test_mask_check_reads_index.py",
    "tests/test_egress_exit_codes.py",
)


def test_mask_check_job_runs_round3_files_and_collection_floor() -> None:
    section = _WORKFLOW.read_text(encoding="utf-8").split("mask-check:", 1)[1].split("\n  CI:", 1)[0]
    for name in _ROUND3:
        assert name in section
    assert "EXPECTED_MASK_TESTS" in section
    assert "count < expected" in section
    assert "--collect-only" in section
