# PURPOSE: The round-3 masker tests stay inside the mask-check collection.

from __future__ import annotations

import re
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
    assert "pytest tests " in section or "pytest tests\n" in section
    ignored = set(re.findall(r"--ignore=(\S+)", section))
    for name in _ROUND3:
        assert name not in ignored
