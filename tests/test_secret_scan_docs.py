# PURPOSE: The scan and mask limits that need an owner are written down.

from __future__ import annotations

from pathlib import Path

_DOC = Path(__file__).resolve().parents[1] / "docs" / "SECRET_SCAN.md"


def test_secret_scan_doc_covers_exemptions_and_progress_bars() -> None:
    text = _DOC.read_text(encoding="utf-8")
    required = (
        "scripts/gitleaks_blob_allow.txt",
        "BASE_SHA",
        "ELF",
        "PDF",
        ".pyc",
        "font",
        "cursor up",
        "cursor hide",
        "bracketed paste",
        "8-bit CSI",
        "does not erase a benign paragraph",
        "types.CodeType",
        "constants",
        "marshal.load",
        "Unlisted bytecode never reaches that walk",
    )
    missing = [phrase for phrase in required if phrase not in text]
    assert missing == []


def test_narrow_jwt_wraps_are_disclosed_at_the_measured_widths() -> None:
    text = _DOC.read_text(encoding="utf-8")
    required = (
        "tests/test_jwt_wrap_widths.py",
        "| 4 | 96/200 | 65/200 |",
        "| 15 | 41/200 | 41/200 |",
        "| 16 | 0/200 | 0/200 |",
        "Width 15 is 41/200",
    )
    missing = [phrase for phrase in required if phrase not in text]
    assert missing == []
