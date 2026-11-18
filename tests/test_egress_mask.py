# PURPOSE: Port of MiscRepos local-proto/tests/test_egress_mask.py.
# Imports target SCP's masker. process_handoff stays in MiscRepos; the handoff
# cases below exercise the same prepare_outbound / --egress-prepare contract.

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scp import mask_secrets, scp_utils

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "egress_mask_synthetic_handoff.md"
_MASK_SCRIPT = Path(__file__).resolve().parents[1] / "src" / "scp" / "mask_secrets.py"

_SENTINELS = (
    "Casey Example",
    "987-65-4321",
    "casey.example@syn.invalid",
    "212-555-0198",
    "03/15/1985",
)


def _run_masker(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_MASK_SCRIPT), *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_fixture_has_labeled_pii() -> None:
    assert _FIXTURE.is_file()
    raw = _FIXTURE.read_text(encoding="utf-8")
    for sentinel in _SENTINELS[1:]:
        assert sentinel in raw


def test_prepare_outbound_removes_labeled_pii() -> None:
    raw = _FIXTURE.read_text(encoding="utf-8")
    out = mask_secrets.prepare_outbound(raw)
    for sentinel in _SENTINELS[1:]:
        assert sentinel not in out
    assert "[DATE_REDACTED]" in out
    assert "[EMAIL_REDACTED]" in out
    assert "[PHONE_REDACTED]" in out
    assert "[SSN_REDACTED]" in out
    source = Path(mask_secrets.__file__).read_text(encoding="utf-8")
    assert "Casey Example" not in source


def test_prepare_outbound_fail_closed_when_mask_is_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    key = "AK" + "IA" + ("C" * 16)
    monkeypatch.setattr(mask_secrets, "mask", lambda text: text)
    with pytest.raises(mask_secrets.EgressMaskError) as exc_info:
        mask_secrets.prepare_outbound("Next step for " + key)
    assert exc_info.value.remaining


def test_existing_credential_mask_still_works() -> None:
    live = "sk" + "_live_" + "abcdefghijklmnop"
    text = f"password=hunter2 api_key={live} user@example.com"
    out = mask_secrets.mask(text)
    assert "hunter2" not in out
    assert live not in out
    assert "[EMAIL_REDACTED]" in out


def test_health_record_patterns_cover_labeled_fields() -> None:
    out = mask_secrets.mask(
        "Patient: Alex Sample. Date of Birth: 1/2/1999. Call (415) 555-0133 or +1-202-555-0147."
    )
    assert "Alex Sample" not in out
    assert "1/2/1999" not in out
    assert "415" not in out
    assert "202-555-0147" not in out
    assert "Patient: [NAME_REDACTED]" in out
    assert "Date of Birth: [DATE_REDACTED]" in out
    assert "DOB: [DATE_REDACTED]" not in out
    assert out.count("[PHONE_REDACTED]") == 2


def test_utils_redacted_count_includes_health_tokens() -> None:
    raw = _FIXTURE.read_text(encoding="utf-8")
    out = scp_utils.mask_secrets(raw)
    assert out["redacted_count"] == mask_secrets.redacted_count(out["masked"])
    assert out["redacted_count"] >= 5
    for sentinel in _SENTINELS[1:]:
        assert sentinel not in out["masked"]


def test_process_handoff_aborts_before_emit_when_sentinel_survives() -> None:
    """Fail closed: a residual sentinel produces no outbound text."""
    marker = "UNIQUE_MARKER_SHOULD_NOT_LEAK"
    proc = _run_masker("--egress-prepare", stdin=f"{marker} user@\nexample.com\n")
    assert proc.returncode != 0
    assert proc.stdout == ""
    assert proc.stderr.strip() == "egress-prepare fail-closed: residual match"
    assert marker not in proc.stderr


def test_process_handoff_masks_fixture_then_emits() -> None:
    raw = _FIXTURE.read_text(encoding="utf-8")
    proc = _run_masker("--egress-prepare", str(_FIXTURE))
    assert proc.returncode == 0
    assert proc.stdout == mask_secrets.prepare_outbound(raw)
    for sentinel in _SENTINELS[1:]:
        assert sentinel not in proc.stdout


def test_process_handoff_masks_pii_in_intent_and_session_brief() -> None:
    """PII that lives only in intent or session text must not survive prepare_outbound."""
    handoff = "Continue the named Next section. No clinical identifiers in this handoff.\n"
    intent = "Track note for Casey Example (DOB: 03/15/1985). casey.example@syn.invalid\n"
    brief = "Reach 212-555-0198. SSN 987-65-4321.\n"
    combined = (
        "handoff_latest.md\n"
        + handoff
        + "intent_surface.md\n"
        + intent
        + "session_brief.md\n"
        + brief
    )
    sent = mask_secrets.prepare_outbound(combined)
    for sentinel in _SENTINELS[1:]:
        assert sentinel not in sent, sentinel
    assert "intent_surface.md" in sent
    assert "session_brief.md" in sent
    assert "[DATE_REDACTED]" in sent
    assert "[EMAIL_REDACTED]" in sent
    assert "[PHONE_REDACTED]" in sent
    assert "[SSN_REDACTED]" in sent


def test_process_handoff_masks_before_excerpt_cap() -> None:
    """Mask the full value before any caller truncates, or a split email fragment leaks."""
    email = "casey.example@syn.invalid"
    prefix = "A" * 24
    split_at = len(prefix) + 8
    body = prefix + email + " tail\n"
    truncated_first = body[:split_at]
    assert "casey" in truncated_first.lower()
    assert "syn.invalid" not in truncated_first

    masked = mask_secrets.mask(body)
    excerpt = masked[:split_at]
    assert email not in excerpt
    assert "casey" not in excerpt.lower()
    assert "syn.invalid" not in excerpt
    assert "[EMAIL" in excerpt


def test_egress_prepare_error_exits_nonzero_and_emits_nothing(tmp_path: Path) -> None:
    missing = tmp_path / "missing-handoff.md"
    directory = tmp_path / "state"
    directory.mkdir()
    for target in (missing, directory):
        proc = _run_masker("--egress-prepare", str(target))
        assert proc.returncode != 0
        assert proc.stdout == ""
        assert proc.stderr.strip() == "egress-prepare fail-closed: error"
        assert str(target) not in proc.stderr
