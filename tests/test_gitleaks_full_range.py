# PURPOSE: The gitleaks job scans every pull-request commit, not the action's first page.

from __future__ import annotations

from pathlib import Path

_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "security-gitleaks.yml"


def test_gitleaks_uses_a_full_fetch_and_explicit_range() -> None:
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "fetch-depth: 0" in text
    assert "github.event.pull_request.base.sha" in text
    assert "github.event.pull_request.head.sha" in text
    assert "--log-opts" in text
