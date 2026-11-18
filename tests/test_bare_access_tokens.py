# PURPOSE: Bare access-key shapes are masked, and gitleaks no longer skips every markdown file.

from __future__ import annotations

from pathlib import Path

from scp import mask_secrets

_REPO = Path(__file__).resolve().parents[1]


def _akia() -> str:
    return "AK" + "IA" + "FAKEFAKEFAKEFAKE"


def _ghp() -> str:
    return "gh" + "p_" + ("A" * 36)


def test_mask_bare_access_key_and_github_token() -> None:
    akia = _akia()
    ghp = _ghp()
    text = f"cloud {akia} gh {ghp}"
    assert mask_secrets.has_secrets(text)
    masked = mask_secrets.mask(text)
    assert akia not in masked
    assert ghp not in masked
    assert "[REDACTED]" in masked
    assert not mask_secrets.has_secrets(masked)


def test_gitleaks_allowlist_is_not_all_markdown() -> None:
    text = (_REPO / ".gitleaks.toml").read_text(encoding="utf-8")
    assert ".*\\.md$" not in text
    assert "tests/fixtures/" in text


def test_ci_runs_mask_check() -> None:
    workflow = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "mask-check:" in workflow
    assert "python scripts/run_mask_check.py" in workflow
    assert "needs: [contract, promptfoo-eval, mask-check]" in workflow


def test_mask_check_skips_test_fixtures() -> None:
    from scripts.run_mask_check import selected_files

    config = (_REPO / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    selected = [path.relative_to(_REPO).as_posix() for path in selected_files(_REPO, config)]
    assert all(not name.startswith("tests/") for name in selected)
    assert "tests/fixtures/egress_mask_synthetic_handoff.md" not in selected
