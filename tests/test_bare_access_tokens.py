# PURPOSE: Bare access-key shapes are masked, and gitleaks no longer skips every markdown file.

from __future__ import annotations

import importlib.util
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


def _mask_check_module():
    path = _REPO / "scripts" / "run_mask_check.py"
    spec = importlib.util.spec_from_file_location("run_mask_check_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mask_check_skips_test_fixtures(tmp_path: Path) -> None:
    module = _mask_check_module()
    config = (_REPO / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    fixture = tmp_path / "tests" / "fixtures"
    fixture.mkdir(parents=True)
    (fixture / "egress_mask_synthetic_handoff.md").write_text("fixture\n", encoding="utf-8")
    state = tmp_path / ".cursor" / "state"
    state.mkdir(parents=True)
    (state / "handoff.md").write_text("state\n", encoding="utf-8")
    selected = [path.relative_to(tmp_path).as_posix() for path in module.selected_files(tmp_path, config)]
    assert selected == [".cursor/state/handoff.md"]
    assert all(not name.startswith("tests/") for name in selected)
