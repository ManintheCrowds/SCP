# PURPOSE: The head-script fallback is only for a pull request whose base has no checker.

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]


def _module():
    path = _REPO / "scripts" / "run_mask_check.py"
    spec = importlib.util.spec_from_file_location("run_mask_check_fallback", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_pull_request_falls_back_when_the_base_script_is_missing(tmp_path: Path) -> None:
    module = _module()
    base = tmp_path / "pinned-masker"
    base.mkdir()
    local = tmp_path / "scripts" / "run_mask_check.py"
    local.parent.mkdir()
    local.write_text("print('head')\n", encoding="utf-8")
    kind, chosen = module.resolve_mask_check_runner("pull_request", base, local)
    assert kind == "fallback"
    assert chosen == local
    with pytest.raises(module.MaskCheckRunnerError, match="refusing to fall back"):
        module.resolve_mask_check_runner("pull_request", None, local)


def test_push_refuses_the_pull_request_fallback(tmp_path: Path) -> None:
    module = _module()
    local = tmp_path / "missing.py"
    with pytest.raises(module.MaskCheckRunnerError, match="refusing to fall back"):
        module.resolve_mask_check_runner("push", None, local)
    present = tmp_path / "scripts" / "run_mask_check.py"
    present.parent.mkdir()
    present.write_text("print('local')\n", encoding="utf-8")
    kind, chosen = module.resolve_mask_check_runner("push", None, present)
    assert kind == "local"
    assert chosen == present


def test_workflow_runs_the_base_checker_without_the_head_resolver() -> None:
    workflow = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    section = workflow.split("mask-check:", 1)[1].split("\n  CI:", 1)[0]
    assert "pinned-masker/scripts/run_mask_check.py" in section
    assert "--resolve-runner" not in section
    assert "refusing to fall back" in section
