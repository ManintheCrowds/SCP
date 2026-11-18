# PURPOSE: mask-check reads the git index, not whatever is currently in the worktree.

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

from scp import mask_secrets


def _module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_mask_check.py"
    spec = importlib.util.spec_from_file_location("run_mask_check_index", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    return repo


def _key() -> str:
    return "AK" + "IA" + ("C" * 16)


def test_index_secret_fails_even_if_worktree_is_clean(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = repo / "handoff.md"
    key = _key()
    path.write_text(f"secret {key}\n", encoding="utf-8")
    _git(repo, "add", "handoff.md")
    path.write_text("clean worktree\n", encoding="utf-8")
    code = _module().check_staged_paths(repo, ["handoff.md"], mask_secrets)
    assert code == 1
    assert "clean worktree" == path.read_text(encoding="utf-8").strip()


def test_worktree_secret_is_ignored_when_index_is_clean(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = repo / "handoff.md"
    path.write_text("clean index\n", encoding="utf-8")
    _git(repo, "add", "handoff.md")
    path.write_text("secret " + _key() + "\n", encoding="utf-8")
    code = _module().check_staged_paths(repo, ["handoff.md"], mask_secrets)
    assert code == 0
