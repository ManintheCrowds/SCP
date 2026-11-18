#!/usr/bin/env python3
# PURPOSE: Run mask-check with an installed masker, not the working-tree copy.
# A commit that weakens src/scp/mask_secrets.py must not be the code that
# approves itself. Install with `pip install .` from a trusted revision.
# CI installs the pull-request base SHA (or the pushed commit on main).
# `pip install -e .` resolves inside this repo and this script exits 2.

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_CONFIG = _REPO / ".pre-commit-config.yaml"


def _hook_section(text: str) -> str:
    marker = "id: mask-check"
    if marker not in text:
        raise RuntimeError("mask-check hook is missing from .pre-commit-config.yaml")
    return text.split(marker, 1)[1]


def files_pattern(text: str) -> re.Pattern[str]:
    match = re.search(r"^\s*files:\s*'([^']+)'", _hook_section(text), re.MULTILINE)
    if match is None:
        raise RuntimeError("mask-check files pattern is missing")
    return re.compile(match.group(1))


def exclude_pattern(text: str) -> re.Pattern[str] | None:
    match = re.search(r"^\s*exclude:\s*(\S+)", _hook_section(text), re.MULTILINE)
    if match is None:
        return None
    return re.compile(match.group(1))


def selected_files(repo: Path, config_text: str) -> list[Path]:
    include = files_pattern(config_text)
    exclude = exclude_pattern(config_text)
    chosen: list[Path] = []
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        if ".git" in path.parts:
            continue
        rel = path.relative_to(repo).as_posix()
        if exclude is not None and exclude.search(rel):
            continue
        if include.search(rel):
            chosen.append(path)
    return chosen


def _inside_repo(path: Path, repo: Path) -> bool:
    try:
        path.resolve().relative_to(repo.resolve())
    except ValueError:
        return False
    return True


def _load_committed_masker():
    """Load the last committed masker so an editable install cannot check itself."""
    import tempfile

    dest = Path(tempfile.mkdtemp(prefix="scp-mask-"))
    package = dest / "scp"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    for name in ("mask_secrets.py", "secret_text.py", "egress_guard.py"):
        proc = subprocess.run(
            ["git", "show", f"HEAD:src/scp/{name}"],
            cwd=_REPO,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            return None
        (package / name).write_bytes(proc.stdout)
    sys.path.insert(0, str(dest))
    for key in list(sys.modules):
        if key == "scp" or key.startswith("scp."):
            del sys.modules[key]
    import scp.mask_secrets as committed

    return committed


def load_masker():
    """Return an installed masker, or the last commit when the install is editable."""
    import scp.mask_secrets as mod

    if not _inside_repo(Path(mod.__file__), _REPO):
        return mod
    return _load_committed_masker()


def staged_bytes(repo: Path, rel: str) -> bytes:
    """Read the git index blob, not the worktree file."""
    proc = subprocess.run(
        ["git", "show", f":{rel}"],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise FileNotFoundError(rel)
    return proc.stdout


def _relative(repo: Path, raw: str) -> str:
    path = Path(raw)
    if path.is_absolute():
        return path.resolve().relative_to(repo.resolve()).as_posix()
    return path.as_posix()


def guard_scan_count(target_count: int, scanned_count: int) -> int:
    """Fail when target files exist but none were scanned."""
    if target_count > 0 and scanned_count == 0:
        print("mask-check found target files but scanned none", file=sys.stderr)
        return 1
    return 0


def check_staged_paths(repo: Path, paths: list[str], mod) -> int:
    failed = False
    scanned = 0
    for raw in paths:
        rel = _relative(repo, raw)
        try:
            text = mod.decode_strict(staged_bytes(repo, rel))
        except Exception:
            print("mask fail-closed: error", file=sys.stderr)
            failed = True
            continue
        scanned += 1
        if mod.has_secrets(text):
            print(f"SECRETS DETECTED: {rel}", file=sys.stderr)
            failed = True
    blocked = guard_scan_count(len(paths), scanned)
    if blocked:
        return blocked
    if failed:
        return 1
    print("OK: No secrets detected")
    return 0


class MaskCheckRunnerError(RuntimeError):
    """The pull-request fallback does not apply."""


def resolve_mask_check_runner(
    event_name: str, base_dir: Path | None, local_script: Path
) -> tuple[str, Path]:
    """Choose the checker.

    A pull request may use the head script only when the base checkout exists
    and that revision has no checker yet. A push, including after this branch
    merges, never takes that fallback. A missing base checkout fails closed.
    """
    if event_name == "pull_request":
        if base_dir is None or not base_dir.is_dir():
            raise MaskCheckRunnerError("base revision checkout missing; refusing to fall back")
        base_script = base_dir / "scripts" / "run_mask_check.py"
        if base_script.is_file():
            return "base", base_script
        if not local_script.is_file():
            raise MaskCheckRunnerError("mask-check script missing; refusing to fall back")
        return "fallback", local_script
    if not local_script.is_file():
        raise MaskCheckRunnerError("mask-check script missing; refusing to fall back")
    return "local", local_script


def _cmd_resolve(args: list[str]) -> int:
    event_name = ""
    base_dir: Path | None = None
    local_script = _REPO / "scripts" / "run_mask_check.py"
    index = 0
    while index < len(args):
        flag = args[index]
        if flag == "--event" and index + 1 < len(args):
            event_name = args[index + 1]
            index += 2
            continue
        if flag == "--base-dir" and index + 1 < len(args):
            base_dir = Path(args[index + 1])
            index += 2
            continue
        if flag == "--local-script" and index + 1 < len(args):
            local_script = Path(args[index + 1])
            index += 2
            continue
        print(f"unknown argument: {flag}", file=sys.stderr)
        return 2
    try:
        kind, path = resolve_mask_check_runner(event_name, base_dir, local_script)
    except MaskCheckRunnerError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"{kind}\t{path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "--resolve-runner":
        return _cmd_resolve(args[1:])
    mod = load_masker()
    if mod is None:
        print(
            "mask-check could not load a committed masker. "
            "An editable install uses the last commit, not the uncommitted tree.",
            file=sys.stderr,
        )
        return 2
    root = Path(os.environ.get("SCP_MASK_CHECK_ROOT", _REPO))
    config_path = Path(os.environ.get("SCP_MASK_CHECK_CONFIG", root / ".pre-commit-config.yaml"))
    if args:
        return check_staged_paths(root, args, mod)
    config_text = config_path.read_text(encoding="utf-8")
    targets = [str(path) for path in selected_files(root, config_text)]
    if not targets:
        print("OK: no handoff/state files")
        return 0
    return check_staged_paths(root, targets, mod)


if __name__ == "__main__":
    sys.exit(main())
