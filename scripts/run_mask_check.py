#!/usr/bin/env python3
# PURPOSE: Run SCP mask-check on handoff and state files selected by pre-commit.
# Test fixtures under tests/ are excluded. B1 uses the installed package.

from __future__ import annotations

import re
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


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    config_text = _CONFIG.read_text(encoding="utf-8")
    if args:
        targets = [str(Path(arg)) for arg in args]
    else:
        targets = [str(path) for path in selected_files(_REPO, config_text)]
    if not targets:
        print("OK: no handoff/state files")
        return 0
    from scp.mask_secrets import main as mask_main

    return mask_main(["--check", *targets])


if __name__ == "__main__":
    sys.exit(main())
