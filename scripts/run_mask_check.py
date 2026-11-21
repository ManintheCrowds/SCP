#!/usr/bin/env python3
# PURPOSE: Scan a tree with the installed masker.
# CI runs this file from the base revision so a pull request cannot approve
# itself by replacing the checker.

from __future__ import annotations

import os
import sys
from pathlib import Path

from scp import mask_secrets

_SKIP_PARTS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "build",
    "dist",
}

# Trees the checker used to skip. Source modules stay out of the scan
# because assignment patterns also match ordinary `key = name` code.
_CHECK_PARTS = frozenset({"docs", "fixtures", "tests", ".cursor"})


def _skipped(path: Path, root: Path) -> bool:
    parts = path.relative_to(root).parts
    if any(part in _SKIP_PARTS for part in parts):
        return True
    return any(part.endswith(".egg-info") for part in parts)


def iter_targets(root: Path) -> list[Path]:
    """Handoff and state files. Source modules are left to gitleaks.

    The assignment patterns also match ordinary `key = name` code, so a
    whole-tree scan would fail on this repository.
    """
    chosen: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or _skipped(path, root):
            continue
        rel_parts = path.relative_to(root).parts
        name = path.name.lower()
        in_checked_tree = any(part in _CHECK_PARTS for part in rel_parts)
        in_state = "state" in rel_parts
        if name.startswith(".env") or name in {"handoff.md", "handoff.txt"} or in_state or in_checked_tree:
            chosen.append(path)
    return chosen


def _loaded_from_head(root: Path) -> bool:
    """True when this process imported the masker from the tree under scan."""
    loaded = Path(mask_secrets.__file__).resolve()
    try:
        loaded.relative_to(root)
    except ValueError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    raw_root = os.environ.get("SCP_MASK_CHECK_ROOT")
    root = Path(raw_root).resolve() if raw_root else Path(".").resolve()
    if raw_root and _loaded_from_head(root):
        print(
            "mask-check refuses a masker loaded from the tree it is scanning",
            file=sys.stderr,
        )
        return 2
    targets = [Path(arg) for arg in args] if args else iter_targets(root)
    failed = False
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            print(f"unreadable {path}", file=sys.stderr)
            failed = True
            continue
        if mask_secrets.has_secrets(text):
            print(f"secret-like text in {path}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
