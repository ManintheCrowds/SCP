"""Helpers for quarantine symlink and NTFS junction tests.

``_winapi`` is a Windows-only stdlib module. Importing it on other platforms
fails, so it is loaded only when ``os.name == "nt"``.
"""

from __future__ import annotations

import importlib
import os
import subprocess
from pathlib import Path

import pytest

_winapi = importlib.import_module("_winapi") if os.name == "nt" else None

# ERROR_ACCESS_DENIED and ERROR_PRIVILEGE_NOT_HELD.
_SYMLINK_PRIVILEGE_WINERRORS = frozenset({5, 1314})


def symlink_or_skip(link: Path, target: Path, *, target_is_directory: bool) -> None:
    """Create a symlink, or skip when Windows denies that privilege."""
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except OSError as exc:
        winerror = getattr(exc, "winerror", None)
        if os.name == "nt" and (
            winerror in _SYMLINK_PRIVILEGE_WINERRORS or isinstance(exc, PermissionError)
        ):
            pytest.skip(
                "symlink creation is not permitted on this Windows host "
                "(Developer Mode or an elevated process is required); "
                f"winerror={winerror}"
            )
        raise


def create_junction(link: Path, target: Path) -> None:
    """Create an NTFS directory junction at ``link`` pointing at ``target``.

    ``mklink /J`` does not need an elevated token. ``_winapi.CreateJunction``
    is only a fallback: it enables ``SE_RESTORE_NAME`` and can fail when that
    privilege is absent, sometimes after leaving an empty directory behind.
    """
    if os.name != "nt":
        raise RuntimeError("directory junctions can only be created on Windows")
    source = os.path.normpath(os.fspath(target.resolve()))
    destination = os.path.normpath(os.fspath(link.parent.resolve() / link.name))
    # One argument after /c so paths that contain spaces stay quoted.
    completed = subprocess.run(
        ["cmd", "/c", f'mklink /J "{destination}" "{source}"'],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        if link.is_dir():
            try:
                link.rmdir()
            except OSError:
                pass
        if _winapi is None or not hasattr(_winapi, "CreateJunction"):
            raise RuntimeError(
                "could not create a directory junction "
                f"(exit {completed.returncode})"
            )
        _winapi.CreateJunction(source, destination)
    if hasattr(os.path, "isjunction") and not os.path.isjunction(destination):
        raise RuntimeError("junction creation did not produce an NTFS junction")
