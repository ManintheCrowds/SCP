# PURPOSE: Byte limits, retention, and quota pressure handling for quarantine disk writes.
# DEPENDENCIES: pathlib, os, time
# MODIFICATION NOTES: AppSec 2026-08-12 — layout-aware quota; layout_subdirs required (no silent omit)

from __future__ import annotations

import os
import stat
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

_ENV_MAX_CONTENT = "SCP_QUARANTINE_MAX_CONTENT_BYTES"
_ENV_MAX_TOTAL = "SCP_QUARANTINE_MAX_TOTAL_BYTES"
_ENV_RETENTION_DAYS = "SCP_QUARANTINE_RETENTION_DAYS_ON_WRITE"
_ENV_EVICT = "SCP_QUARANTINE_EVICT_OLDEST_ON_PRESSURE"

_DEFAULT_MAX_CONTENT = 1_048_576  # 1 MiB per entry
_DEFAULT_MAX_TOTAL = 100 * 1024 * 1024  # 100 MiB total stored
_HARD_MAX_TOTAL = 512 * 1024 * 1024 * 1024  # 512 GiB sanity ceiling
# ntpath.FILE_ATTRIBUTE_REPARSE_POINT. Absent from stat on non-Windows builds.
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _parse_positive_int(env_key: str, default: int, *, hard_max: int | None = None) -> int:
    raw = (os.environ.get(env_key) or "").strip()
    if not raw:
        return default
    try:
        n = int(raw)
        if n < 1:
            return default
        if hard_max is not None:
            return min(n, hard_max)
        return n
    except ValueError:
        return default


def max_content_bytes() -> int:
    return _parse_positive_int(
        _ENV_MAX_CONTENT,
        _DEFAULT_MAX_CONTENT,
        hard_max=50 * 1024 * 1024,
    )


def max_total_bytes() -> int:
    return _parse_positive_int(_ENV_MAX_TOTAL, _DEFAULT_MAX_TOTAL, hard_max=_HARD_MAX_TOTAL)


def retention_days_on_write() -> int | None:
    raw = (os.environ.get(_ENV_RETENTION_DAYS) or "").strip()
    if not raw:
        return None
    try:
        d = int(raw)
        return d if d > 0 else None
    except ValueError:
        return None


def evict_oldest_on_pressure() -> bool:
    raw = (os.environ.get(_ENV_EVICT) or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _pair_disk_bytes_and_mtime(qdir: Path, qid: str) -> tuple[int, float]:
    txt = qdir / f"{qid}.txt"
    js = qdir / f"{qid}.json"
    sz = 0
    mt = 0.0
    for p in (txt, js):
        if p.is_file():
            st = p.stat()
            sz += st.st_size
            mt = max(mt, st.st_mtime)
    return sz, mt


_LAYOUT_SUBDIRS_REQUIRED = (
    "layout_subdirs is required (frozenset of allowlisted layout names; "
    "use frozenset() for root-only). Omitting it (or passing None) under-counts "
    "layout bytes and reopens the quarantine total-quota bypass."
)


def _require_layout_subdirs(layout_subdirs: frozenset[str]) -> frozenset[str]:
    """Fail loud: omit/None must not silently mean root-only accounting."""
    if not isinstance(layout_subdirs, frozenset):
        raise TypeError(_LAYOUT_SUBDIRS_REQUIRED)
    return layout_subdirs


def _path_is_reparse_point(path: Path) -> bool:
    """True for symlinks, directory junctions, and other NTFS reparse points.

    ``Path.is_symlink`` is false for junctions, and junctions need no special
    privilege to create. Missing paths are not reparse points. A path that
    cannot be classified is treated as a reparse point so callers fail closed.
    """
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None:
        try:
            if isjunction(os.fspath(path)):
                return True
        except OSError:
            return True
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode):
        return True
    attributes = int(getattr(st, "st_file_attributes", 0) or 0)
    if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        return True
    tag = int(getattr(st, "st_reparse_tag", 0) or 0)
    return tag != 0


def _contains_reparse_point(path: Path, root: Path) -> bool:
    """True when ``path`` or a parent strictly below ``root`` is a reparse point.

    ``root`` itself is not inspected. Comparison is lexical, so a junction is
    not followed before it can be recognized.
    """
    root_key = os.path.normcase(os.path.normpath(os.fspath(root.absolute())))
    current = Path(os.path.normpath(os.fspath(path.absolute())))
    seen: set[str] = set()
    while True:
        current_key = os.path.normcase(os.fspath(current))
        if current_key in seen:
            return True
        seen.add(current_key)
        if current_key == root_key:
            return False
        if _path_is_reparse_point(current):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _safe_existing_layout_dir(root: Path, sub: Path) -> bool:
    """True when ``sub`` is a real directory strictly inside ``root``.

    Symlinks, junctions, and other reparse points are rejected even when
    ``resolve()`` would land back inside ``root``.
    """
    if _path_is_reparse_point(sub) or not sub.is_dir():
        return False
    try:
        root_resolved = root.resolve()
        sub_resolved = sub.resolve()
    except OSError:
        return False
    return sub_resolved != root_resolved and sub_resolved.is_relative_to(root_resolved)


def _pair_dirs(qdir: Path, layout_subdirs: frozenset[str]) -> list[Path]:
    """Root plus allowlisted layout subdirs that exist (no path traversal / unbounded rglob)."""
    dirs = [qdir]
    for name in sorted(layout_subdirs):
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            continue
        sub = qdir / name
        if _safe_existing_layout_dir(qdir, sub):
            dirs.append(sub)
    return dirs


def _iter_pairs(
    qdir: Path, layout_subdirs: frozenset[str]
) -> Iterator[tuple[Path, str]]:
    """Yield ``(pair_dir, qid)`` for each ``*.json`` stem under root and allowlisted layouts."""
    for pair_dir in _pair_dirs(qdir, layout_subdirs):
        for meta_path in pair_dir.glob("*.json"):
            yield pair_dir, meta_path.stem


def total_quarantine_bytes(qdir: Path, *, layout_subdirs: frozenset[str]) -> int:
    layouts = _require_layout_subdirs(layout_subdirs)
    if not qdir.is_dir():
        return 0
    total = 0
    for pair_dir, qid in _iter_pairs(qdir, layouts):
        sz, _ = _pair_disk_bytes_and_mtime(pair_dir, qid)
        total += sz
    return total


def _protected_identity(
    protected_pair: tuple[Path, str] | None,
) -> tuple[Path, str] | None:
    if protected_pair is None:
        return None
    try:
        return (protected_pair[0].resolve(), protected_pair[1])
    except OSError:
        return (protected_pair[0], protected_pair[1])


def _is_protected(pair_dir: Path, qid: str, protected: tuple[Path, str] | None) -> bool:
    if protected is None:
        return False
    try:
        return (pair_dir.resolve(), qid) == protected
    except OSError:
        return (pair_dir, qid) == protected


def _retention_would_purge(
    pair_dir: Path,
    qid: str,
    *,
    cutoff: float,
    protected: tuple[Path, str] | None,
) -> bool:
    """Same predicate as ``purge_older_than``: nothing is deleted here.

    Protected pairs are kept even when their ``.json`` mtime is stale, because
    purge skips them. Stat failures are kept. Only a metadata mtime strictly
    older than ``cutoff`` is eligible, so equal and future mtimes stay.
    """
    if _is_protected(pair_dir, qid, protected):
        return False
    meta_path = pair_dir / f"{qid}.json"
    try:
        mtime = meta_path.stat().st_mtime
    except OSError:
        return False
    return mtime < cutoff


def _stage_path(path: Path, token: str) -> tuple[Path, Path] | None:
    if not path.exists():
        return None
    staged = path.with_name(f".{path.stem}.{path.suffix[1:]}.{token}.delete")
    os.replace(path, staged)
    return staged, path


def _restore_staged_paths(staged: list[tuple[Path, Path]]) -> None:
    for staged_path, original_path in reversed(staged):
        try:
            if staged_path.exists() and not original_path.exists():
                os.replace(staged_path, original_path)
        except OSError:
            continue


def _cleanup_staged_paths(staged: list[tuple[Path, Path]]) -> None:
    for staged_path, _original_path in staged:
        try:
            staged_path.unlink(missing_ok=True)
        except OSError:
            # The pair has already been moved out of quota/listing scope. Leaving
            # a hidden tombstone is safer than failing and rolling back the new
            # quarantine evidence after old evidence was selected for removal.
            continue


def _iter_staged_delete_paths(
    qdir: Path, layout_subdirs: frozenset[str]
) -> Iterator[Path]:
    for pair_dir in _pair_dirs(qdir, layout_subdirs):
        for suffix in ("txt", "json"):
            yield from pair_dir.glob(f".*.{suffix}.*.delete")


def _ensure_no_orphaned_staged_deletes(
    qdir: Path, layout_subdirs: frozenset[str]
) -> None:
    for staged_path in list(_iter_staged_delete_paths(qdir, layout_subdirs)):
        try:
            staged_path.unlink(missing_ok=True)
        except OSError as exc:
            raise ValueError(
                "staged quarantine cleanup failed; remove staged delete files "
                "or retry after filesystem cleanup recovers"
            ) from exc


def _stage_pair_for_delete(pair_dir: Path, qid: str) -> list[tuple[Path, Path]]:
    token = uuid.uuid4().hex
    staged: list[tuple[Path, Path]] = []
    try:
        for suffix in ("txt", "json"):
            moved = _stage_path(pair_dir / f"{qid}.{suffix}", token)
            if moved is not None:
                staged.append(moved)
    except OSError:
        _restore_staged_paths(staged)
        raise
    return staged


def _total_quarantine_bytes_after_retention(
    qdir: Path,
    *,
    days: int,
    layout_subdirs: frozenset[str],
    protected_pair: tuple[Path, str] | None = None,
) -> int:
    """Bytes that would remain after ``purge_older_than``, without deleting.

    Counts root and ``layout_subdirs``. The protected pair is included when it
    is already on disk (purge will not remove it). A pair that is not on disk
    yet is not counted; callers add that write as ``incoming``.
    """
    layouts = _require_layout_subdirs(layout_subdirs)
    if days <= 0 or not qdir.is_dir():
        return total_quarantine_bytes(qdir, layout_subdirs=layouts)
    protected = _protected_identity(protected_pair)
    cutoff = time.time() - days * 86400
    total = 0
    for pair_dir, qid in _iter_pairs(qdir, layouts):
        if _retention_would_purge(pair_dir, qid, cutoff=cutoff, protected=protected):
            continue
        size, _mtime = _pair_disk_bytes_and_mtime(pair_dir, qid)
        total += size
    return total


def purge_older_than(
    qdir: Path,
    days: int,
    *,
    layout_subdirs: frozenset[str],
    protected_pair: tuple[Path, str] | None = None,
) -> int:
    """Delete pairs whose .json mtime is older than ``days``. Returns number of qids removed."""
    layouts = _require_layout_subdirs(layout_subdirs)
    if days <= 0 or not qdir.is_dir():
        return 0
    protected = _protected_identity(protected_pair)
    cutoff = time.time() - days * 86400
    staged_all: list[tuple[Path, Path]] = []
    purged = 0
    for pair_dir, qid in list(_iter_pairs(qdir, layouts)):
        if not _retention_would_purge(pair_dir, qid, cutoff=cutoff, protected=protected):
            continue
        try:
            staged = _stage_pair_for_delete(pair_dir, qid)
        except OSError:
            _restore_staged_paths(staged_all)
            return 0
        if staged:
            staged_all.extend(staged)
            purged += 1
    _cleanup_staged_paths(staged_all)
    return purged


def evict_oldest_until_under(
    qdir: Path,
    target_total: int,
    *,
    layout_subdirs: frozenset[str],
    protected_pair: tuple[Path, str] | None = None,
) -> int:
    """Delete oldest-by-mtime pairs until total bytes <= ``target_total`` or stuck.

    The protected pair is never a victim. When deleting every other pair still
    cannot reach ``target_total``, nothing is deleted.
    """
    layouts = _require_layout_subdirs(layout_subdirs)
    protected = _protected_identity(protected_pair)
    if not qdir.is_dir():
        return 0
    total = total_quarantine_bytes(qdir, layout_subdirs=layouts)
    if total <= target_total:
        return 0
    candidates: list[tuple[str, float, Path, int]] = []
    for pair_dir, qid in _iter_pairs(qdir, layouts):
        if _is_protected(pair_dir, qid, protected):
            continue
        size, mtime = _pair_disk_bytes_and_mtime(pair_dir, qid)
        candidates.append((qid, mtime, pair_dir, size))
    candidates.sort(key=lambda item: (item[1], item[0]))
    planned: list[tuple[str, Path, int]] = []
    remaining = total
    for qid, _mtime, pair_dir, size in candidates:
        if remaining <= target_total:
            break
        planned.append((qid, pair_dir, size))
        remaining -= size
    if remaining > target_total:
        return 0
    staged_all: list[tuple[Path, Path]] = []
    freed = 0
    for qid, pair_dir, size in planned:
        try:
            staged = _stage_pair_for_delete(pair_dir, qid)
        except OSError:
            _restore_staged_paths(staged_all)
            return 0
        if staged:
            staged_all.extend(staged)
            freed += size
    _cleanup_staged_paths(staged_all)
    return freed


def validate_quarantine_write(
    qdir: Path,
    content_utf8_bytes: int,
    meta_utf8_bytes: int,
    *,
    layout_subdirs: frozenset[str],
    protected_pair: tuple[Path, str] | None = None,
) -> None:
    """Raise before any write that can never fit or cannot fit without eviction.

    When eviction is disabled and retention is configured, bytes that retention
    would purge count as free space. This does not delete anything; the purge
    runs only after the new pair is durable. ``protected_pair`` is kept in the
    forecast when it is already on disk, matching purge.
    """
    layouts = _require_layout_subdirs(layout_subdirs)
    _ensure_no_orphaned_staged_deletes(qdir, layouts)
    max_c = max_content_bytes()
    if content_utf8_bytes > max_c:
        raise ValueError(
            f"quarantine content ({content_utf8_bytes} bytes) exceeds "
            f"SCP_QUARANTINE_MAX_CONTENT_BYTES ({max_c})"
        )

    max_t = max_total_bytes()
    if max_c > max_t:
        raise ValueError(
            "SCP_QUARANTINE_MAX_CONTENT_BYTES must not exceed SCP_QUARANTINE_MAX_TOTAL_BYTES"
        )

    incoming = content_utf8_bytes + meta_utf8_bytes
    if incoming > max_t:
        raise ValueError(
            f"quarantine entry ({incoming} bytes) exceeds "
            f"SCP_QUARANTINE_MAX_TOTAL_BYTES ({max_t})"
        )

    # Eviction deferred to enforce_quarantine_limits after durable commit.
    if evict_oldest_on_pressure():
        return

    total = total_quarantine_bytes(qdir, layout_subdirs=layouts)
    if total + incoming <= max_t:
        return

    days = retention_days_on_write()
    if days is not None:
        retained = _total_quarantine_bytes_after_retention(
            qdir,
            days=days,
            layout_subdirs=layouts,
            protected_pair=protected_pair,
        )
        if retained + incoming <= max_t:
            return
        total = retained

    raise ValueError(
        f"quarantine storage full (current {total} bytes, need {incoming} more; "
        f"limit {max_t} bytes per SCP_QUARANTINE_MAX_TOTAL_BYTES). "
        "Purge entries, raise limits, or set SCP_QUARANTINE_EVICT_OLDEST_ON_PRESSURE=1."
    )


def enforce_quarantine_limits(
    qdir: Path,
    *,
    layout_subdirs: frozenset[str],
    protected_pair: tuple[Path, str] | None = None,
) -> None:
    """Apply retention/eviction after a new pair is durably committed.

    Retention runs only after the caller has the new pair on disk. The total
    is measured again after that purge. If it is still over the cap (unlink
    failed, the stale set changed, or the clock moved), this raises so the
    caller can roll the new pair back. The cap is not left exceeded by the
    write that just committed.
    """
    layouts = _require_layout_subdirs(layout_subdirs)
    days = retention_days_on_write()
    if days is not None:
        purge_older_than(
            qdir,
            days,
            layout_subdirs=layouts,
            protected_pair=protected_pair,
        )

    max_t = max_total_bytes()
    total = total_quarantine_bytes(qdir, layout_subdirs=layouts)
    if total <= max_t:
        return

    if evict_oldest_on_pressure():
        evict_oldest_until_under(
            qdir,
            max_t,
            layout_subdirs=layouts,
            protected_pair=protected_pair,
        )
        total = total_quarantine_bytes(qdir, layout_subdirs=layouts)
        if total <= max_t:
            return

    raise ValueError(
        f"quarantine storage full (current {total} bytes; "
        f"limit {max_t} bytes per SCP_QUARANTINE_MAX_TOTAL_BYTES). "
        "Purge entries, raise limits, or set SCP_QUARANTINE_EVICT_OLDEST_ON_PRESSURE=1."
    )


def prepare_quarantine_write(
    qdir: Path,
    content_utf8_bytes: int,
    meta_utf8_bytes: int,
    *,
    layout_subdirs: frozenset[str],
) -> None:
    """Raise ``ValueError`` if the write would violate limits (after optional retention/eviction).

    ``layout_subdirs`` is required: pass allowlisted layout names (e.g. registry_fetch) so
    total/eviction cover those dirs; use ``frozenset()`` only when root-only is intentional.
    """
    layouts = _require_layout_subdirs(layout_subdirs)
    _ensure_no_orphaned_staged_deletes(qdir, layouts)
    max_c = max_content_bytes()
    if content_utf8_bytes > max_c:
        raise ValueError(
            f"quarantine content ({content_utf8_bytes} bytes) exceeds "
            f"SCP_QUARANTINE_MAX_CONTENT_BYTES ({max_c})"
        )

    max_t = max_total_bytes()
    if max_c > max_t:
        raise ValueError(
            "SCP_QUARANTINE_MAX_CONTENT_BYTES must not exceed SCP_QUARANTINE_MAX_TOTAL_BYTES"
        )

    incoming = content_utf8_bytes + meta_utf8_bytes
    if incoming > max_t:
        raise ValueError(
            f"quarantine entry ({incoming} bytes) exceeds "
            f"SCP_QUARANTINE_MAX_TOTAL_BYTES ({max_t})"
        )

    days = retention_days_on_write()
    if days is not None:
        purge_older_than(qdir, days, layout_subdirs=layouts)

    total = total_quarantine_bytes(qdir, layout_subdirs=layouts)
    if total + incoming <= max_t:
        return

    if evict_oldest_on_pressure():
        evict_oldest_until_under(
            qdir, max(0, max_t - incoming), layout_subdirs=layouts
        )
        total = total_quarantine_bytes(qdir, layout_subdirs=layouts)
        if total + incoming <= max_t:
            return

    raise ValueError(
        f"quarantine storage full (current {total} bytes, need {incoming} more; "
        f"limit {max_t} bytes per SCP_QUARANTINE_MAX_TOTAL_BYTES). "
        "Purge entries, raise limits, or set SCP_QUARANTINE_EVICT_OLDEST_ON_PRESSURE=1."
    )
