# PURPOSE: Byte limits, retention, and quota pressure handling for quarantine disk writes.
# DEPENDENCIES: pathlib, os, time
# MODIFICATION NOTES: AppSec 2026-08-12 — layout-aware quota; layout_subdirs required (no silent omit)

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from pathlib import Path

_ENV_MAX_CONTENT = "SCP_QUARANTINE_MAX_CONTENT_BYTES"
_ENV_MAX_TOTAL = "SCP_QUARANTINE_MAX_TOTAL_BYTES"
_ENV_RETENTION_DAYS = "SCP_QUARANTINE_RETENTION_DAYS_ON_WRITE"
_ENV_EVICT = "SCP_QUARANTINE_EVICT_OLDEST_ON_PRESSURE"

_DEFAULT_MAX_CONTENT = 1_048_576  # 1 MiB per entry
_DEFAULT_MAX_TOTAL = 100 * 1024 * 1024  # 100 MiB total stored
_HARD_MAX_TOTAL = 512 * 1024 * 1024 * 1024  # 512 GiB sanity ceiling


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


def _pair_dirs(qdir: Path, layout_subdirs: frozenset[str]) -> list[Path]:
    """Root plus allowlisted layout subdirs that exist (no path traversal / unbounded rglob)."""
    dirs = [qdir]
    for name in sorted(layout_subdirs):
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            continue
        sub = qdir / name
        if sub.is_dir():
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


def purge_older_than(qdir: Path, days: int, *, layout_subdirs: frozenset[str]) -> int:
    """Delete pairs whose .json mtime is older than ``days``. Returns number of qids removed."""
    layouts = _require_layout_subdirs(layout_subdirs)
    if days <= 0 or not qdir.is_dir():
        return 0
    cutoff = time.time() - days * 86400
    purged = 0
    for pair_dir, qid in list(_iter_pairs(qdir, layouts)):
        meta_path = pair_dir / f"{qid}.json"
        try:
            if meta_path.stat().st_mtime < cutoff:
                (pair_dir / f"{qid}.txt").unlink(missing_ok=True)
                meta_path.unlink(missing_ok=True)
                purged += 1
        except OSError:
            continue
    return purged


def evict_oldest_until_under(
    qdir: Path, target_total: int, *, layout_subdirs: frozenset[str]
) -> int:
    """Delete oldest-by-mtime pairs until total bytes <= ``target_total`` or stuck."""
    layouts = _require_layout_subdirs(layout_subdirs)
    freed = 0
    while qdir.is_dir() and total_quarantine_bytes(qdir, layout_subdirs=layouts) > target_total:
        pairs: list[tuple[str, float, Path]] = []
        for pair_dir, qid in _iter_pairs(qdir, layouts):
            _, mt = _pair_disk_bytes_and_mtime(pair_dir, qid)
            pairs.append((qid, mt, pair_dir))
        if not pairs:
            break
        pairs.sort(key=lambda x: x[1])
        victim, _, victim_dir = pairs[0]
        sz_before, _ = _pair_disk_bytes_and_mtime(victim_dir, victim)
        try:
            (victim_dir / f"{victim}.json").unlink(missing_ok=True)
            (victim_dir / f"{victim}.txt").unlink(missing_ok=True)
            freed += sz_before
        except OSError:
            break
    return freed


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
