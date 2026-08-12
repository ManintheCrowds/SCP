# PURPOSE: Byte limits, retention, and quota pressure handling for quarantine disk writes.

from __future__ import annotations

import os
import time
from pathlib import Path

_ENV_MAX_CONTENT = "SCP_QUARANTINE_MAX_CONTENT_BYTES"
_ENV_MAX_TOTAL = "SCP_QUARANTINE_MAX_TOTAL_BYTES"
_ENV_RETENTION_DAYS = "SCP_QUARANTINE_RETENTION_DAYS_ON_WRITE"
_ENV_EVICT = "SCP_QUARANTINE_EVICT_OLDEST_ON_PRESSURE"

_DEFAULT_MAX_CONTENT = 1_048_576  # 1 MiB per entry
_DEFAULT_MAX_TOTAL = 100 * 1024 * 1024  # 100 MiB total stored
_HARD_MAX_TOTAL = 512 * 1024 * 1024 * 1024  # 512 GiB sanity ceiling
_KNOWN_LAYOUT_DIRS = ("registry_fetch",)


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


def _iter_meta_paths(qdir: Path):
    yield from qdir.glob("*.json")
    for layout in _KNOWN_LAYOUT_DIRS:
        layout_dir = qdir / layout
        if layout_dir.is_dir():
            yield from layout_dir.glob("*.json")


def _pair_disk_bytes_and_mtime(meta_path: Path) -> tuple[int, float]:
    qid = meta_path.stem
    txt = meta_path.with_name(f"{qid}.txt")
    js = meta_path
    sz = 0
    mt = 0.0
    for p in (txt, js):
        if p.is_file():
            st = p.stat()
            sz += st.st_size
            mt = max(mt, st.st_mtime)
    return sz, mt


def total_quarantine_bytes(qdir: Path) -> int:
    if not qdir.is_dir():
        return 0
    total = 0
    for meta_path in _iter_meta_paths(qdir):
        sz, _ = _pair_disk_bytes_and_mtime(meta_path)
        total += sz
    return total


def purge_older_than(qdir: Path, days: int) -> int:
    """Delete pairs whose .json mtime is older than ``days``. Returns number of qids removed."""
    if days <= 0 or not qdir.is_dir():
        return 0
    cutoff = time.time() - days * 86400
    purged = 0
    for meta_path in list(_iter_meta_paths(qdir)):
        qid = meta_path.stem
        try:
            if meta_path.stat().st_mtime < cutoff:
                meta_path.with_name(f"{qid}.txt").unlink(missing_ok=True)
                meta_path.unlink(missing_ok=True)
                purged += 1
        except OSError:
            continue
    return purged


def evict_oldest_until_under(qdir: Path, target_total: int) -> int:
    """Delete oldest-by-mtime pairs until ``total_quarantine_bytes(qdir) <= target_total`` or stuck."""
    freed = 0
    while qdir.is_dir() and total_quarantine_bytes(qdir) > target_total:
        pairs: list[tuple[Path, float]] = []
        for meta_path in _iter_meta_paths(qdir):
            _, mt = _pair_disk_bytes_and_mtime(meta_path)
            pairs.append((meta_path, mt))
        if not pairs:
            break
        pairs.sort(key=lambda x: x[1])
        victim = pairs[0][0]
        sz_before, _ = _pair_disk_bytes_and_mtime(victim)
        try:
            victim.unlink(missing_ok=True)
            victim.with_suffix(".txt").unlink(missing_ok=True)
            freed += sz_before
        except OSError:
            break
    return freed


def prepare_quarantine_write(qdir: Path, content_utf8_bytes: int, meta_utf8_bytes: int) -> None:
    """Raise ``ValueError`` if the write would violate limits (after optional retention/eviction)."""
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
        purge_older_than(qdir, days)

    total = total_quarantine_bytes(qdir)
    if total + incoming <= max_t:
        return

    if evict_oldest_on_pressure():
        evict_oldest_until_under(qdir, max(0, max_t - incoming))
        total = total_quarantine_bytes(qdir)
        if total + incoming <= max_t:
            return

    raise ValueError(
        f"quarantine storage full (current {total} bytes, need {incoming} more; "
        f"limit {max_t} bytes per SCP_QUARANTINE_MAX_TOTAL_BYTES). "
        "Purge entries, raise limits, or set SCP_QUARANTINE_EVICT_OLDEST_ON_PRESSURE=1."
    )
