# PURPOSE: Full history is ignored only by exact commit fingerprints.
# A new leak still fails. The real gitleaks 8.30.1 binary is used.

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_BINARY_SHA = "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"
_LOG_OPTS = "--diff-merges=first-parent --text"


def _binary(dest: Path) -> Path:
    cached = Path("/tmp/gitleaks-bin/gitleaks")
    digest = hashlib.sha256(cached.read_bytes()).hexdigest()
    if digest != _BINARY_SHA:
        raise AssertionError("pinned gitleaks binary is not available")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(cached.read_bytes())
    dest.chmod(dest.stat().st_mode | stat.S_IEXEC)
    return dest


def _config(path: Path) -> None:
    path.write_text(
        "\n".join(
            (
                "[extend]",
                "useDefault = true",
                "[allowlist]",
                "paths = [",
                "'''(^|/)[^/]+\\.pyc$''',",
                "]",
                "",
            )
        ),
        encoding="utf-8",
    )


def _scan(source: Path, config: Path, ignore: Path, binary: Path) -> int:
    proc = subprocess.run(
        [
            str(binary),
            "detect",
            "--source",
            str(source),
            "--config",
            str(config),
            "--gitleaks-ignore-path",
            str(ignore),
            "--ignore-gitleaks-allow",
            "--log-opts",
            _LOG_OPTS,
            "--exit-code",
            "2",
            "--no-banner",
            "--redact",
        ],
        cwd=source,
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.returncode


def _entries() -> list[str]:
    rows: list[str] = []
    for line in (_REPO / ".gitleaksignore").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rows.append(stripped)
    return rows


def test_ignore_entries_are_commit_qualified() -> None:
    rows = _entries()
    assert len(rows) == 5
    for row in rows:
        commit, path, rule, line = row.split(":")
        assert len(commit) == 40
        assert all(char in "0123456789abcdef" for char in commit)
        assert path
        assert rule
        assert line.isdigit()


def test_reachable_history_is_clean_and_a_new_leak_fails(tmp_path: Path) -> None:
    binary = _binary(tmp_path / "gitleaks")
    config = tmp_path / "rules.toml"
    _config(config)
    assert _scan(_REPO, config, _REPO / ".gitleaksignore", binary) == 0

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", "init", "-q", "-b", "main"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    state = 41
    chars: list[str] = []
    for index in range(36):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(alphabet[state % len(alphabet)])
    token = "".join(("gh", "p_")) + "".join(chars)
    (repo / "old.txt").write_text("value " + token + "\n", encoding="utf-8")
    subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", "add", "old.txt"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", "commit", "-q", "-m", "old"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    report = tmp_path / "report.json"
    listed = subprocess.run(
        [
            str(binary),
            "detect",
            "--source",
            str(repo),
            "--config",
            str(config),
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--log-opts",
            _LOG_OPTS,
            "--exit-code",
            "2",
            "--no-banner",
            "--redact",
        ],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    assert listed.returncode == 2
    payload = json.loads(report.read_text(encoding="utf-8") or "[]")
    report.unlink()
    fingerprint = str(payload[0]["Fingerprint"])
    del payload
    ignore = tmp_path / "ignore"
    ignore.write_text(fingerprint + "\n", encoding="utf-8")
    state = 99
    fresh: list[str] = []
    for index in range(36):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        fresh.append(alphabet[state % len(alphabet)])
    (repo / "new.txt").write_text("value " + "".join(("gh", "p_")) + "".join(fresh) + "\n", encoding="utf-8")
    subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", "add", "new.txt"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", "commit", "-q", "-m", "new"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    assert _scan(repo, config, ignore, binary) == 2
