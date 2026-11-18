# PURPOSE: The mask-check pre-commit hook fails on a planted fake secret
# and passes after SCP's masker redacts that handoff.
# The fake access-key prefix is assembled at runtime so no committed markdown
# file contains a bare AKIA or ghp_ token.

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from scp import mask_secrets

_REPO = Path(__file__).resolve().parents[1]
_CONFIG = _REPO / ".pre-commit-config.yaml"
_GITLEAKS_REV = "v8.30.1"


def _config_text() -> str:
    return _CONFIG.read_text(encoding="utf-8")


def _mask_check_section() -> str:
    text = _config_text()
    marker = "id: mask-check"
    assert marker in text
    return text.split(marker, 1)[1]


def _mask_check_entry() -> list[str]:
    match = re.search(r"^\s*entry:\s*(.+)$", _mask_check_section(), re.MULTILINE)
    assert match is not None
    argv = match.group(1).strip().split()
    assert argv[0] == "python"
    argv[0] = sys.executable
    assert "--check" in argv
    assert any(part.endswith("mask_secrets.py") for part in argv)
    return argv


def _mask_check_files() -> re.Pattern[str]:
    match = re.search(r"^\s*files:\s*'([^']+)'", _mask_check_section(), re.MULTILINE)
    assert match is not None
    return re.compile(match.group(1))


def _fake_access_key() -> str:
    return "AK" + "IA" + "FAKEFAKEFAKEFAKE"


def _planted_handoff() -> str:
    return (
        "# Synthetic handoff fixture\n\n"
        "Not a real secret. The values below are obvious fakes for the mask-check hook proof.\n\n"
        f"AWS_ACCESS_KEY_ID={_fake_access_key()}\n"
        "email: test@example.com\n"
        "SSN: 000-00-0000\n"
    )


def _planted_secret_values(raw: str) -> list[str]:
    values: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("email:") or lower.startswith("ssn:"):
            values.append(stripped.split(":", 1)[1].strip())
        elif "=" in stripped and not stripped.startswith("#"):
            values.append(stripped.split("=", 1)[1].strip())
    assert values
    return values


def _run_hook(target: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*_mask_check_entry(), str(target)],
        cwd=_REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_precommit_pins_gitleaks_and_mask_check() -> None:
    text = _config_text()
    assert re.search(
        r"repo:\s*https://github.com/gitleaks/gitleaks\s+rev:\s*" + re.escape(_GITLEAKS_REV),
        text,
    )
    assert "id: gitleaks" in text
    section = _mask_check_section()
    assert "pass_filenames: true" in section
    assert "stages: [pre-commit]" in section
    files_re = _mask_check_files()
    assert files_re.search(".cursor/state/handoff_latest.md")
    assert files_re.search("notes/handoff_latest.json")
    assert files_re.search(".cursor/state/session.jsonl")
    assert files_re.search("src/scp/mask_secrets.py") is None
    assert files_re.search("README.md") is None


def test_committed_markdown_has_no_bare_access_key_prefix() -> None:
    prefix = "AK" + "IA"
    for path in _REPO.rglob("*.md"):
        if ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        assert prefix not in text, path
        assert "ghp_" not in text, path


def test_planted_handoff_fails_mask_check_until_masked(tmp_path: Path) -> None:
    raw = _planted_handoff()
    secrets = _planted_secret_values(raw)
    assert _fake_access_key() in secrets
    rel = Path(".cursor/state/handoff_latest.md")
    assert _mask_check_files().search(rel.as_posix())

    target = tmp_path / rel
    target.parent.mkdir(parents=True)
    target.write_text(raw, encoding="utf-8")

    failed = _run_hook(target)
    assert failed.returncode != 0
    assert "SECRETS DETECTED" in failed.stderr
    for secret in secrets:
        assert secret not in failed.stdout
        assert secret not in failed.stderr
        assert secret in raw

    masked = mask_secrets.mask(raw)
    for secret in secrets:
        assert secret not in masked
    target.write_text(masked, encoding="utf-8")

    passed = _run_hook(target)
    assert passed.returncode == 0
    assert "OK: No secrets detected" in passed.stdout
    for secret in secrets:
        assert secret not in passed.stdout
        assert secret not in passed.stderr
