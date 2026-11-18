# PURPOSE: The mask-check pre-commit hook fails on a planted fake secret
# and passes after SCP's masker redacts that handoff.
# The fake access-key prefix is assembled at runtime so no committed markdown
# file contains a bare cloud-key or GitHub token prefix.

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from scp import mask_secrets

_REPO = Path(__file__).resolve().parents[1]
_CONFIG = _REPO / ".pre-commit-config.yaml"
_GITLEAKS_REV = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
_GITLEAKS_ACTION = "ff98106e4c7b2bc287b24eaf42907196329070c7"


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
    assert any(part.endswith("run_mask_check.py") for part in argv)
    assert not any(part.endswith("mask_secrets.py") for part in argv)
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


def _external_masker(tmp_path: Path) -> str:
    dest = tmp_path / "installed"
    package = dest / "scp"
    if not (package / "mask_secrets.py").is_file():
        shutil.copytree(_REPO / "src" / "scp", package)
    return str(dest)


def _run_hook(target: Path, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = _external_masker(tmp_path)
    return subprocess.run(
        [*_mask_check_entry(), str(target)],
        cwd=_REPO,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_hook_files_match_handoff_names_regardless_of_case() -> None:
    files_re = _mask_check_files()
    assert files_re.search(".cursor/state/HANDOFF.md")
    assert files_re.search(".cursor/state/notes.TXT")
    assert files_re.search(".cursor/state/config.YAML")
    assert files_re.search(".cursor/state/config.yml")
    assert files_re.search("handoffs/today.md")
    assert files_re.search(".cursor/state/next_prompt")
    assert files_re.search(".cursor/state/blob")
    assert files_re.search(".cursor/state/notes.bin")
    assert files_re.search(".cursor/state/drafts/next_prompt.txt")
    assert files_re.search("README.md") is None
    assert files_re.search("src/scp/mask_secrets.py") is None


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
        assert "gh" + "p_" not in text, path


def test_editable_install_uses_the_committed_masker() -> None:
    proc = subprocess.run(
        [sys.executable, str(_REPO / "scripts" / "run_mask_check.py")],
        cwd=_REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0
    assert "could not load" not in proc.stderr
    assert "OK" in proc.stdout


def test_gitleaks_hook_and_action_are_pinned_to_commits() -> None:
    pre_commit = _config_text()
    assert _GITLEAKS_REV in pre_commit
    assert "rev: v8.30.1" not in pre_commit
    workflow = (_REPO / ".github" / "workflows" / "security-gitleaks.yml").read_text(
        encoding="utf-8"
    )
    assert f"gitleaks/gitleaks-action@{_GITLEAKS_ACTION}" in workflow
    assert "gitleaks-action@v2" not in workflow
    ci = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "github.event.pull_request.base.sha" in ci
    assert "pip install ./pinned-masker" in ci


def test_planted_handoff_fails_mask_check_until_masked(tmp_path: Path) -> None:
    raw = _planted_handoff()
    secrets = _planted_secret_values(raw)
    assert _fake_access_key() in secrets
    rel = Path(".cursor/state/handoff_latest.md")
    assert _mask_check_files().search(rel.as_posix())
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    target = repo / rel
    target.parent.mkdir(parents=True)
    target.write_text(raw, encoding="utf-8")
    subprocess.run(["git", "add", rel.as_posix()], cwd=repo, check=True)
    module = importlib.util.spec_from_file_location(
        "run_mask_check_planted", _REPO / "scripts" / "run_mask_check.py"
    )
    assert module is not None and module.loader is not None
    loaded = importlib.util.module_from_spec(module)
    module.loader.exec_module(loaded)

    failed = loaded.check_staged_paths(repo, [rel.as_posix()], mask_secrets)
    assert failed == 1
    for secret in secrets:
        assert secret in raw

    masked = mask_secrets.mask(raw)
    for secret in secrets:
        assert secret not in masked
    target.write_text(masked, encoding="utf-8")
    subprocess.run(["git", "add", rel.as_posix()], cwd=repo, check=True)
    passed = loaded.check_staged_paths(repo, [rel.as_posix()], mask_secrets)
    assert passed == 0
