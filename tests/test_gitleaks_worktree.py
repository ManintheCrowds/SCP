# PURPOSE: A pull request cannot hide a leak behind its own .gitleaksignore.
# The scan uses the real gitleaks 8.30.1 binary, not a stand-in that records args.

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import urllib.request
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_VERSION = "8.30.1"
_TARBALL_SHA = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
_BINARY_SHA = "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"
_TARBALL_URL = (
    "https://github.com/gitleaks/gitleaks/releases/download/v"
    + _VERSION
    + "/gitleaks_"
    + _VERSION
    + "_linux_x64.tar.gz"
)


def _workflow(name: str) -> str:
    return (_REPO / ".github" / "workflows" / name).read_text(encoding="utf-8")


def _run_block(workflow: str, step_name: str) -> str:
    lines = workflow.splitlines()
    name_line = f"name: {step_name}"
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped != name_line and stripped != f"- {name_line}":
            continue
        for cursor in range(index + 1, min(index + 80, len(lines))):
            if lines[cursor].strip() != "run: |":
                continue
            body: list[str] = []
            base_indent: int | None = None
            for raw in lines[cursor + 1 :]:
                if raw.strip() == "":
                    body.append("")
                    continue
                indent = len(raw) - len(raw.lstrip(" "))
                if base_indent is None:
                    base_indent = indent
                if indent < base_indent:
                    break
                body.append(raw[base_indent:])
            if base_indent is None:
                raise AssertionError(f"empty run block for {step_name}")
            return "\n".join(body).strip() + "\n"
    raise AssertionError(f"missing run block for {step_name}")


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
    return proc.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _real_gitleaks(dest_dir: Path) -> Path:
    """Pinned binary. Reuse a verified copy, otherwise download the release."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    binary = dest_dir / "gitleaks"
    cached = Path("/tmp/gitleaks-bin/gitleaks")
    if cached.is_file() and _sha256(cached) == _BINARY_SHA:
        binary.write_bytes(cached.read_bytes())
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
        return binary
    archive = dest_dir / "gitleaks.tar.gz"
    urllib.request.urlretrieve(_TARBALL_URL, archive)
    if _sha256(archive) != _TARBALL_SHA:
        raise AssertionError("gitleaks tarball digest mismatch")
    subprocess.run(
        ["tar", "-xzf", str(archive), "-C", str(dest_dir), "gitleaks"],
        check=True,
    )
    if _sha256(binary) != _BINARY_SHA:
        raise AssertionError("gitleaks binary digest mismatch")
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    return binary


def _synthetic_token() -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    state = 11
    chars: list[str] = []
    for index in range(36):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(alphabet[state % len(alphabet)])
    return "".join(("gh", "p_")) + "".join(chars)


def _scan_script() -> str:
    return _run_block(_workflow("security-gitleaks.yml"), "Scan with the base ignore file")


def _fingerprint(report: Path) -> str:
    findings = json.loads(report.read_text(encoding="utf-8") or "[]")
    report.unlink()
    if len(findings) != 1 or "Fingerprint" not in findings[0]:
        raise AssertionError("pinned gitleaks did not return one fingerprint")
    return str(findings[0]["Fingerprint"])


def _prepare_leak_repo(tmp_path: Path, binary: Path) -> tuple[Path, str]:
    """Commit a synthetic leak and a .gitleaksignore entry that hides it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / ".gitleaksignore").write_text("base-ignore-marker\n", encoding="utf-8")
    _git(repo, "add", ".gitleaksignore")
    _git(repo, "commit", "-m", "base ignore")
    base_sha = _git(repo, "rev-parse", "HEAD")
    token = _synthetic_token()
    (repo / "leak.txt").write_text("value " + token + "\n", encoding="utf-8")
    _git(repo, "add", "leak.txt")
    _git(repo, "commit", "-m", "add leak")
    config = repo / "rules.toml"
    config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
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
            "--exit-code",
            "2",
            "--no-banner",
            "--redact",
        ],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if listed.returncode != 2 or not report.is_file():
        raise AssertionError("pinned gitleaks did not flag the synthetic leak")
    (repo / ".gitleaksignore").write_text(_fingerprint(report) + "\n", encoding="utf-8")
    _git(repo, "add", ".gitleaksignore")
    _git(repo, "commit", "-m", "ignore the leak")
    return repo, base_sha


def test_pull_request_ignore_file_cannot_hide_a_leak(tmp_path: Path) -> None:
    binary = _real_gitleaks(tmp_path / "bin")
    env = os.environ.copy()
    env["PATH"] = f"{binary.parent}{os.pathsep}{env.get('PATH', '')}"
    repo, base_sha = _prepare_leak_repo(tmp_path, binary)
    config = repo / "rules.toml"
    empty = tmp_path / "empty.ignore"
    empty.write_text("", encoding="utf-8")
    hidden = subprocess.run(
        [
            str(binary),
            "detect",
            "--source",
            str(repo),
            "--config",
            str(config),
            "--gitleaks-ignore-path",
            str(empty),
            "--ignore-gitleaks-allow",
            "--exit-code",
            "2",
            "--no-banner",
            "--redact",
        ],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    assert hidden.returncode == 0
    runner = tmp_path / "runner"
    runner.mkdir()
    env["RUNNER_TEMP"] = str(runner)
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_SHA"] = base_sha
    env["GITLEAKS_CONFIG"] = str(config)
    env["GITLEAKS_VERSION"] = _VERSION
    proc = subprocess.run(
        ["bash", "-c", _scan_script()],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2
    used = (runner / "gitleaks.base.ignore").read_text(encoding="utf-8")
    assert "base-ignore-marker" in used
    assert "head-ignore-marker" not in used


def test_wrong_gitleaks_version_is_refused(tmp_path: Path) -> None:
    proc = subprocess.run(
        ["bash", "-c", _scan_script()],
        cwd=tmp_path,
        env={**os.environ, "GITLEAKS_VERSION": "8.29.0"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "refusing GITLEAKS_VERSION" in proc.stderr


def test_inline_allow_comment_cannot_hide_a_leak(tmp_path: Path) -> None:
    binary = _real_gitleaks(tmp_path / "bin")
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    token = _synthetic_token()
    (repo / "leak.txt").write_text("value " + token + " # gitleaks:allow\n", encoding="utf-8")
    _git(repo, "add", "leak.txt")
    _git(repo, "commit", "-m", "leak")
    config = repo / "rules.toml"
    config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    runner = tmp_path / "runner"
    runner.mkdir()
    env = os.environ.copy()
    env["PATH"] = f"{binary.parent}{os.pathsep}{env.get('PATH', '')}"
    env["RUNNER_TEMP"] = str(runner)
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_SHA"] = ""
    env["GITLEAKS_CONFIG"] = str(config)
    env["GITLEAKS_VERSION"] = _VERSION
    proc = subprocess.run(
        ["bash", "-c", _scan_script()],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 2


def test_checksum_mismatch_exits_on_its_own(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / "clean.txt").write_text("nothing to see\n", encoding="utf-8")
    _git(repo, "add", "clean.txt")
    _git(repo, "commit", "-m", "clean")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "gitleaks"
    stub.write_text(
        "#!/bin/sh\nif [ \"$1\" = version ]; then echo 8.30.1; exit 0; fi\nexit 0\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["RUNNER_TEMP"] = str(tmp_path / "runner")
    (tmp_path / "runner").mkdir()
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_SHA"] = ""
    env["GITLEAKS_CONFIG"] = str(repo / "clean.txt")
    env["GITLEAKS_VERSION"] = _VERSION
    proc = subprocess.run(
        ["bash", "-c", _scan_script()],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "refusing gitleaks binary digest" in proc.stderr


def test_digest_is_checked_before_the_binary_runs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / "clean.txt").write_text("plain\n", encoding="utf-8")
    _git(repo, "add", "clean.txt")
    _git(repo, "commit", "-m", "clean")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls"
    stub = bindir / "gitleaks"
    stub.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$GITLEAKS_CALLS\"\n"
        "if [ \"$1\" = version ]; then echo 8.30.1; exit 0; fi\nexit 0\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["GITLEAKS_CALLS"] = str(log)
    env["RUNNER_TEMP"] = str(tmp_path / "runner")
    (tmp_path / "runner").mkdir()
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_SHA"] = ""
    env["GITLEAKS_CONFIG"] = str(repo / "clean.txt")
    env["GITLEAKS_VERSION"] = _VERSION
    proc = subprocess.run(
        ["bash", "-c", _scan_script()],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "refusing gitleaks binary digest" in proc.stderr
    assert not log.exists() or log.read_text(encoding="utf-8") == ""


def test_wrong_gitleaks_binary_is_refused(tmp_path: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "gitleaks"
    stub.write_text("#!/bin/sh\nif [ \"$1\" = version ]; then echo 8.30.1; exit 0; fi\nexit 0\n", encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["GITLEAKS_VERSION"] = _VERSION
    proc = subprocess.run(
        ["bash", "-c", _scan_script()],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "digest" in proc.stderr


def test_checker_forces_pythonsafepath(tmp_path: Path) -> None:
    script = _run_block(_workflow("ci.yml"), "Run the base mask checker")
    base = tmp_path / "base"
    (base / "scripts").mkdir(parents=True)
    (base / "scripts" / "run_mask_check.py").write_text("print('ok')\n", encoding="utf-8")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "py.log"
    stub = bindir / "python3"
    stub.write_text(
        "#!/bin/sh\nprintf '%s' \"$PYTHONSAFEPATH\" > \"$PY_LOG\"\nexit 0\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["PY_LOG"] = str(log)
    env["PYTHONSAFEPATH"] = "0"
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_DIR"] = str(base)
    proc = subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    assert log.read_text(encoding="utf-8") == "1"


def test_tests_job_fetches_history_and_names_the_head() -> None:
    text = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "fetch-depth: 0" in text
    assert "SCP_GITLEAKS_HISTORY" in text


def test_codeowners_covers_the_ignore_file_and_github_workflows() -> None:
    # GitHub reads .github/CODEOWNERS before a root file. #101 also adds
    # .github/CODEOWNERS, so the entries have to live here or they are ignored.
    assert not (_REPO / "CODEOWNERS").exists()
    text = (_REPO / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    owners = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        path, _, owner = stripped.partition(" ")
        owners[path] = owner.strip()
    assert owners.get(".gitleaksignore") == "@ManintheCrowds"
    assert owners.get(".github/") == "@ManintheCrowds"
    assert owners.get(".gitattributes") == "@ManintheCrowds"
    assert owners.get(".gitleaks.toml") == "@ManintheCrowds"
    assert owners.get("scripts/run_mask_check.py") == "@ManintheCrowds"
    assert owners.get("scripts/mask_check_allow.txt") == "@ManintheCrowds"
    assert owners.get("scripts/gitleaks_blob_allow.txt") == "@ManintheCrowds"
    assert owners.get(".github/CODEOWNERS") == "@ManintheCrowds"
