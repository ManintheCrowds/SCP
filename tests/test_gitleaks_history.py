# PURPOSE: Attributes, merge commits, NUL bytes, and UTF-16 cannot hide a leak.
# Uses the real gitleaks 8.30.1 binary.

from __future__ import annotations

import hashlib
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


def _workflow() -> str:
    return (_REPO / ".github" / "workflows" / "security-gitleaks.yml").read_text(encoding="utf-8")


def _run_block(step_name: str) -> str:
    lines = _workflow().splitlines()
    name_line = f"name: {step_name}"
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped != name_line and stripped != f"- {name_line}":
            continue
        for cursor in range(index + 1, min(index + 120, len(lines))):
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


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )


def _token(salt: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    state = salt & 0xFFFFFFFF
    chars: list[str] = []
    for index in range(36):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(alphabet[state % len(alphabet)])
    return "".join(("gh", "p_")) + "".join(chars)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _binary(dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    binary = dest_dir / "gitleaks"
    cached = Path("/tmp/gitleaks-bin/gitleaks")
    if cached.is_file() and _sha256(cached) == _BINARY_SHA:
        binary.write_bytes(cached.read_bytes())
    else:
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


def _init(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "rules.toml").write_text("[extend]\nuseDefault = true\n", encoding="utf-8")


def _scan(repo: Path, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    binary = _binary(tmp_path / "bin")
    runner = tmp_path / "runner"
    runner.mkdir()
    env = os.environ.copy()
    env["PATH"] = f"{binary.parent}{os.pathsep}{env.get('PATH', '')}"
    env["RUNNER_TEMP"] = str(runner)
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_SHA"] = ""
    env["GITLEAKS_CONFIG"] = str(repo / "rules.toml")
    env["GITLEAKS_VERSION"] = _VERSION
    return subprocess.run(
        ["bash", "-c", _run_block("Scan with the base ignore file")],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_log_opts_do_not_walk_other_branches() -> None:
    script = _run_block("Scan with the base ignore file")
    assert "--diff-merges=first-parent" in script
    assert "--text" in script
    assert "--all" not in script


def test_binary_attribute_cannot_hide_a_leak(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "leak.py").write_text("value " + _token(21) + "\n", encoding="utf-8")
    (repo / ".gitattributes").write_text("*.py binary\n", encoding="utf-8")
    _git(repo, "add", "leak.py", ".gitattributes")
    _git(repo, "commit", "-q", "-m", "leak")
    proc = _scan(repo, tmp_path)
    assert proc.returncode == 2


def test_nodiff_attribute_cannot_hide_a_leak(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "leak.py").write_text("value " + _token(22) + "\n", encoding="utf-8")
    (repo / ".gitattributes").write_text("*.py -diff\n", encoding="utf-8")
    _git(repo, "add", "leak.py", ".gitattributes")
    _git(repo, "commit", "-q", "-m", "leak")
    assert _scan(repo, tmp_path).returncode == 2


def test_subdirectory_attributes_cannot_hide_a_leak(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "sub").mkdir()
    (repo / "sub" / "leak.py").write_text("value " + _token(23) + "\n", encoding="utf-8")
    (repo / "sub" / ".gitattributes").write_text("* binary\n", encoding="utf-8")
    _git(repo, "add", "sub")
    _git(repo, "commit", "-q", "-m", "leak")
    assert _scan(repo, tmp_path).returncode == 2


def test_attributes_added_later_cannot_hide_an_older_leak(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "leak.py").write_text("value " + _token(24) + "\n", encoding="utf-8")
    _git(repo, "add", "leak.py")
    _git(repo, "commit", "-q", "-m", "leak")
    (repo / ".gitattributes").write_text("*.py binary\n", encoding="utf-8")
    _git(repo, "add", ".gitattributes")
    _git(repo, "commit", "-q", "-m", "hide")
    assert _scan(repo, tmp_path).returncode == 2


def test_merge_resolution_cannot_hide_a_leak(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "f.txt").write_text("main-line\n", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / "f.txt").write_text("side-line\n", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "side")
    _git(repo, "checkout", "-q", "main")
    (repo / "f.txt").write_text("other-line\n", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "diverge")
    merged = subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", "merge", "side"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    assert merged.returncode != 0
    (repo / "f.txt").write_text("resolved\nvalue " + _token(25) + "\n", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "resolve")
    assert _scan(repo, tmp_path).returncode == 2


def test_clean_merge_cannot_smuggle_a_leak(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "a.txt").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / "b.txt").write_text("side\n", encoding="utf-8")
    _git(repo, "add", "b.txt")
    _git(repo, "commit", "-q", "-m", "side")
    _git(repo, "checkout", "-q", "main")
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=ci@example.com",
            "-c",
            "user.name=ci",
            "merge",
            "--no-ff",
            "--no-commit",
            "side",
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    (repo / "hidden.py").write_text("value " + _token(26) + "\n", encoding="utf-8")
    _git(repo, "add", "hidden.py")
    _git(repo, "commit", "-q", "-m", "merge")
    assert _scan(repo, tmp_path).returncode == 2


def test_nul_byte_in_a_text_file_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "note.txt").write_bytes(b"\x00\nvalue " + _token(27).encode("ascii") + b"\n")
    _git(repo, "add", "note.txt")
    _git(repo, "commit", "-q", "-m", "nul")
    proc = _scan(repo, tmp_path)
    assert proc.returncode == 1
    assert "refusing" in proc.stderr


def test_utf16_bom_file_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "note.txt").write_bytes(("value " + _token(28) + "\n").encode("utf-16"))
    _git(repo, "add", "note.txt")
    _git(repo, "commit", "-q", "-m", "utf")
    proc = _scan(repo, tmp_path)
    assert proc.returncode == 1
    assert "refusing UTF-16 text" in proc.stderr


def test_bomless_utf16_is_refused_under_former_binary_names(tmp_path: Path) -> None:
    suffixes = (".png", ".pyc", ".zip", ".exe", ".so", ".woff2", ".wasm", ".ttf")
    refused = 0
    for index, suffix in enumerate(suffixes):
        repo = tmp_path / f"repo{index}"
        _init(repo)
        (repo / f"blob{suffix}").write_bytes(("value " + _token(40 + index)).encode("utf-16-le"))
        _git(repo, "add", f"blob{suffix}")
        _git(repo, "commit", "-q", "-m", "utf")
        proc = _scan(repo, tmp_path / f"scan{index}")
        if proc.returncode == 1 and "refusing UTF-16 text" in proc.stderr:
            refused += 1
    assert refused == len(suffixes)


def test_bomless_utf16_with_a_binary_name_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "photo.png").write_bytes(("value " + _token(29)).encode("utf-16-le"))
    _git(repo, "add", "photo.png")
    _git(repo, "commit", "-q", "-m", "le")
    le = _scan(repo, tmp_path)
    assert le.returncode == 1
    assert "refusing UTF-16 text" in le.stderr
    repo2 = tmp_path / "be"
    _init(repo2)
    (repo2 / "note.pdf").write_bytes(("value " + _token(30)).encode("utf-16-be"))
    _git(repo2, "add", "note.pdf")
    _git(repo2, "commit", "-q", "-m", "be")
    be = _scan(repo2, tmp_path / "be-scan")
    assert be.returncode == 1
    assert "refusing UTF-16 text" in be.stderr


def test_token_after_a_nul_in_a_png_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    blob = b"\x89PNG\r\n\x1a\n" + b"\x00" + _token(31).encode("ascii")
    (repo / "photo.png").write_bytes(blob)
    _git(repo, "add", "photo.png")
    _git(repo, "commit", "-q", "-m", "png")
    proc = _scan(repo, tmp_path)
    assert proc.returncode == 1
    assert "refusing text hidden after a NUL byte" in proc.stderr


def _oid(repo: Path, path: str) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", f"HEAD:{path}"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
    return proc.stdout.strip()


def _scan_at_base(repo: Path, tmp_path: Path, base_sha: str) -> subprocess.CompletedProcess[str]:
    binary = _binary(tmp_path / "bin")
    runner = tmp_path / "runner"
    runner.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["PATH"] = f"{binary.parent}{os.pathsep}{env.get('PATH', '')}"
    env["RUNNER_TEMP"] = str(runner)
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_SHA"] = base_sha
    env["GITLEAKS_CONFIG"] = str(repo / "rules.toml")
    env["GITLEAKS_VERSION"] = _VERSION
    return subprocess.run(
        ["bash", "-c", _run_block("Scan with the base ignore file")],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_base_blob_exemption_is_exact_and_ignores_the_pull_request(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    blob = b"\x00" + bytes(range(1, 32))
    (repo / "clean.bin").write_bytes(blob)
    _git(repo, "add", "clean.bin")
    _git(repo, "commit", "-q", "-m", "blob")
    bare = _scan(repo, tmp_path / "bare")
    assert bare.returncode == 1
    oid = _oid(repo, "clean.bin")
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    (repo / "scripts").mkdir()
    (repo / "scripts" / "gitleaks_blob_allow.txt").write_text(oid + "\n", encoding="utf-8")
    _git(repo, "add", "scripts/gitleaks_blob_allow.txt")
    _git(repo, "commit", "-q", "-m", "allow on the branch only")
    ignored = _scan_at_base(repo, tmp_path / "pr", base)
    assert ignored.returncode == 1
    listed = _scan_at_base(repo, tmp_path / "base", subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=True
    ).stdout.strip())
    assert listed.returncode == 0
    (repo / "clean.bin").write_bytes(blob + b"\x7f")
    _git(repo, "add", "clean.bin")
    _git(repo, "commit", "-q", "-m", "changed")
    changed = _scan_at_base(repo, tmp_path / "changed", subprocess.run(
        ["git", "rev-parse", "HEAD^"], cwd=repo, text=True, capture_output=True, check=True
    ).stdout.strip())
    assert changed.returncode == 1


def test_a_real_png_header_without_text_is_not_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    body = bytearray(b"\x89PNG\r\n\x1a\n")
    body += bytes(range(1, 32))
    body += b"\x00\x01\x02\x03"
    (repo / "photo.png").write_bytes(bytes(body))
    _git(repo, "add", "photo.png")
    _git(repo, "commit", "-q", "-m", "png")
    proc = _scan(repo, tmp_path)
    assert proc.returncode == 0
