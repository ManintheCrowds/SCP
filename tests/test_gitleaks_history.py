# PURPOSE: Attributes, merge commits, NUL bytes, and UTF-16 cannot hide a leak.
# Uses the real gitleaks 8.30.1 binary.

from __future__ import annotations

import hashlib
import marshal
import os
import py_compile
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


def _head(repo: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def _scan_as_base(
    repo: Path,
    tmp_path: Path,
    extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Treat the commit that holds the blob as the base revision."""
    return _scan_at_base(repo, tmp_path, _head(repo), extra)


def _scan_at_base(
    repo: Path,
    tmp_path: Path,
    base_sha: str,
    extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
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
    if extra:
        env.update(extra)
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


def _compiled(directory: Path) -> bytes:
    source = directory / "sample.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    dest = directory / "sample.pyc"
    py_compile.compile(str(source), cfile=str(dest), doraise=True)
    return dest.read_bytes()


def _loose_header() -> bytes:
    """Forty-two bytes that used to pass the header check and ignore the tail."""
    header = bytes((0xF3, 0x0D, 0x0D, 0x0A)) + (0).to_bytes(4, "little") + bytes(8)
    counts = b"".join((0).to_bytes(4, "little") for _ in range(5))
    return header + bytes((0xE3,)) + counts + bytes((0x73,)) + (1).to_bytes(4, "little") + b"\x00"


def test_prescan_does_not_import_repo_root_modules(tmp_path: Path) -> None:
    """A pull request cannot shadow the stdlib modules the prescan imports."""
    repo = tmp_path / "repo"
    _init(repo)
    shadow = "open(__file__ + '.ran', 'w', encoding='utf-8').write('ran\\n')\n"
    for name in ("subprocess.py", "os.py", "json.py"):
        (repo / name).write_text(shadow, encoding="utf-8")
    (repo / "app.py").write_text("value " + _token(44) + "\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "leak and shadows")
    proc = _scan(repo, tmp_path / "scan")
    ran = sorted(path.name for path in repo.glob("*.ran"))
    assert ran == []
    assert proc.returncode == 2


def test_a_cpython_bytecode_blob_is_not_refused_as_utf16(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "notes.pyc").write_bytes(_compiled(tmp_path))
    _git(repo, "add", "notes.pyc")
    _git(repo, "commit", "-q", "-m", "bytecode")
    proc = _scan_as_base(repo, tmp_path)
    assert proc.returncode == 0, proc.stderr


def test_a_pyc_header_or_tail_does_not_hide_utf16(tmp_path: Path) -> None:
    hidden = ("value " + _token(71)).encode("utf-16-le")
    payloads = (
        _loose_header() + hidden,
        _loose_header() + ("value " + _token(72)).encode("utf-16"),
        _loose_header() + ("value " + _token(73)).encode("utf-16-be"),
        _compiled(tmp_path) + hidden,
    )
    names = ("blob.pyc", "config.txt", "README.md", "extra.pyc")
    refused = 0
    for index, (name, payload) in enumerate(zip(names, payloads, strict=True)):
        repo = tmp_path / f"repo{index}"
        _init(repo)
        (repo / name).write_bytes(payload)
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", "tail")
        proc = _scan(repo, tmp_path / f"scan{index}")
        if proc.returncode == 1 and "refusing" in proc.stderr:
            refused += 1
    assert refused == len(payloads)
    script = _run_block("Scan with the base ignore file")
    assert "marshal.load" in script
    assert "buffer.tell()" in script
    assert 'python-version: "3.13.18"' in _workflow()
    workflow = _workflow()
    assert "crashes while walking a spliced code table" not in workflow
    assert "The pin does not stop a crash inside marshal" in workflow
    assert "The CI tests job runs on Python 3.12" in workflow
    ci = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert 'python-version: "3.12"' in ci
    doc = (_REPO / "docs" / "SECRET_SCAN.md").read_text(encoding="utf-8")
    assert "The CI tests job runs on Python 3.12" in doc
    assert "The pin does not stop a crash inside marshal" in doc


def _header(payload: bytes) -> bytes:
    return (
        bytes((0xF3, 0x0D, 0x0D, 0x0A))
        + (0).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + payload
    )


def _utf16(salt: int, codec: str) -> bytes:
    return ("value " + _token(salt)).encode(codec)


def _code_pyc(code: object) -> bytes:
    return _header(marshal.dumps(code))


def _pyc_with_planted_code(planted_bytes: bytes) -> bytes:
    """Put hidden bytes in the marshalled code table.

    The code-object constructor rewrites co_code, so a plant has to be
    written into the marshal blob after that constructor has finished.
    """
    base = compile(
        "def f(a, b, c):\n"
        "    return (a + b) * c\n"
        "print(f(1, 2, 3))\n"
        "items = [f(i, i + 1, 2) for i in range(4)]\n",
        "m.py",
        "exec",
    )
    original = base.co_code
    if len(planted_bytes) > len(original):
        raise AssertionError("bytecode plant is longer than the host code")
    planted = planted_bytes + original[len(planted_bytes) :]
    blob = bytearray(marshal.dumps(base))
    at = blob.find(original)
    if at < 0:
        raise AssertionError("code table missing from the marshal blob")
    blob[at : at + len(original)] = planted
    return _header(bytes(blob))


def _planted(salt: int) -> str:
    """UTF-16LE token text, decoded so the code object stores those bytes."""
    return _utf16(salt, "utf-16-le").decode("latin-1")


def test_utf16_in_each_code_object_field_is_refused(tmp_path: Path) -> None:
    base = compile("x = 1\n", "m.py", "exec")
    hidden = _planted(90)
    raw = hidden.encode("latin-1")
    nulled = "".join(char + "\x00" for char in _token(91))
    nested = base.replace(co_consts=base.co_consts + (base.replace(co_filename=hidden),))
    cases = (
        ("co_filename", base.replace(co_filename=hidden)),
        ("co_name", base.replace(co_name=hidden)),
        ("co_qualname", base.replace(co_qualname=hidden)),
        ("co_names", base.replace(co_names=base.co_names + (hidden,))),
        ("co_varnames", base.replace(co_varnames=(hidden,), co_nlocals=1)),
        ("co_freevars", base.replace(co_freevars=(hidden,))),
        ("co_cellvars", base.replace(co_cellvars=(hidden,))),
        ("co_linetable", base.replace(co_linetable=raw)),
        ("co_exceptiontable", base.replace(co_exceptiontable=raw)),
        ("nested_co_filename", nested),
        ("co_filename_nul", base.replace(co_filename=nulled)),
    )
    payloads = [(label, _code_pyc(code)) for label, code in cases]
    payloads.append(("co_code", _pyc_with_planted_code(raw)))
    missed: list[str] = []
    for index, (label, payload) in enumerate(payloads):
        repo = tmp_path / f"field{index}"
        _init(repo)
        (repo / "m.pyc").write_bytes(payload)
        _git(repo, "add", "m.pyc")
        _git(repo, "commit", "-q", "-m", label)
        proc = _scan_as_base(repo, tmp_path / f"field-scan{index}")
        # The code table is loaded only in a child. A crash there is a
        # refusal and must not take the parent down. The other fields have
        # to name the secret.
        if label == "co_code":
            ok = (
                proc.returncode == 1
                and "refusing" in proc.stderr
                and "Traceback" not in proc.stderr
            )
        else:
            ok = proc.returncode == 1 and "refusing secret text inside bytecode" in proc.stderr
        if not ok:
            missed.append(f"{label} rc={proc.returncode} {proc.stderr[-180:]!r}")
    assert missed == []


def test_prescan_locks_the_isolation_and_the_field_walk() -> None:
    script = _run_block("Scan with the base ignore file")
    assert "refusing bytecode that is not on the base allow-list" in script
    assert '"co_filename"' in script
    assert '"co_names"' in script
    assert "_CODE_BINARY" in script
    for name in ("co_code", "co_linetable", "co_exceptiontable"):
        assert name in script


def test_prescan_python_is_isolated_from_the_checkout(tmp_path: Path) -> None:
    """The prescan interpreter is isolated, even if the text of the step changes."""
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "app")
    binary = _binary(tmp_path / "bin")
    bindir = tmp_path / "stub"
    bindir.mkdir()
    log = tmp_path / "py.log"
    stub = bindir / "python3"
    stub.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" > \"$PY_LOG\"\n"
        "printf '%s\\n' \"$PWD\" >> \"$PY_LOG\"\n"
        "printf '%s\\n' \"${PYTHONSAFEPATH-}\" >> \"$PY_LOG\"\n"
        "cat >/dev/null\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    runner = tmp_path / "runner"
    runner.mkdir()
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{binary.parent}{os.pathsep}{env.get('PATH', '')}"
    env["PY_LOG"] = str(log)
    env["RUNNER_TEMP"] = str(runner)
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_SHA"] = ""
    env["GITLEAKS_CONFIG"] = str(repo / "rules.toml")
    env["GITLEAKS_VERSION"] = _VERSION
    env["PYTHONSAFEPATH"] = "0"
    proc = subprocess.run(
        ["bash", "-c", _run_block("Scan with the base ignore file")],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    recorded = log.read_text(encoding="utf-8").splitlines()
    assert recorded[0].startswith("-I ")
    assert recorded[1] == str(runner)
    assert recorded[2] == "1"


def _crashing_code_table() -> bytes:
    """High bytes over a code table. marshal faults on this shape."""
    salt = 6
    length = 60
    planted = bytes((128 + ((salt * 17 + index) % 128)) for index in range(length))
    return _pyc_with_planted_code(planted)


def test_a_listed_crash_is_refused_by_the_child_not_the_parent(tmp_path: Path) -> None:
    """A signal from the child is a refusal, and the parent stays up.

    Loading the same bytes in this process, or treating the signal as
    success, changes the result.
    """
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "m.pyc").write_bytes(_crashing_code_table())
    _git(repo, "add", "m.pyc")
    _git(repo, "commit", "-q", "-m", "crash")
    proc = _scan_as_base(repo, tmp_path / "scan")
    assert proc.returncode == 1, proc.stderr
    assert "refusing unreadable bytecode" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_a_child_timeout_is_a_refusal(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "m.pyc").write_bytes(_compiled(tmp_path))
    _git(repo, "add", "m.pyc")
    _git(repo, "commit", "-q", "-m", "clean")
    proc = _scan_as_base(
        repo,
        tmp_path / "scan",
        {"BYTECODE_CHILD_SECONDS": "0.001"},
    )
    assert proc.returncode == 1, proc.stderr
    assert "refusing unreadable bytecode" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_the_bytecode_child_ignores_a_path_module(tmp_path: Path) -> None:
    """The load runs out of process and does not import from PYTHONPATH."""
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "m.pyc").write_bytes(_compiled(tmp_path))
    _git(repo, "add", "m.pyc")
    _git(repo, "commit", "-q", "-m", "clean")
    site = tmp_path / "site"
    site.mkdir()
    marker = tmp_path / "site-ran"
    (site / "sitecustomize.py").write_text(
        "open(__import__('os').environ['SITE_LOG'], 'w').write('ran\\n')\n",
        encoding="utf-8",
    )
    proc = _scan_as_base(
        repo,
        tmp_path / "scan",
        {"PYTHONPATH": str(site), "SITE_LOG": str(marker)},
    )
    assert proc.returncode == 0, proc.stderr
    assert not marker.exists()


def test_a_short_filename_and_a_twenty_character_line_table_are_refused(tmp_path: Path) -> None:
    base = compile("x = 1\n", "m.py", "exec")
    short = "ABCDEFGHIJ".encode("utf-16-le").decode("latin-1")
    twenty = "ABCDEFGHIJKLMNOPQRST".encode("utf-16-le")
    payloads = (
        _code_pyc(base.replace(co_filename=short)),
        _code_pyc(base.replace(co_names=base.co_names + (short,))),
        _code_pyc(base.replace(co_linetable=twenty)),
    )
    refused = 0
    for index, payload in enumerate(payloads):
        repo = tmp_path / f"repo{index}"
        _init(repo)
        (repo / "m.pyc").write_bytes(payload)
        _git(repo, "add", "m.pyc")
        _git(repo, "commit", "-q", "-m", "short-field")
        proc = _scan_as_base(repo, tmp_path / f"scan{index}")
        if proc.returncode == 1 and "refusing secret text inside bytecode" in proc.stderr:
            refused += 1
    assert refused == len(payloads)


def test_a_spliced_code_table_is_refused_before_it_is_loaded(tmp_path: Path) -> None:
    """The 3.13.5 crash shape: UTF-16 bytes written over the code table."""
    hidden = _planted(90).encode("latin-1")
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "m.pyc").write_bytes(_pyc_with_planted_code(hidden))
    _git(repo, "add", "m.pyc")
    _git(repo, "commit", "-q", "-m", "splice")
    proc = _scan(repo, tmp_path / "scan")
    assert proc.returncode == 1
    assert "refusing bytecode that is not on the base allow-list" in proc.stderr
    assert "Traceback" not in proc.stderr


def _fixed_stride_run(data: bytes, need: int = 16) -> bool:
    """Printable bytes with a fixed NUL gap. The old splice host tripped this."""

    def scan(stride: int) -> bool:
        gap = b"\x00" * (stride - 1)
        length = len(data)
        for align in range(stride):
            run = 0
            index = align
            while index + stride <= length:
                window = data[index : index + stride]
                if 32 <= window[0] <= 126 and window[1:] == gap:
                    run += 1
                    if run >= need:
                        return True
                else:
                    run = 0
                index += stride
        return False

    return bool(data) and (scan(2) or scan(3) or scan(4))


def test_a_clean_bytecode_host_passes_when_the_base_lists_it(tmp_path: Path) -> None:
    """The host itself is not a NUL run, so a splice is what changes the blob."""
    host = compile(
        "def f(a, b, c):\n"
        "    return (a + b) * c\n"
        "print(f(1, 2, 3))\n"
        "items = [f(i, i + 1, 2) for i in range(4)]\n",
        "m.py",
        "exec",
    )
    blob = _code_pyc(host)
    assert _fixed_stride_run(marshal.dumps(host)) is False
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "m.pyc").write_bytes(blob)
    _git(repo, "add", "m.pyc")
    _git(repo, "commit", "-q", "-m", "clean host")
    listed = _scan_as_base(repo, tmp_path / "listed")
    assert listed.returncode == 0, listed.stderr
    bare = tmp_path / "bare"
    _init(bare)
    (bare / "m.pyc").write_bytes(blob)
    _git(bare, "add", "m.pyc")
    _git(bare, "commit", "-q", "-m", "unlisted host")
    unlisted = _scan(bare, tmp_path / "unlisted")
    assert unlisted.returncode == 1
    assert "refusing bytecode that is not on the base allow-list" in unlisted.stderr


def test_random_non_text_code_splices_are_refused_without_a_crash(tmp_path: Path) -> None:
    """High bytes, random bytes, and NUL-free pairs must not reach marshal."""
    names = ("m.pyc", "notes.bin", "__pycache__/m.cpython-313.pyc")
    refused = 0
    total = 0
    for salt in range(12):
        length = 60 if salt % 2 == 0 else 40
        if salt % 3 == 0:
            planted = bytes((128 + ((salt * 17 + index) % 128)) for index in range(length))
        elif salt % 3 == 1:
            state = (salt + 1) * 997
            raw = bytearray()
            for index in range(length):
                state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
                raw.append(state & 0xFF)
            planted = bytes(raw)
        else:
            planted = bytes(((index + salt) % 255) + 1 for index in range(length))
        payload = _pyc_with_planted_code(planted)
        repo = tmp_path / f"splice{salt}"
        _init(repo)
        name = names[salt % len(names)]
        if "/" in name:
            (repo / name).parent.mkdir()
        (repo / name).write_bytes(payload)
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", "splice")
        proc = _scan(repo, tmp_path / f"splice-scan{salt}")
        total += 1
        if (
            proc.returncode == 1
            and "refusing bytecode that is not on the base allow-list" in proc.stderr
            and "Traceback" not in proc.stderr
        ):
            refused += 1
    assert total == 12
    assert refused == 12


def test_bytecode_constants_and_renamed_files_do_not_hide_utf16(tmp_path: Path) -> None:
    token_text = "".join(char + "\x00" for char in _token(80))
    compiled = tmp_path / "built"
    compiled.mkdir()
    source = compiled / "holds.py"
    source.write_text("T = " + repr(_utf16(81, "utf-16-le")) + "\n", encoding="utf-8")
    pyc = compiled / "holds.pyc"
    py_compile.compile(str(source), cfile=str(pyc), doraise=True)
    string_source = compiled / "holds_text.py"
    string_source.write_text("T = " + repr(token_text) + "\n", encoding="utf-8")
    string_pyc = compiled / "holds_text.pyc"
    py_compile.compile(str(string_source), cfile=str(string_pyc), doraise=True)
    payloads = (
        _header(marshal.dumps(_utf16(82, "utf-16-le"))),
        _header(marshal.dumps(_utf16(83, "utf-16"))),
        _header(marshal.dumps(_utf16(84, "utf-16-be"))),
        _header(marshal.dumps(token_text)),
        _header(marshal.dumps((_utf16(85, "utf-16-le"),))),
        _header(marshal.dumps({"k": _utf16(86, "utf-16-le")})),
        pyc.read_bytes(),
        string_pyc.read_bytes(),
        pyc.read_bytes(),
        _header(marshal.dumps(_utf16(87, "utf-16-le"))),
        _header(marshal.dumps(_utf16(88, "utf-16-le"))),
    )
    names = (
        "blob.pyc",
        "blob.pyc",
        "blob.pyc",
        "blob.pyc",
        "blob.pyc",
        "blob.pyc",
        "holds.pyc",
        "holds_text.pyc",
        "notes.txt",
        "config.txt",
        "README.md",
    )
    refused = 0
    for index, (name, payload) in enumerate(zip(names, payloads, strict=True)):
        repo = tmp_path / f"repo{index}"
        _init(repo)
        if "/" in name:
            (repo / name).parent.mkdir()
        (repo / name).write_bytes(payload)
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", "const")
        proc = _scan(repo, tmp_path / f"scan{index}")
        if proc.returncode == 1 and "refusing" in proc.stderr:
            refused += 1
    assert refused == len(payloads)


def test_historical_bytecode_on_main_is_consumed_exactly(tmp_path: Path) -> None:
    listed = subprocess.run(
        ["git", "rev-list", "--objects", "origin/main"],
        cwd=_REPO,
        capture_output=True,
        check=True,
    )
    blobs = []
    for line in listed.stdout.splitlines():
        if b" " not in line or not line.endswith(b".pyc"):
            continue
        oid, _, _path = line.partition(b" ")
        blobs.append(oid.decode("ascii"))
    assert len(blobs) == 7
    repo = tmp_path / "repo"
    _init(repo)
    for index, oid in enumerate(blobs):
        data = subprocess.run(
            ["git", "cat-file", "blob", oid],
            cwd=_REPO,
            capture_output=True,
            check=True,
        ).stdout
        (repo / f"blob{index}.pyc").write_bytes(data)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "history")
    proc = _scan_as_base(repo, tmp_path / "scan")
    assert proc.returncode == 0, proc.stderr
    base = _head(repo)
    (repo / "extra.pyc").write_bytes(_compiled(tmp_path))
    _git(repo, "add", "extra.pyc")
    _git(repo, "commit", "-q", "-m", "new bytecode")
    added = _scan_at_base(repo, tmp_path / "added", base)
    assert added.returncode == 1
    assert "refusing bytecode that is not on the base allow-list" in added.stderr
    assert "Traceback" not in added.stderr


def test_a_pyc_header_in_front_of_utf16_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    magic = bytes((0xF3, 0x0D, 0x0D, 0x0A)) + bytes(12)
    text = ("value " + _token(71)).encode("utf-16-le")
    (repo / "blob.pyc").write_bytes(magic + text)
    _git(repo, "add", "blob.pyc")
    _git(repo, "commit", "-q", "-m", "fake")
    proc = _scan(repo, tmp_path)
    assert proc.returncode == 1
    assert "refusing" in proc.stderr


def test_this_repo_history_scan_passes(tmp_path: Path) -> None:
    base = subprocess.run(
        ["git", "rev-parse", "origin/main"],
        cwd=_REPO,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    config = tmp_path / "base.toml"
    shown = subprocess.run(
        ["git", "show", f"{base}:.gitleaks.toml"],
        cwd=_REPO,
        capture_output=True,
        check=True,
    )
    config.write_bytes(shown.stdout)
    binary = _binary(tmp_path / "bin")
    runner = tmp_path / "runner"
    runner.mkdir()
    env = os.environ.copy()
    env["PATH"] = f"{binary.parent}{os.pathsep}{env.get('PATH', '')}"
    env["RUNNER_TEMP"] = str(runner)
    env["GITHUB_EVENT_NAME"] = "pull_request"
    env["BASE_SHA"] = base
    env["GITLEAKS_CONFIG"] = str(config)
    env["GITLEAKS_VERSION"] = _VERSION
    proc = subprocess.run(
        ["bash", "-c", _run_block("Scan with the base ignore file")],
        cwd=_REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_utf16_after_a_long_magic_header_is_refused(tmp_path: Path) -> None:
    hidden = ("value " + _token(70)).encode("utf-16-le")
    padding = bytes((index % 251) + 1 for index in range(600))
    refused = 0
    magics = (b"\x89PNG\r\n\x1a\n", b"%PDF-")
    for index, magic in enumerate(magics):
        repo = tmp_path / f"pad{index}"
        _init(repo)
        name = "blob.png" if magic.startswith(b"\x89") else "blob.pdf"
        (repo / name).write_bytes(magic + padding + hidden)
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", "padded")
        proc = _scan(repo, tmp_path / f"pad-scan{index}")
        if proc.returncode == 1 and "refusing UTF-16 text" in proc.stderr:
            refused += 1
    assert refused == len(magics)


def test_blob_exemption_list_is_read_from_the_base_not_the_head(tmp_path: Path) -> None:
    block = _run_block("Scan with the base ignore file")
    pull_request, _, _push = block.partition("elif [ -f scripts/gitleaks_blob_allow.txt ]")
    assert 'git show "${BASE_SHA}:scripts/gitleaks_blob_allow.txt"' in pull_request
    assert "cp scripts/gitleaks_blob_allow.txt" not in pull_request
    repo = tmp_path / "repo"
    _init(repo)
    blob = b"\x00" + bytes(range(1, 40))
    (repo / "clean.bin").write_bytes(blob)
    _git(repo, "add", "clean.bin")
    _git(repo, "commit", "-q", "-m", "blob")
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    oid = _oid(repo, "clean.bin")
    (repo / "scripts").mkdir()
    (repo / "scripts" / "gitleaks_blob_allow.txt").write_text(oid + "\n", encoding="utf-8")
    _git(repo, "add", "scripts/gitleaks_blob_allow.txt")
    _git(repo, "commit", "-q", "-m", "exemption only on the pull request")
    proc = _scan_at_base(repo, tmp_path / "scan", base)
    assert proc.returncode == 1
    assert "refusing" in proc.stderr


def test_a_renamed_code_object_is_not_exempt(tmp_path: Path) -> None:
    code = compile("x = 1\n", "m.py", "exec").replace(co_filename=("p" * 80) + ".py")
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "notes.txt").write_bytes(_code_pyc(code))
    _git(repo, "add", "notes.txt")
    _git(repo, "commit", "-q", "-m", "renamed")
    proc = _scan(repo, tmp_path / "scan")
    assert proc.returncode == 1
    assert "refusing" in proc.stderr


def test_a_non_code_marshal_object_is_not_exempt(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "m.pyc").write_bytes(_header(marshal.dumps("p" * 80)))
    _git(repo, "add", "m.pyc")
    _git(repo, "commit", "-q", "-m", "string")
    proc = _scan(repo, tmp_path / "scan")
    assert proc.returncode == 1
    assert "refusing" in proc.stderr


def test_a_short_utf16_constant_is_not_saved_by_the_blob_exemption(tmp_path: Path) -> None:
    """Ten interleaved pairs are too short for the raw code-table run."""
    hidden = ("ABCDEFGHIJ").encode("utf-16-le")
    assert len(hidden) == 20
    code = compile("x = 1\n", "m.py", "exec").replace(co_consts=(hidden,))
    cases = (
        _code_pyc(code),
        _header(marshal.dumps({"k": hidden})),
        _header(marshal.dumps({hidden: "v"})),
        _header(marshal.dumps((hidden,))),
    )
    refused = 0
    for index, payload in enumerate(cases):
        repo = tmp_path / f"short{index}"
        _init(repo)
        (repo / "m.pyc").write_bytes(payload)
        _git(repo, "add", "m.pyc")
        _git(repo, "commit", "-q", "-m", "short")
        proc = _scan_as_base(repo, tmp_path / f"short-scan{index}")
        if proc.returncode == 1 and "refusing secret text inside bytecode" in proc.stderr:
            refused += 1
    assert refused == len(cases)


def test_marshal_containers_are_refused_as_bytecode(tmp_path: Path) -> None:
    hidden = _utf16(99, "utf-16-le")
    payloads = (
        marshal.dumps({"k": hidden}),
        marshal.dumps({hidden: "v"}),
        marshal.dumps((hidden,)),
        marshal.dumps(frozenset((hidden,))),
    )
    refused = 0
    for index, payload in enumerate(payloads):
        repo = tmp_path / f"box{index}"
        _init(repo)
        (repo / "m.pyc").write_bytes(_header(payload))
        _git(repo, "add", "m.pyc")
        _git(repo, "commit", "-q", "-m", "box")
        proc = _scan_as_base(repo, tmp_path / f"box-scan{index}")
        if proc.returncode == 1 and "refusing secret text inside bytecode" in proc.stderr:
            refused += 1
    assert refused == len(payloads)


def test_a_long_bytecode_filename_is_not_refused(tmp_path: Path) -> None:
    code = compile("x = 1\n", "m.py", "exec").replace(co_filename=("p" * 80) + ".py")
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "m.pyc").write_bytes(_code_pyc(code))
    _git(repo, "add", "m.pyc")
    _git(repo, "commit", "-q", "-m", "filename")
    proc = _scan_as_base(repo, tmp_path / "scan")
    assert proc.returncode == 0, proc.stderr


def test_ascii_after_a_nul_in_a_constant_is_still_refused(tmp_path: Path) -> None:
    hidden = b"\x00" + (b"A" * 24)
    code = compile("x = 1\n", "m.py", "exec").replace(co_consts=(hidden,))
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "m.pyc").write_bytes(_code_pyc(code))
    _git(repo, "add", "m.pyc")
    _git(repo, "commit", "-q", "-m", "nul")
    proc = _scan_as_base(repo, tmp_path / "scan")
    assert proc.returncode == 1
    assert "refusing secret text inside bytecode" in proc.stderr


def test_a_deeply_nested_constant_is_refused(tmp_path: Path) -> None:
    nested: object = "x"
    for _ in range(1500):
        nested = (nested,)
    code = compile("x = 1\n", "m.py", "exec").replace(co_consts=(nested,))
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "m.pyc").write_bytes(_code_pyc(code))
    _git(repo, "add", "m.pyc")
    _git(repo, "commit", "-q", "-m", "deep")
    proc = _scan_as_base(repo, tmp_path / "scan")
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert "refusing unreadable bytecode: m.pyc" in proc.stderr


def test_a_lone_surrogate_constant_is_refused(tmp_path: Path) -> None:
    code = compile("x = 1\n", "m.py", "exec").replace(co_consts=("\ud800",))
    repo = tmp_path / "repo"
    _init(repo)
    (repo / "m.pyc").write_bytes(_code_pyc(code))
    _git(repo, "add", "m.pyc")
    _git(repo, "commit", "-q", "-m", "surrogate")
    proc = _scan_as_base(repo, tmp_path / "scan")
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert "refusing secret text inside bytecode" in proc.stderr


def test_a_short_utf16_run_is_refused_in_a_binary_and_a_constant(tmp_path: Path) -> None:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    state = 91
    chars = []
    for index in range(16):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(alphabet[state % len(alphabet)])
    key = "".join(("AK", "IA")) + "".join(chars)
    hidden = key.encode("utf-16-le")
    noise = bytes((index % 200) + 1 for index in range(40))
    planted = noise + hidden + noise
    png = tmp_path / "png"
    _init(png)
    (png / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + planted)
    _git(png, "add", "shot.png")
    _git(png, "commit", "-q", "-m", "png")
    png_proc = _scan(png, tmp_path / "png-scan")
    code = compile("x = 1\n", "m.py", "exec").replace(co_consts=(planted,))
    pyc = tmp_path / "pyc"
    _init(pyc)
    (pyc / "m.pyc").write_bytes(_code_pyc(code))
    _git(pyc, "add", "m.pyc")
    _git(pyc, "commit", "-q", "-m", "pyc")
    pyc_proc = _scan_as_base(pyc, tmp_path / "pyc-scan")
    assert png_proc.returncode == 1 and "refusing UTF-16 text" in png_proc.stderr
    assert pyc_proc.returncode == 1 and "refusing secret text inside bytecode" in pyc_proc.stderr


def test_nul_strides_behind_binary_magic_are_refused(tmp_path: Path) -> None:
    letters = "ABCDEFGHIJKLMNOP"
    magics = ((b"\x89PNG\r\n\x1a\n", "shot.png"), (b"PK\x03\x04", "pack.zip"))
    refused = 0
    total = 0
    for stride in (2, 3, 4):
        planted = b"".join(bytes((ord(char),)) + (b"\x00" * (stride - 1)) for char in letters)
        for index, (magic, name) in enumerate(magics):
            repo = tmp_path / f"stride{stride}-{index}"
            _init(repo)
            (repo / name).write_bytes(magic + planted)
            _git(repo, "add", name)
            _git(repo, "commit", "-q", "-m", "stride")
            proc = _scan(repo, tmp_path / f"stride-scan{stride}-{index}")
            total += 1
            if proc.returncode == 1 and "refusing UTF-16 text" in proc.stderr:
                refused += 1
    assert total == 6
    assert refused == 6
    noise = bytes((index % 200) + 1 for index in range(80))
    clean = 0
    for index, (magic, name) in enumerate(magics):
        repo = tmp_path / f"clean{index}"
        _init(repo)
        (repo / name).write_bytes(magic + noise)
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", "clean")
        if _scan(repo, tmp_path / f"clean-scan{index}").returncode == 0:
            clean += 1
    assert clean == len(magics)


def test_mixed_nul_gaps_are_refused_and_wider_gaps_are_not(tmp_path: Path) -> None:
    """Gaps of 1 to 3 NULs may mix. Four NULs, or a non-NUL separator, stay."""
    letters = "ABCDEFGHIJKLMNOP"
    gaps = (1, 2, 3)
    little = b"".join(
        bytes((ord(char),)) + (b"\x00" * gaps[index % 3]) for index, char in enumerate(letters)
    )
    big = b"".join(
        (b"\x00" * gaps[index % 3]) + bytes((ord(char),)) for index, char in enumerate(letters)
    )
    refused = 0
    for index, planted in enumerate((little, big)):
        repo = tmp_path / f"mix{index}"
        _init(repo)
        (repo / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + planted)
        _git(repo, "add", "shot.png")
        _git(repo, "commit", "-q", "-m", "mixed")
        proc = _scan(repo, tmp_path / f"mix-scan{index}")
        if proc.returncode == 1 and "refusing UTF-16 text" in proc.stderr:
            refused += 1
    assert refused == 2
    wide = b"".join(bytes((ord(char),)) + (b"\x00" * 4) for char in letters)
    separated = b"".join(bytes((ord(char), 1)) for char in letters)
    passed = 0
    for index, planted in enumerate((wide, separated)):
        repo = tmp_path / f"limit{index}"
        _init(repo)
        (repo / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + planted)
        _git(repo, "add", "shot.png")
        _git(repo, "commit", "-q", "-m", "limit")
        if _scan(repo, tmp_path / f"limit-scan{index}").returncode == 0:
            passed += 1
    assert passed == 2
    doc = (_REPO / "docs" / "SECRET_SCAN.md").read_text(encoding="utf-8")
    assert "4 or more NULs" in doc
    assert "separator that is not a NUL" in doc


def test_a_big_endian_run_at_the_threshold_is_refused(tmp_path: Path) -> None:
    """Exactly eight big-endian characters, then a byte that is not NUL.

    A longer run is also caught by the shifted little-endian alignment.
    The threshold length is not, so the big-endian walk has to see it.
    Seven characters stay under the threshold.
    """
    letters = "ABCDEFGH"
    short = "ABCDEFG"
    refused = 0
    passed = 0
    for stride in (2, 3, 4):
        planted = b"".join(
            (b"\x00" * (stride - 1)) + bytes((ord(char),)) for char in letters
        ) + b"\x01"
        repo = tmp_path / f"be{stride}"
        _init(repo)
        (repo / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + planted)
        _git(repo, "add", "shot.png")
        _git(repo, "commit", "-q", "-m", "big-endian")
        proc = _scan(repo, tmp_path / f"be-scan{stride}")
        if proc.returncode == 1 and "refusing UTF-16 text" in proc.stderr:
            refused += 1
        under = b"".join(
            (b"\x00" * (stride - 1)) + bytes((ord(char),)) for char in short
        ) + b"\x01"
        quiet = tmp_path / f"under{stride}"
        _init(quiet)
        (quiet / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + under)
        _git(quiet, "add", "shot.png")
        _git(quiet, "commit", "-q", "-m", "under")
        if _scan(quiet, tmp_path / f"under-scan{stride}").returncode == 0:
            passed += 1
    assert refused == 3
    assert passed == 3


def test_a_little_endian_run_at_the_threshold_is_refused(tmp_path: Path) -> None:
    """Exactly eight little-endian characters, including mixed gaps.

    Nine or more are also caught by the shifted big-endian walk. The
    threshold length is not, and a mixed gap is not a fixed stride, so
    both the little-endian walk and the mixed-gap walk have to see it.
    """
    letters = "ABCDEFGH"
    short = "ABCDEFG"
    refused = 0
    passed = 0
    patterns = []
    for stride in (2, 3, 4):
        patterns.append(
            b"".join(bytes((ord(char),)) + (b"\x00" * (stride - 1)) for char in letters) + b"\x01"
        )
    gaps = (1, 2, 3, 1, 2, 3, 2, 1)
    patterns.append(
        b"".join(bytes((ord(char),)) + (b"\x00" * gap) for char, gap in zip(letters, gaps, strict=True))
        + b"\x01"
    )
    for index, planted in enumerate(patterns):
        repo = tmp_path / f"le{index}"
        _init(repo)
        (repo / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + planted)
        _git(repo, "add", "shot.png")
        _git(repo, "commit", "-q", "-m", "little-endian")
        proc = _scan(repo, tmp_path / f"le-scan{index}")
        if proc.returncode == 1 and "refusing UTF-16 text" in proc.stderr:
            refused += 1
    for stride in (2, 3, 4):
        under = b"".join(
            bytes((ord(char),)) + (b"\x00" * (stride - 1)) for char in short
        ) + b"\x01"
        quiet = tmp_path / f"le-under{stride}"
        _init(quiet)
        (quiet / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + under)
        _git(quiet, "add", "shot.png")
        _git(quiet, "commit", "-q", "-m", "under")
        if _scan(quiet, tmp_path / f"le-under-scan{stride}").returncode == 0:
            passed += 1
    assert refused == 4
    assert passed == 3


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
