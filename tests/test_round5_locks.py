# PURPOSE: Mutants that used to survive now fail these checks.

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from scp import encounter_auto_log, mask_secrets

_REPO = Path(__file__).resolve().parents[1]


def _workflow() -> str:
    return (_REPO / ".github" / "workflows" / "security-gitleaks.yml").read_text(encoding="utf-8")


def test_action_pins_the_gitleaks_version() -> None:
    lines = _workflow().splitlines()
    in_action = False
    version = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("uses:") and "gitleaks-action@" in stripped:
            in_action = True
            continue
        if in_action and stripped.startswith("- name:"):
            break
        if in_action and stripped.startswith("GITLEAKS_VERSION:"):
            version = stripped.split(":", 1)[1].strip().strip('"')
    assert version == "8.30.1"


def test_environment_version_is_refused_before_a_clean_scan(tmp_path: Path) -> None:
    binary = Path("/tmp/gitleaks-bin/gitleaks")
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", "init", "-q", "-b", "main"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    (repo / "note.txt").write_text("plain\n", encoding="utf-8")
    subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", "add", "note.txt"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-c", "user.email=ci@example.com", "-c", "user.name=ci", "commit", "-q", "-m", "plain"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    script = ""
    lines = _workflow().splitlines()
    for index, line in enumerate(lines):
        if line.strip() not in {"name: Scan with the base ignore file", "- name: Scan with the base ignore file"}:
            continue
        for cursor in range(index + 1, index + 30):
            if lines[cursor].strip() == "run: |":
                body = []
                base = None
                for raw in lines[cursor + 1 :]:
                    if raw.strip() == "":
                        body.append("")
                        continue
                    indent = len(raw) - len(raw.lstrip(" "))
                    if base is None:
                        base = indent
                    if indent < base:
                        break
                    body.append(raw[base:])
                script = "\n".join(body).strip() + "\n"
                break
    env = os.environ.copy()
    env["PATH"] = f"{binary.parent}{os.pathsep}{env.get('PATH', '')}"
    env["RUNNER_TEMP"] = str(tmp_path / "runner")
    (tmp_path / "runner").mkdir()
    env["GITHUB_EVENT_NAME"] = "push"
    env["GITLEAKS_CONFIG"] = str(repo / "note.txt")
    env["GITLEAKS_VERSION"] = "8.29.0"
    proc = subprocess.run(
        ["bash", "-c", script],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "refusing GITLEAKS_VERSION" in proc.stderr


def test_bare_begin_markers_stay_under_a_second_and_a_half() -> None:
    text = "-----BEGIN " * (1_000_000 // len("-----BEGIN "))
    started = time.perf_counter()
    assert mask_secrets.has_secrets(text) is False
    assert time.perf_counter() - started < 1.5


def test_non_marker_signature_over_512_is_masked() -> None:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    def segment(length: int, salt: int) -> str:
        state = salt & 0xFFFFFFFF
        chars: list[str] = []
        for index in range(length):
            state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
            chars.append(alphabet[state % len(alphabet)])
        return "".join(chars)

    header = "A" + segment(31, 2)
    payload = segment(40, 3)
    signature = segment(600, 4)
    token = header + "." + payload + "." + signature
    assert not token.startswith("".join(("ey", "J")))
    leaked = signature in mask_secrets.mask(token)
    assert leaked is False


def test_log_cut_does_not_keep_a_lowercase_prose_word() -> None:
    limit = encounter_auto_log._LOG_MASK_CHARS
    body = ("n" * limit) + "\nbefore the note"
    prefix = encounter_auto_log._prefix_for_mask(body)
    assert "before" not in prefix
