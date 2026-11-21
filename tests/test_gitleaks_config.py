# PURPOSE: The gitleaks config must load built-in rules, detect synthetic
# tokens, and keep allowlists too narrow to hide a lookalike path.

from __future__ import annotations

import base64
import json
import math
import re
import secrets
import shutil
import string
import subprocess
import tempfile
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG = REPO_ROOT / ".gitleaks.toml"
IGNORE = REPO_ROOT / ".gitleaksignore"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security-gitleaks.yml"

_AWS_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_ALNUM = string.ascii_letters + string.digits

_BENIGN = """\
region = us-east-1
owner = sample-team
note = placeholders are not credentials
AKIA
ghp_
github_pat_
xoxb-
eyJ
"""


def _entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _sample(build: Callable[[], str]) -> str:
    for _ in range(8):
        value = build()
        if _entropy(value) >= 3.2:
            return value
    raise AssertionError("could not build a high-entropy sample")


def _aws() -> str:
    body = "".join(secrets.choice(_AWS_ALPHABET) for _ in range(16))
    if body.endswith("EXAMPLE"):
        body = "Z" + body[:-1]
    return "AKIA" + body


def _github_pat() -> str:
    return "ghp_" + "".join(secrets.choice(_ALNUM) for _ in range(36))


def _github_fine_grained() -> str:
    return "github_pat_" + "".join(secrets.choice(_ALNUM) for _ in range(82))


def _slack_bot() -> str:
    def digits(count: int) -> str:
        return "".join(secrets.choice(string.digits) for _ in range(count))

    suffix = "".join(secrets.choice(_ALNUM) for _ in range(24))
    return f"xoxb-{digits(11)}-{digits(11)}-{suffix}"


def _jwt() -> str:
    def encode(payload: dict[str, object]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = encode({"alg": "HS256", "typ": "JWT"})
    body = encode({"sub": "gitleaks-fixture", "iat": 1516239022})
    signature = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    return f"{header}.{body}.{signature}"


def _allowlist_paths(text: str) -> list[str]:
    match = re.search(r"(?ms)^\[allowlist\].*?^paths\s*=\s*\[(.*?)^\]", text)
    assert match is not None
    return re.findall(r"'''(.+?)'''", match.group(1))


def _require_gitleaks() -> str:
    binary = shutil.which("gitleaks")
    assert binary is not None, "gitleaks is not on PATH"
    proc = subprocess.run(
        [binary, "version"],
        check=True,
        capture_output=True,
        text=True,
    )
    version = proc.stdout.strip()
    assert version == "8.30.1", f"expected gitleaks 8.30.1, found {version}"
    return binary


def _redact(text: str) -> str:
    text = re.sub(r"AKIA[A-Z2-7]{16}", "[redacted]", text)
    text = re.sub(r"ghp_[0-9A-Za-z]{36}", "[redacted]", text)
    text = re.sub(r"github_pat_[0-9A-Za-z_]{82}", "[redacted]", text)
    text = re.sub(r"xoxb-[0-9A-Za-z-]{20,}", "[redacted]", text)
    text = re.sub(
        r"ey[A-Za-z0-9]{17,}\.ey[A-Za-z0-9_\/-]{17,}\.[A-Za-z0-9_\/-]{10,}",
        "[redacted]",
        text,
    )
    return text


@contextmanager
def _repo() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="gitleaks-config-") as tmp:
        root = Path(tmp)
        subprocess.run(["git", "-C", str(root), "init", "-q", "-b", "main"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "config", "user.email", "gitleaks-fixture@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "config", "user.name", "gitleaks-fixture"],
            check=True,
        )
        yield root


def _write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _commit(root: Path) -> None:
    subprocess.run(
        ["git", "-C", str(root), "add", "."],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
        check=True,
    )


def _scan(root: Path) -> list[tuple[str, str]]:
    binary = _require_gitleaks()
    with tempfile.TemporaryDirectory(prefix="gitleaks-report-") as tmp:
        report = Path(tmp) / "report.json"
        ignore = Path(tmp) / "ignore"
        ignore.mkdir()
        proc = subprocess.run(
            [
                binary,
                "detect",
                "--source",
                str(root),
                "--config",
                str(CONFIG),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--gitleaks-ignore-path",
                str(ignore),
                "--redact",
                "--no-banner",
                "--no-color",
                "--log-level",
                "error",
                "--exit-code",
                "1",
            ],
            cwd=root,
            capture_output=True,
            text=True,
        )
        if proc.returncode not in (0, 1):
            detail = _redact(proc.stderr)[-500:]
            raise AssertionError(f"gitleaks failed with exit {proc.returncode}: {detail}")
        payload = json.loads(report.read_text() or "[]")
        summary = [
            (str(item.get("RuleID", "")), str(item.get("File", "")))
            for item in payload
        ]
        for item in payload:
            item.clear()
        return summary


def test_config_extends_default_rules() -> None:
    text = CONFIG.read_text()
    assert "[extend]" in text
    assert re.search(r"(?m)^useDefault\s*=\s*true\s*$", text)


def test_allowlist_paths_are_anchored() -> None:
    paths = _allowlist_paths(CONFIG.read_text())
    assert paths
    for pattern in paths:
        assert pattern.startswith("^") or pattern.startswith("(^|"), pattern
        assert (
            pattern.endswith("$")
            or pattern.endswith("/")
            or pattern.endswith("(/|$)")
        ), pattern
        assert "test_appsec" not in pattern
        assert "test_egress" not in pattern
        assert "test_gitleaks" not in pattern


def test_ignore_entries_are_exact_fingerprints() -> None:
    entries = [
        line.strip()
        for line in IGNORE.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert entries == [
        "67c651da93fc759b016e981c7b8b5b2d277a23a5:tests/test_appsec_antigen_mcp_gates.py:generic-api-key:250"
    ]


def test_config_detects_synthetic_tokens() -> None:
    expected = {
        "cloud.txt": "aws-access-token",
        "git.txt": "github-pat",
        "fine.txt": "github-fine-grained-pat",
        "chat.txt": "slack-bot-token",
        "session.txt": "jwt",
        "nested/src/scp/mask_secrets.py": "github-pat",
        "src/scp/mask_secrets.py.extra": "github-fine-grained-pat",
        "elsewhere/tests/fixtures/hazard.txt": "jwt",
        "leak.md.txt": "github-pat",
    }
    hidden = (
        "src/scp/mask_secrets.py",
        "tests/fixtures/hazard.txt",
        "leak.md",
    )
    with _repo() as root:
        _write(root, "cloud.txt", _sample(_aws) + "\n")
        _write(root, "git.txt", _sample(_github_pat) + "\n")
        _write(root, "fine.txt", _sample(_github_fine_grained) + "\n")
        _write(root, "chat.txt", _sample(_slack_bot) + "\n")
        _write(root, "session.txt", _sample(_jwt) + "\n")
        _write(root, "src/scp/mask_secrets.py", _sample(_aws) + "\n")
        _write(root, "nested/src/scp/mask_secrets.py", _sample(_github_pat) + "\n")
        _write(root, "src/scp/mask_secrets.py.extra", _sample(_github_fine_grained) + "\n")
        _write(root, "tests/fixtures/hazard.txt", _sample(_slack_bot) + "\n")
        _write(root, "elsewhere/tests/fixtures/hazard.txt", _sample(_jwt) + "\n")
        _write(root, "leak.md", _sample(_aws) + "\n")
        _write(root, "leak.md.txt", _sample(_github_pat) + "\n")
        _commit(root)
        summary = _scan(root)

    assert summary
    found: dict[str, set[str]] = {}
    for rule, path in summary:
        found.setdefault(path, set()).add(rule)
    for path, rule in expected.items():
        assert rule in found.get(path, set()), path
    for path in hidden:
        assert path not in found, path


def test_workflow_pins_action_and_scans_full_range() -> None:
    text = WORKFLOW.read_text()
    assert "gitleaks/gitleaks-action@v2" not in text
    assert (
        "uses: gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7"
        in text
    )
    assert 'GITLEAKS_VERSION: "8.30.1"' in text
    assert "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" in text
    job = text.split("jobs:", 1)[1]
    assert re.search(r"(?m)^    timeout-minutes:\s*[1-9]\d*\s*$", job)
    assert "if: github.event_name == 'pull_request'" in job
    log_opts = (
        '--log-opts="-m ${{ github.event.pull_request.base.sha }}'
        '..${{ github.event.pull_request.head.sha }}"'
    )
    assert log_opts in job
    assert "tests/test_gitleaks_config.py" in job


def test_benign_sample_passes() -> None:
    with _repo() as root:
        _write(root, "notes.txt", _BENIGN)
        _commit(root)
        summary = _scan(root)
    assert summary == []
