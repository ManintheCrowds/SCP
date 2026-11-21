# PURPOSE: Unlabeled token shapes and personal-data rules on every surface.

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scp import mask_secrets

_SCRIPT = [sys.executable, "-m", "scp.mask_secrets"]


def _cat(*parts: str) -> str:
    return "".join(parts)


def _samples() -> list[tuple[str, str]]:
    ssn = "000" + "-" + "00" + "-" + "0000"
    phone = "555" + "-010-" + "0000"
    return [
        ("personal", _cat("gh", "p_") + ("A" * 36)),
        ("oauth", _cat("gh", "o_") + ("B" * 36)),
        ("fine", _cat("github", "_pat_") + ("C" * 22)),
        ("lab", _cat("gl", "pat-") + ("D" * 20)),
        ("project", _cat("sk-", "proj-") + ("E" * 20)),
        ("access", _cat("AK", "IA") + ("F" * 16)),
        ("slack", _cat("xo", "xb-") + ("1" * 10) + "-" + ("A" * 16)),
        ("jwt", ("a" * 16) + "." + ("b" * 16) + "." + ("c" * 16)),
        ("patient", "Patient: Ada Lovelace"),
        ("dob", "Date of Birth: 2 January 1900"),
        ("ssn", ssn),
        ("phone", phone),
    ]


def test_every_surface_masks_bare_tokens_and_pii(tmp_path: Path) -> None:
    for name, secret in _samples():
        text = "note " + secret + " end"
        assert mask_secrets.has_secrets(text), name
        masked = mask_secrets.mask(text)
        assert secret not in masked, name
        outbound = mask_secrets.prepare_outbound(text)
        assert secret not in outbound, name
        path = tmp_path / f"{name}.txt"
        path.write_text(text, encoding="utf-8")
        checked = subprocess.run(
            [*_SCRIPT, "--check", str(path)],
            capture_output=True,
            check=False,
        )
        assert checked.returncode != 0, name
        assert secret.encode("utf-8") not in checked.stdout
        assert secret.encode("utf-8") not in checked.stderr
        egress = subprocess.run(
            [*_SCRIPT, "--egress-prepare", "-"],
            input=text.encode("utf-8"),
            capture_output=True,
            check=False,
        )
        assert secret.encode("utf-8") not in egress.stdout, name
        if egress.returncode != 0:
            assert egress.stdout == b""
