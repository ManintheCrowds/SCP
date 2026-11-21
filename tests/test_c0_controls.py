# PURPOSE: C0 controls other than tab, LF, and CR are refused on every surface.

from __future__ import annotations

import subprocess
import sys

from scp import mask_secrets, secret_surface

_SCRIPT = [sys.executable, "-m", "scp.mask_secrets"]
# NUL, SOH, BEL, BS, SO, ESC, and FS through US.
_CONTROLS = (
    "\u0000",
    "\u0001",
    "\u0007",
    "\u0008",
    "\u000e",
    "\u001b",
    "\u001c",
    "\u001d",
    "\u001e",
    "\u001f",
)


def _token() -> str:
    return "".join(("gh", "p_")) + ("A" * 36)


def test_c0_controls_inside_a_token_fail_on_every_surface(tmp_path) -> None:
    token = _token()
    for mark in _CONTROLS:
        assert secret_surface.is_refused_control(mark)
        text = token[:8] + mark + token[8:]
        assert mask_secrets.has_secrets(text)
        masked = mask_secrets.mask(text)
        assert token not in masked
        assert mark not in masked
        try:
            outbound = mask_secrets.prepare_outbound(text)
        except mask_secrets.EgressMaskError:
            outbound = ""
        else:
            raise AssertionError("egress accepted a control character")
        assert token not in outbound
        path = tmp_path / "note.txt"
        path.write_bytes(text.encode("utf-8"))
        checked = subprocess.run(
            [*_SCRIPT, "--check", str(path)],
            capture_output=True,
            check=False,
        )
        assert checked.returncode != 0
        assert token.encode("utf-8") not in checked.stdout
        assert token.encode("utf-8") not in checked.stderr
        egress = subprocess.run(
            [*_SCRIPT, "--egress-prepare", "-"],
            input=text.encode("utf-8"),
            capture_output=True,
            check=False,
        )
        assert egress.returncode != 0
        assert egress.stdout == b""
        assert token.encode("utf-8") not in egress.stderr


def test_tab_lf_and_cr_are_not_refused() -> None:
    for mark in ("\t", "\n", "\r"):
        assert secret_surface.is_refused_control(mark) is False
