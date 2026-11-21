# PURPOSE: CSI color sequences are not a refused control. Other C0 stays refused.
# Private-key detection does not copy the tail of the buffer.

from __future__ import annotations

import subprocess
import sys

import pytest

from scp import encounter_auto_log, mask_secrets, secret_surface


def _token() -> str:
    return "".join(("gh", "p_")) + ("A" * 36)


def _paint(text: str) -> str:
    return "\x1b[31m" + text + "\x1b[0m"


def test_colored_text_is_not_refused_and_a_colored_token_is_masked() -> None:
    note = _paint("Thanks for the note.")
    assert secret_surface.has_refused_control("\x1b") is True
    assert mask_secrets.has_secrets(note) is False
    outbound = mask_secrets.prepare_outbound(note)
    assert "Thanks" in outbound
    assert "\x1b" not in outbound
    token = _token()
    colored = _paint(token)
    assert mask_secrets.has_secrets(colored) is True
    masked = mask_secrets.mask(colored)
    leaked = token in masked or token in mask_secrets.prepare_outbound(colored)
    assert leaked is False


def _eight_visible(token: str, text: str) -> bool:
    return any(token[index : index + 8] in text for index in range(0, len(token) - 7))


def test_complete_sgr_erase_and_osc_do_not_hide_a_token() -> None:
    token = _token()
    sequences = (
        "\x1b[K",
        "\x1b[2J",
        "\x1b[38:5:196m",
        "\x1b]8;;https://example.test/\x07",
    )
    leaked = 0
    for sequence in sequences:
        text = token[:8] + sequence + token[8:]
        outbound = mask_secrets.prepare_outbound(text)
        if _eight_visible(token, mask_secrets.mask(text)) or _eight_visible(token, outbound):
            leaked += 1
    assert leaked == 0


def test_unfinished_escapes_do_not_leak_on_mask_egress_or_log() -> None:
    token = _token()
    sequences = ("\x1b[31", "\x1b[", "\x1b[?", "\x9b", "\x9b31")
    leaked = 0
    for sequence in sequences:
        text = token[:8] + sequence + token[8:]
        masked = mask_secrets.mask(text)
        logged = encounter_auto_log._sanitize_for_log(text, "reversal")
        try:
            outbound = mask_secrets.prepare_outbound(text)
        except mask_secrets.EgressMaskError:
            outbound = ""
        else:
            leaked += 1
        if _eight_visible(token, masked) or _eight_visible(token, outbound) or _eight_visible(token, logged):
            leaked += 1
        checked = subprocess.run(
            [sys.executable, "-m", "scp.mask_secrets", "--egress-prepare", "-"],
            input=text.encode("utf-8"),
            capture_output=True,
            check=False,
        )
        if checked.returncode == 0 or checked.stdout:
            leaked += 1
    assert leaked == 0


def test_control_character_sweep_does_not_leak() -> None:
    token = _token()
    codes = [code for code in range(0x20) if code not in (0x09, 0x0A, 0x0D)]
    codes.append(0x7F)
    codes.extend(range(0x80, 0xA0))
    leaked = 0
    for code in codes:
        mark = chr(code)
        text = token[:8] + mark + token[8:]
        if _eight_visible(token, mask_secrets.mask(text)):
            leaked += 1
        try:
            mask_secrets.prepare_outbound(text)
        except mask_secrets.EgressMaskError:
            pass
        else:
            leaked += 1
    assert leaked == 0


def test_bare_esc_and_esc_inside_a_token_are_still_refused() -> None:
    token = _token()
    for text in ("\x1b", "\x1b[31", token[:8] + "\x1b" + token[8:]):
        assert mask_secrets.has_secrets(text) is True
        with pytest.raises(mask_secrets.EgressMaskError):
            mask_secrets.prepare_outbound(text)
    for mark in ("\t", "\n", "\r"):
        assert secret_surface.is_refused_control(mark) is False
        assert mask_secrets.has_secrets("Thanks" + mark + "there") is False


def test_private_key_block_is_redacted_without_copying_the_tail() -> None:
    kind = "PRIVATE KEY"
    text = "-----BEGIN " + kind + "-----\n" + ("A" * 64) + "\n-----END " + kind + "-----"
    masked = mask_secrets.mask(text)
    kept = ("A" * 8) in masked
    missing = "pad\n-----BEGIN " + "RSA " + kind + "-----\n" + ("B" * 32)
    kept = kept or ("B" * 8) in mask_secrets.mask(missing + ("C" * 1000))
    assert kept is False
