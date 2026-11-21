# PURPOSE: CSI color sequences are not a refused control. Other C0 stays refused.
# Private-key detection does not copy the tail of the buffer.

from __future__ import annotations

import pytest

from scp import mask_secrets, secret_surface


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


def test_bare_esc_and_esc_inside_a_token_are_still_refused() -> None:
    token = _token()
    for text in ("\x1b", "\x1b[31", "\x1b[2J", token[:8] + "\x1b" + token[8:]):
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
