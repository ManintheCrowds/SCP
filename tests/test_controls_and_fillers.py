# PURPOSE: Refused controls and filler/homoglyph normalization.

from __future__ import annotations

import pytest

from scp import mask_secrets, secret_surface


def _token() -> str:
    return "".join(("gh", "p_")) + ("A" * 36)


def _disguised(mark: str) -> str:
    token = _token()
    return "export GH_TOKEN=" + token[:8] + mark + token[8:]


def test_refused_controls_fail_closed() -> None:
    for mark in ("\u000b", "\u000c", "\u007f", "\u0085", "\u009b"):
        assert secret_surface.is_refused_control(mark)
        text = "note" + mark
        assert mask_secrets.has_secrets(text)
        assert mark not in mask_secrets.mask(text)
        with pytest.raises(mask_secrets.EgressMaskError):
            mask_secrets.prepare_outbound(text)


def test_control_inside_a_token_is_masked() -> None:
    token = _token()
    text = _disguised("\u007f")
    assert mask_secrets.has_secrets(text)
    masked = mask_secrets.mask(text)
    assert token not in masked
    assert "\u007f" not in masked


def test_hangul_nbsp_fullwidth_and_homoglyph_do_not_hide_a_token() -> None:
    token = _token()
    marks = (
        "\u115f",
        "\u1160",
        "\u3164",
        "\uffa0",
        "\u00a0",
        "\u2003",
        "\uff21",
        "\u0410",
    )
    for mark in marks:
        text = _disguised(mark)
        assert mask_secrets.has_secrets(text), hex(ord(mark))
        masked = mask_secrets.mask(text)
        assert token[8:20] not in masked
        assert mark not in masked
