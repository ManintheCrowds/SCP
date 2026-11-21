# PURPOSE: mask, has_secrets, and egress share one linear normalization.

from __future__ import annotations

import pytest

from scp import mask_secrets, secret_surface


def _token() -> str:
    return "gh" + "p_" + ("A" * 36)


def _assignment(token: str) -> str:
    return "export GH_TOKEN=" + token


def test_filler_categories_do_not_hide_a_token() -> None:
    token = _token()
    # Cf, Mn (including U+17B4 / U+17B5), Zl, and Zp. Not a hand-picked set of
    # zero-width code points: each character is selected by Unicode category.
    fillers = [
        "\u2060",  # Cf WORD JOINER
        "\u0301",  # Mn COMBINING ACUTE ACCENT
        "\u17b4",  # Mn KHMER VOWEL INHERENT AQ
        "\u17b5",  # Mn KHMER VOWEL INHERENT AA
        "\u2028",  # Zl LINE SEPARATOR
        "\u2029",  # Zp PARAGRAPH SEPARATOR
    ]
    for filler in fillers:
        text = _assignment(token[:8] + filler + token[8:])
        assert secret_surface.is_filler(filler)
        assert mask_secrets.has_secrets(text)
        assert token not in mask_secrets.mask(text)
        outbound = mask_secrets.prepare_outbound(text)
        assert token not in outbound


def test_line_separator_between_every_character_is_masked() -> None:
    token = _token()
    text = _assignment("\u2028".join(token))
    assert mask_secrets.has_secrets(text)
    assert token not in mask_secrets.mask(text)


def test_both_views_are_scanned(monkeypatch: pytest.MonkeyPatch) -> None:
    token = _token()
    calls: list[str] = []
    real_spans = mask_secrets.credential_spans

    def spy(text: str):
        calls.append(text)
        return real_spans(text)

    monkeypatch.setattr(mask_secrets, "credential_spans", spy)
    monkeypatch.setattr(
        secret_surface,
        "detection_views",
        lambda _text: ("clean line", _assignment(token)),
    )
    assert mask_secrets.has_secrets("ignored")
    assert token not in mask_secrets.mask("ignored")
    assert "clean line" in calls
    assert _assignment(token) in calls


def test_unjoined_view_still_finds_a_visible_token(monkeypatch: pytest.MonkeyPatch) -> None:
    token = _token()
    monkeypatch.setattr(
        secret_surface,
        "detection_views",
        lambda _text: (_assignment(token), "notes only"),
    )
    assert mask_secrets.has_secrets("ignored")
    assert token not in mask_secrets.mask("ignored")


def test_normalization_budget_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secret_surface, "_BUDGET_FACTOR", 0)
    token = _token()
    text = _assignment(token) + "\n" + ("x" * 64)
    assert mask_secrets.has_secrets(text)
    assert mask_secrets.mask(text) == "[REDACTED]"
    assert token not in mask_secrets.mask(text)
    with pytest.raises(mask_secrets.EgressMaskError):
        mask_secrets.prepare_outbound(text)


def test_plain_email_behavior_is_unchanged() -> None:
    assert mask_secrets.mask("Contact ada@example.com.") == "Contact [EMAIL_REDACTED]."
    assert mask_secrets.has_secrets("Contact ada@example.com.") is False
