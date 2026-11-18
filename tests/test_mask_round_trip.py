# PURPOSE: Clean text is unchanged. Secrets are replaced inside the original text.

from __future__ import annotations

from scp import mask_secrets


def test_clean_text_round_trips() -> None:
    samples = (
        "hello\u2014world",
        "hello\u2013world",
        "hello\u00a0world",
        "ﬁle",
        'say "hello\nand\nmore\n',
        "wrapped\nwords stay\n",
    )
    for sample in samples:
        assert mask_secrets.mask(sample) == sample


def test_secret_inside_dashed_text_is_replaced() -> None:
    text = "note\u2014 password: hunter2 \u2014end"
    out = mask_secrets.mask(text)
    assert "hunter2" not in out
    assert out.startswith("note\u2014")
    assert out.endswith("\u2014end")
    assert "[REDACTED]" in out
