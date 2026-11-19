# PURPOSE: Wrapped tokens are joined from the previous line ending only.

from __future__ import annotations

import time

from scp import mask_secrets, secret_surface


def _token() -> str:
    return "gh" + "p_" + ("A" * 36)


def _jwt() -> str:
    return ("a" * 16) + "." + ("b" * 16) + "." + ("c" * 16)


def _assignment(token: str | None = None) -> str:
    return "export GH_TOKEN=" + (token if token is not None else _token())


def _assert_masked(text: str, secret: str) -> str:
    assert mask_secrets.has_secrets(text)
    masked = mask_secrets.mask(text)
    assert secret not in masked
    outbound = mask_secrets.prepare_outbound(text)
    assert secret not in outbound
    return masked


def test_assignment_wraps_at_widths_17_through_23() -> None:
    line = _assignment()
    secret = _token()
    assert len("export GH_TOKEN=") == 16
    for width in range(17, 24):
        wrapped = line[:width] + "\n" + line[width:]
        _assert_masked(wrapped, secret)


def test_eighty_column_prose_wrap_is_masked() -> None:
    secret = _token()
    prefix = ("Note. " * 8) + "export GH_TOKEN="
    body = prefix + secret + " before Friday."
    assert len(prefix) < 80 < len(prefix) + len(secret)
    hard = body[:80] + "\n" + body[80:]
    indented = body[:80] + "\n    " + body[80:]
    for text in (hard, indented):
        masked = _assert_masked(text, secret)
        assert "before" in masked
        assert "Friday" in masked


def test_tab_indented_continuation_is_masked() -> None:
    line = _assignment()
    secret = _token()
    wrapped = line[:20] + "\n\t" + line[20:]
    _assert_masked(wrapped, secret)


def test_following_words_are_not_glued_onto_the_token() -> None:
    secret = _token()
    line = _assignment(secret)
    for word in ("Thanks", "Notes"):
        whole = line + "\n" + word
        masked = _assert_masked(whole, secret)
        assert word in masked
        split = line[:22] + "\n" + line[22:] + "\n" + word
        masked = _assert_masked(split, secret)
        assert word in masked


def test_jwt_split_at_dots_is_masked() -> None:
    secret = _jwt()
    parts = secret.split(".")
    text = parts[0] + ".\n" + parts[1] + ".\n" + parts[2]
    _assert_masked(text, secret)
    assert secret not in mask_secrets.mask(secret + "\nThanks")
    assert "Thanks" in mask_secrets.mask(secret + "\nThanks")


def test_line_separator_between_every_character() -> None:
    secret = _token()
    text = _assignment("\u2028".join(secret))
    _assert_masked(text, secret)


def test_kept_indexes_match_the_joined_string() -> None:
    line = _assignment()
    samples = [
        line[:18] + "\n    " + line[18:],
        line[:21] + "\n\t" + line[21:] + "\nThanks",
        "aaaa.\nbbbb.\ncccc",
    ]
    for text in samples:
        joined = secret_surface.join_wrapped(text)
        kept = secret_surface._kept_unjoined_indexes(text)
        assert "".join(text[index] for index in kept) == joined


def test_join_doubling_stays_under_the_linear_bound() -> None:
    def once(count: int) -> float:
        started = time.process_time()
        secret_surface.join_wrapped(("Abcdefgh\n") * count)
        return time.process_time() - started

    once(2_000)
    ratios = []
    for _ in range(3):
        small = once(8_000)
        large = once(16_000)
        ratios.append(large / small if small > 0 else large)
    ratios.sort()
    assert ratios[1] < 2.6
