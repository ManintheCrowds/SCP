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


def test_three_or_more_continuation_lines() -> None:
    secret = _token()
    text = "export GH_TOKEN=" + secret[:4] + "\n" + secret[4:8] + "\n" + secret[8:12] + "\n" + secret[12:]
    masked = _assert_masked(text, secret)
    followed = text + "\nThanks"
    assert "Thanks" in mask_secrets.mask(followed)
    assert secret not in masked


def test_label_split_across_an_eighty_column_wrap() -> None:
    secret = _token()
    filler = "Note. " * 12
    text = filler + "GH_TOK\nEN=" + secret
    assert len(filler + "GH_TOK") >= 72
    _assert_masked(text, secret)


def test_label_then_space_leaves_the_token_visible() -> None:
    secret = _token()
    bearer = "B" * 24
    samples = (
        ("token: \n" + secret, secret),
        ("key = \n" + secret, secret),
        ("Bearer \n" + bearer, bearer),
    )
    for text, hidden in samples:
        _assert_masked(text, hidden)


def test_one_to_seven_chars_after_a_spaced_label() -> None:
    secret = _token()
    for count in range(1, 8):
        for label in ("token: ", "key = "):
            text = label + secret[:count] + "\n" + secret[count:]
            _assert_masked(text, secret)


def test_jwt_split_inside_segments_two_and_three() -> None:
    secret = _jwt()
    text = secret[:25] + "\n" + secret[25:33] + "\n" + secret[33:42] + "\n" + secret[42:]
    _assert_masked(text, secret)


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
