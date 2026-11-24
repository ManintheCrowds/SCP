# PURPOSE: A known prefix starts a new token, and a short word after a wrap
# is not glued onto the secret.

from __future__ import annotations

from scp import mask_secrets

_WORDS = (
    "ok",
    "to",
    "be",
    "if",
    "or",
    "an",
    "at",
    "on",
    "in",
    "of",
    "is",
    "it",
    "we",
    "my",
    "up",
    "no",
    "so",
    "do",
    "go",
    "us",
    "am",
    "as",
)


def _personal() -> str:
    return "".join(("gh", "p_")) + ("A" * 36)


def _oauth() -> str:
    return "".join(("gh", "o_")) + ("B" * 36)


def _access() -> str:
    return "".join(("AK", "IA")) + ("F" * 16)


def _lab() -> str:
    return "".join(("sk", "-")) + ("C" * 20)


def _fine() -> str:
    return "".join(("github", "_pat_")) + ("D" * 22)


def _wrapped(secret: str, width: int) -> str:
    return "\n".join(secret[index : index + width] for index in range(0, len(secret), width))


def _longest(secret: str, text: str) -> int:
    best = 0
    for line in text.splitlines():
        for start in range(len(secret)):
            if secret[start] not in line:
                continue
            end = start + best
            while end < len(secret) and secret[start : end + 1] in line:
                end += 1
            best = max(best, end - start)
    return best


def _leak8(secret: str, text: str) -> bool:
    return _longest(secret, mask_secrets.mask(text)) >= 8


def test_a_word_after_a_wrapped_token_does_not_leak() -> None:
    assert len(_WORDS) == 22
    personal = _personal()
    access = _access()
    personal_leaks = 0
    personal_total = 0
    for width in range(1, len(personal) + 1):
        for word in _WORDS:
            personal_total += 1
            if _leak8(personal, _wrapped(personal, width) + "\n" + word):
                personal_leaks += 1
    access_leaks = 0
    access_total = 0
    for width in range(1, len(access) + 1):
        for carriage in ("\n", "\r\n"):
            for word in _WORDS:
                access_total += 1
                text = _wrapped(access, width).replace("\n", carriage) + carriage + word
                if _leak8(access, text):
                    access_leaks += 1
    assert personal_total == 880
    assert access_total == 880
    assert personal_leaks == 0
    assert access_leaks == 0


def test_a_word_line_does_not_glue_onto_a_new_token() -> None:
    cases = (
        ("ok", _personal()),
        ("to", _oauth()),
        ("be", _access()),
        ("if", _lab()),
    )
    kept = 0
    for word, secret in cases:
        text = word + "\n" + secret[:8] + "\n" + secret[8:]
        masked = mask_secrets.mask(text)
        if _longest(secret, masked) < 8 and word in masked:
            kept += 1
    assert len(cases) == 4
    assert kept == 4


def test_short_prefix_pieces_still_join() -> None:
    secret = _fine()
    pieces = ("gi", "th", "ub", "_p")
    rest = secret[len("".join(pieces)) :]
    text = "\n".join((*pieces, rest))
    masked = mask_secrets.mask(text)
    assert _longest(secret, masked) < 8
    prose = "Thanks\n" + _wrapped(secret, 4)
    masked = mask_secrets.mask(prose)
    assert "Thanks" in masked
    assert _longest(secret, masked) < 8
