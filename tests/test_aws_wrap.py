# PURPOSE: An assignment value that wraps through '/' or '+' stays masked.

from __future__ import annotations

from scp import mask_secrets


def _chunk(length: int, salt: int, mark: str) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    state = salt & 0xFFFFFFFF
    chars: list[str] = []
    for index in range(length):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(alphabet[state % len(alphabet)])
    if length:
        chars[salt % length] = mark
    return "".join(chars)


def _leaks(text: str, second: str) -> bool:
    masked = mask_secrets.mask(text)
    try:
        outbound = mask_secrets.prepare_outbound(text)
    except mask_secrets.EgressMaskError:
        outbound = ""
    return second in masked or second in outbound


def test_slash_at_the_split_does_not_leave_the_second_half() -> None:
    first = _chunk(20, 4, "/")
    second = _chunk(20, 8, "A")
    leaked = 0
    for label in ("AWS_SECRET_ACCESS_KEY=", "SecretAccessKey:"):
        text = label + first + "\n" + second
        if _leaks(text, second):
            leaked += 1
    assert leaked == 0


def test_random_slash_and_plus_splits_stay_masked() -> None:
    leaked = 0
    total = 0
    for salt in range(40):
        for mark in ("/", "+"):
            first = _chunk(20, salt, mark)
            second = _chunk(20, salt + 50, mark)
            text = "AWS_SECRET_ACCESS_KEY=" + first + "\n" + second
            total += 1
            if _leaks(text, second):
                leaked += 1
    assert total == 80
    assert leaked == 0
