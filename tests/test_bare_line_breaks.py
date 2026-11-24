# PURPOSE: A bare token broken across short lines is masked, not glued to prose.

from __future__ import annotations

from scp import mask_secrets


def _cat(*parts: str) -> str:
    return "".join(parts)


def _families() -> dict[str, str]:
    return {
        "personal": _cat("gh", "p_") + ("A" * 36),
        "oauth": _cat("gh", "o_") + ("B" * 36),
        "fine": _cat("github", "_pat_") + ("C" * 22),
        "lab": _cat("gl", "pat-") + ("D" * 20),
        "project": _cat("sk-", "proj-") + ("E" * 20),
        "access": _cat("AK", "IA") + ("F" * 16),
        "slack": _cat("xo", "xb-") + ("1" * 10) + "-" + ("A" * 16),
    }


def _wrapped(secret: str, width: int) -> str:
    return "\n".join(secret[index : index + width] for index in range(0, len(secret), width))


def test_short_line_breaks_do_not_leak_bare_tokens() -> None:
    leaked = 0
    total = 0
    for secret in _families().values():
        for width in range(1, len(secret)):
            total += 1
            text = _wrapped(secret, width)
            masked = mask_secrets.mask(text)
            if secret in masked or not mask_secrets.has_secrets(text):
                leaked += 1
    assert total == 212
    assert leaked == 0


def test_a_following_word_is_not_glued_to_a_bare_token() -> None:
    secret = _families()["personal"]
    text = secret + "\nThanks"
    masked = mask_secrets.mask(text)
    assert secret not in masked
    assert "Thanks" in masked
    split = _wrapped(secret, 4) + "\nNotes"
    masked = mask_secrets.mask(split)
    assert secret not in masked
    assert "Notes" in masked
