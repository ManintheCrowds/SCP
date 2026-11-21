# PURPOSE: Realistic synthetic JWTs, including ones split on the dots.

from __future__ import annotations

from scp import mask_secrets

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _segment(length: int, salt: int) -> str:
    chars = []
    state = salt & 0xFFFFFFFF
    for index in range(length):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(_ALPHABET[state % len(_ALPHABET)])
    return "".join(chars)


def _jwt(header: int, payload: int, signature: int, salt: int) -> str:
    return ".".join(
        (
            _segment(header, salt),
            _segment(payload, salt + 1),
            _segment(signature, salt + 2),
        )
    )


def _split_on_dots(token: str) -> str:
    header, payload, signature = token.split(".")
    return header + ".\n" + payload + ".\n" + signature


_SHAPES = (
    (20, 20, 20, 3),
    (36, 48, 43, 4),
    (24, 180, 43, 5),
    (32, 500, 64, 6),
    (40, 720, 86, 7),
    (18, 90, 32, 8),
    (64, 256, 64, 9),
    (28, 1024, 43, 10),
    (22, 64, 22, 11),
    (48, 400, 128, 12),
)


def test_realistic_jwts_are_masked_bare_and_in_json() -> None:
    for shape in _SHAPES:
        token = _jwt(*shape)
        assert mask_secrets.has_secrets(token)
        assert token not in mask_secrets.mask(token)
        wrapped = '{"id_token":"' + token + '"}'
        assert mask_secrets.has_secrets(wrapped)
        assert token not in mask_secrets.mask(wrapped)
        outbound = mask_secrets.prepare_outbound(wrapped)
        assert token not in outbound


def test_dot_splits_of_realistic_jwts_are_masked() -> None:
    leaked = 0
    for shape in _SHAPES:
        token = _jwt(*shape)
        bare = _split_on_dots(token)
        labelled = "id_token: " + _split_on_dots(token)
        for text in (bare, labelled):
            masked = mask_secrets.mask(text)
            if token in masked or not mask_secrets.has_secrets(text):
                leaked += 1
            assert token not in masked
            assert token not in mask_secrets.prepare_outbound(text)
    assert leaked == 0
