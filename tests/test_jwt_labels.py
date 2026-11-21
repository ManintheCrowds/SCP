# PURPOSE: Dot-split JWTs stay masked after labels, CRLF, and indentation.
# Signature segments cover a 4096-bit RSA token. Short segments require the
# JWT marker. Nothing here is a real credential.

from __future__ import annotations

import time

from scp import mask_secrets

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_LABELS = (
    "",
    "token: ",
    "token=",
    "Bearer ",
    "JWT=",
    "export JWT=",
    "id_token: ",
    "id_token=",
    "access_token: ",
    "Authorization: Bearer ",
)
# header, payload, signature, and whether the header carries the JWT marker.
_SHAPES = (
    (10, 10, 10, True),
    (12, 20, 16, True),
    (16, 16, 16, False),
    (24, 48, 32, True),
    (36, 180, 43, True),
    (20, 200, 512, True),
    (20, 200, 600, True),
    (20, 200, 683, True),
    (20, 80, 1024, True),
    (32, 500, 86, False),
    (18, 40, 40, True),
    (40, 90, 64, True),
    (22, 64, 22, True),
    (28, 256, 128, False),
)


def _segment(length: int, salt: int) -> str:
    chars: list[str] = []
    state = salt & 0xFFFFFFFF
    for index in range(length):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(_ALPHABET[state % len(_ALPHABET)])
    return "".join(chars)


def _header(length: int, salt: int, marked: bool) -> str:
    if not marked:
        return _segment(length, salt)
    marker = "".join(("ey", "J"))
    return marker + _segment(length - len(marker), salt)


def _parts(shape: tuple[int, int, int, bool]) -> tuple[str, str, str]:
    header_len, payload_len, signature_len, marked = shape
    return (
        _header(header_len, header_len + 3, marked),
        _segment(payload_len, payload_len + 5),
        _segment(signature_len, signature_len + 9),
    )


def _split(header: str, payload: str, signature: str, newline: str, indent: str) -> str:
    return header + "." + newline + indent + payload + "." + newline + indent + signature


def _segment_leaks(masked: str, parts: tuple[str, str, str]) -> bool:
    return any(len(part) >= 8 and part in masked for part in parts)


def test_labelled_dot_splits_do_not_leave_jwt_segments() -> None:
    assert "token: " in _LABELS
    assert "Bearer " in _LABELS
    assert "JWT=" in _LABELS
    assert "export JWT=" in _LABELS
    assert len(_LABELS) * 2 * 2 * len(_SHAPES) == 560
    leaked = 0
    total = 0
    for label in _LABELS:
        for carriage in (False, True):
            newline = "\r\n" if carriage else "\n"
            for indent in ("", "    "):
                for shape in _SHAPES:
                    header, payload, signature = _parts(shape)
                    text = label + _split(header, payload, signature, newline, indent)
                    masked = mask_secrets.mask(text)
                    total += 1
                    if _segment_leaks(masked, (header, payload, signature)):
                        leaked += 1
    assert total == 560
    assert leaked == 0


def test_long_signature_and_short_marker_match_on_one_line() -> None:
    header, payload, signature = _parts((20, 80, 1024, True))
    token = header + "." + payload + "." + signature
    assert signature not in mask_secrets.mask(token)
    short = _parts((10, 10, 10, True))
    short_token = ".".join(short)
    assert short[2] not in mask_secrets.mask(short_token)


def test_jwt_scan_stays_linear_without_two_dots() -> None:
    marker = "".join(("ey", "J"))
    text = marker + ("a" * 100_000)
    started = time.perf_counter()
    assert mask_secrets.has_secrets(text) is False
    assert time.perf_counter() - started < 1.0
