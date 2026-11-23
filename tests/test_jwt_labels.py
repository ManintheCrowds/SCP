# PURPOSE: Dot-split JWTs stay masked after labels, CRLF, and indentation.
# Signature segments cover a 4096-bit RSA token. Short segments require the
# JWT marker. Nothing here is a real credential.

from __future__ import annotations

import time

from scp import encounter_auto_log, mask_secrets, secret_surface

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


def _signature_visible(text: str, signature: str) -> bool:
    masked = mask_secrets.mask(text)
    try:
        outbound = mask_secrets.prepare_outbound(text)
    except mask_secrets.EgressMaskError:
        outbound = ""
    logged = encounter_auto_log._sanitize_for_log(text, "reversal")
    return signature in masked or signature in outbound or signature in logged


def test_indented_trailing_space_and_bearer_dot_splits_hide_the_signature() -> None:
    header, payload, signature = _parts((36, 48, 43, True))
    shapes = (
        "  " + header + ".\n" + payload + ".\n" + signature,
        "token: " + header + ". \n" + payload + ". \n" + signature,
        "Authorization: Bearer " + header + "\n." + payload + "\n." + signature,
        "Here is the header.\n  " + header + ".\n  " + payload + ".\n  " + signature,
    )
    visible = sum(1 for text in shapes if _signature_visible(text, signature))
    assert visible == 0


def _lower_segment(length: int, salt: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    state = salt & 0xFFFFFFFF
    chars: list[str] = []
    for index in range(length):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(alphabet[state % len(alphabet)])
    return "".join(chars)


def test_narrow_wrapped_bare_jwts_stay_under_the_old_leak_count() -> None:
    leaked = 0
    total = 0
    marker = "".join(("ey", "J"))
    for width in (4, 8):
        for salt in range(220):
            mixed = (
                _header(36, salt + 10, True),
                _segment(80, salt + 20),
                _segment(43, salt + 30),
            )
            lower = (
                marker + _lower_segment(33, salt + 1),
                _lower_segment(40, salt + 2),
                _lower_segment(43, salt + 3),
            )
            for header, payload, signature in (mixed, lower):
                token = header + "." + payload + "." + signature
                text = "\n".join(
                    token[index : index + width] for index in range(0, len(token), width)
                )
                total += 1
                masked = mask_secrets.mask(text)
                if any(token[index : index + 8] in masked for index in range(0, len(token) - 7)):
                    leaked += 1
    assert total == 880
    assert leaked <= 80


def test_punctuation_prefixes_do_not_emit_the_signature() -> None:
    header, payload, signature = _parts((36, 48, 43, True))
    prefixes = (
        "- ",
        '"',
        "'",
        "# ",
        "// ",
        "(",
        "[",
        "> ",
        "`",
        'token="',
    )
    leaked = 0
    total = 0
    for prefix in prefixes:
        shapes = (
            prefix + header + ".\n" + payload + ".\n" + signature,
            prefix + header + "\n." + payload + "\n." + signature,
            prefix + header + "." + payload + ".\n" + signature,
        )
        for text in shapes:
            total += 1
            if _signature_visible(text, signature):
                leaked += 1
    yaml_list = "- " + header + ".\n  " + payload + ".\n  " + signature
    json_string = '{"id_token":"' + header + ".\n" + payload + ".\n" + signature
    bullet = "* " + header + ".\n" + payload + ".\n" + signature
    for text in (yaml_list, json_string, bullet):
        total += 1
        if _signature_visible(text, signature):
            leaked += 1
    assert total == 33
    assert leaked == 0


def test_list_table_and_punctuation_prefixes_do_not_emit_the_signature() -> None:
    header, payload, signature = _parts((36, 48, 43, True))
    prefixes = (
        "1. ",
        "2) ",
        "| ",
        "; ",
        "~ ",
        "! ",
        "@ ",
        "$ ",
        "% ",
        "& ",
        "+ ",
        ", ",
        "\\ ",
        "12. ",
    )
    leaked = 0
    total = 0
    for prefix in prefixes:
        shapes = (
            prefix + header + ".\n" + payload + ".\n" + signature,
            prefix + header + "\n." + payload + "\n." + signature,
            prefix + header + "." + payload + ".\n" + signature,
        )
        for text in shapes:
            total += 1
            if _signature_visible(text, signature):
                leaked += 1
    assert total == 42
    assert leaked == 0


def test_a_known_prefix_inside_an_open_jwt_still_joins() -> None:
    header = "".join(("ey", "J")) + ("A" * 20)
    payload = "".join(("gh", "p_")) + ("B" * 16)
    signature = "C" * 24
    text = header + ".\n" + payload + ".\n" + signature
    assert signature not in mask_secrets.mask(text)


def test_a_fragment_word_stays_off_an_open_jwt() -> None:
    header = "".join(("ey", "J")) + ("A" * 20)
    text = header + ".\n" + "before"
    _unjoined, joined = secret_surface.detection_views(text)
    assert "\nbefore" in joined
    assert not joined.endswith(".before")


def test_a_word_line_after_a_jwt_survives() -> None:
    header, payload, signature = _parts((36, 80, 43, True))
    words = ("about", "other", "which", "would", "could", "their", "where", "while")
    glued = 0
    for word in words:
        text = header + ".\n" + payload + ".\n" + signature + "\n" + word
        masked = mask_secrets.mask(text)
        if word not in masked or signature in masked:
            glued += 1
    assert glued == 0


def test_bearer_without_the_marker_still_joins_a_leading_dot() -> None:
    header, payload, signature = _parts((16, 16, 16, False))
    header = "Q" + header[1:]
    visible = 0
    for label in ("Bearer ", "Authorization: Bearer "):
        text = label + header + "\n." + payload + "\n." + signature
        if _signature_visible(text, signature):
            visible += 1
    assert visible == 0


def test_a_word_after_a_one_line_jwt_survives() -> None:
    header, payload, signature = _parts((36, 80, 43, True))
    words = (
        "about", "other", "which", "their", "there", "would", "could", "should",
        "these", "those", "where", "while", "after", "before", "under", "again",
        "being", "every", "first", "found", "great", "house", "large", "never",
        "place", "small", "still", "water",
    )
    glued = 0
    for word in words:
        shapes = (
            header + "." + payload + "." + signature + "\n" + word,
            header + "." + payload + "." + signature + " \n" + word,
            "  " + header + "." + payload + "." + signature + "\n" + word,
        )
        for text in shapes:
            masked = mask_secrets.mask(text)
            if word not in masked or signature in masked:
                glued += 1
    assert glued == 0


def test_jwt_scan_stays_linear_without_two_dots() -> None:
    marker = "".join(("ey", "J"))
    text = marker + ("a" * 100_000)
    started = time.perf_counter()
    assert mask_secrets.has_secrets(text) is False
    assert time.perf_counter() - started < 1.0
