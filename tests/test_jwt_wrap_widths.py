# PURPOSE: Narrow JWT wraps are measured by one generator, and the doc quotes it.
# Segments are built at runtime. Nothing here is a real credential.

from __future__ import annotations

from pathlib import Path

from scp.mask_secrets import mask

_DOC = Path(__file__).resolve().parents[1] / "docs" / "SECRET_SCAN.md"
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_MARKER = "".join(("ey", "J"))
# 8 or more signature characters still visible, and the whole signature.
_EXPECTED = {
    4: (96, 65),
    5: (66, 59),
    6: (25, 19),
    7: (6, 6),
    8: (12, 9),
    9: (6, 6),
    10: (13, 13),
    11: (0, 0),
    12: (6, 6),
    13: (0, 0),
    14: (0, 0),
    15: (41, 41),
    16: (0, 0),
}


def _segment(length: int, salt: int) -> str:
    state = salt & 0xFFFFFFFF
    chars: list[str] = []
    for index in range(length):
        state = (state * 1664525 + 1013904223 + index) & 0xFFFFFFFF
        chars.append(_ALPHABET[state % len(_ALPHABET)])
    return "".join(chars)


def _wrap(token: str, width: int) -> str:
    return "\n".join(token[index : index + width] for index in range(0, len(token), width))


def _eight_visible(signature: str, text: str) -> bool:
    for index in range(len(signature) - 7):
        if signature[index : index + 8] in text:
            return True
    return False


def _measure() -> dict[int, tuple[int, int]]:
    found: dict[int, tuple[int, int]] = {}
    for width in range(4, 17):
        partial = 0
        whole = 0
        for sample in range(200):
            header = _MARKER + _segment(30, 1000 + sample)
            payload = _MARKER + _segment(40, 2000 + sample)
            signature = _segment(43, 3000 + sample)
            token = header + "." + payload + "." + signature
            visible = mask(_wrap(token, width))
            joined = "".join(visible.split())
            if _eight_visible(signature, visible) or _eight_visible(signature, joined):
                partial += 1
            if signature in joined:
                whole += 1
        found[width] = (partial, whole)
    return found


def test_narrow_wrap_counts_match_the_disclosure() -> None:
    measured = _measure()
    assert measured == _EXPECTED
    text = _DOC.read_text(encoding="utf-8")
    assert "tests/test_jwt_wrap_widths.py" in text
    for width, (partial, whole) in _EXPECTED.items():
        assert f"| {width} | {partial}/200 | {whole}/200 |" in text
    assert "Width 15 is 41/200" in text
