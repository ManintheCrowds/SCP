# PURPOSE: Locked leak classes and a benign false-positive ceiling.
# Tokens are built at runtime. Nothing here is a real credential.

from __future__ import annotations

import tracemalloc

import pytest

from scp import mask_secrets

_BENIGN_PER_TEMPLATE = 40
_BENIGN_FLAG_CEILING = 0
_TEMPLATES = (
    "Thanks for the note. Notes from meeting {n} stay in the folder.",
    "def total(left, right):\n    return left + right  # item {n}\n",
    (
        '<div class="et_pb_module et_pb_text et_pb_bg_layout_light">'
        '<div class="et_pb_text_inner"><p>Studio note {n}.</p></div></div>'
    ),
    "Write ada@\n    example.com about item {n}.",
    "# rebuild the static page for item {n}",
    '{{"title": "weekly update", "item": {n}}}',
    ".et_pb_text_inner {{ color: #333; margin: {n}px; }}",
    'The shelf is 27" wide and item {n} is on the left.',
    "select title, body from notes where item = {n}",
    "<p>Ordinary paragraph {n}. Nothing to hide.</p>",
    "Version 1.2.{n} shipped on 12 March. See the changelog.",
    '"Hello," she said, "item {n} is ready for review."',
)


def _token() -> str:
    return "gh" + "p_" + ("A" * 36)


def _jwt() -> str:
    return ("a" * 16) + "." + ("b" * 16) + "." + ("c" * 16)


def _assignment(token: str | None = None) -> str:
    return "export GH_TOKEN=" + (token if token is not None else _token())


def _cases() -> list[tuple[str, str, str]]:
    token = _token()
    line = _assignment(token)
    jwt = _jwt()
    parts = jwt.split(".")
    prefix = ("Note. " * 8) + "export GH_TOKEN="
    prose = prefix + token + " before Friday."
    samples = [
        ("prose-80", prose[:80] + "\n" + prose[80:], token),
        ("prose-80-indent", prose[:80] + "\n    " + prose[80:], token),
        ("tab-indent", line[:20] + "\n\t" + line[20:], token),
        ("jwt-dots", parts[0] + ".\n" + parts[1] + ".\n" + parts[2], jwt),
        ("per-char-separator", _assignment("\u2028".join(token)), token),
        ("filler-17b4", _assignment(token[:8] + "\u17b4" + token[8:]), token),
        ("filler-17b5", _assignment(token[:8] + "\u17b5" + token[8:]), token),
    ]
    for width in range(17, 24):
        samples.append((f"wrap-{width}", line[:width] + "\n" + line[width:], token))
    return samples


def test_more_than_seven_benign_templates() -> None:
    assert len(_TEMPLATES) > 7


@pytest.mark.parametrize(
    ("name", "text", "secret"),
    _cases(),
    ids=[case[0] for case in _cases()],
)
def test_leak_class_is_masked(name: str, text: str, secret: str) -> None:
    del name
    assert mask_secrets.has_secrets(text)
    masked = mask_secrets.mask(text)
    assert secret not in masked
    outbound = mask_secrets.prepare_outbound(text)
    assert secret not in outbound


def _benign_lines() -> list[str]:
    count = len(_TEMPLATES) * _BENIGN_PER_TEMPLATE
    return [_TEMPLATES[index % len(_TEMPLATES)].format(n=index) for index in range(count)]


def test_benign_flags_stay_under_the_ceiling() -> None:
    flagged = [line for line in _benign_lines() if mask_secrets.has_secrets(line)]
    assert len(flagged) <= _BENIGN_FLAG_CEILING


def test_prose_mask_trace_stays_under_the_old_map_cost() -> None:
    """A 250 KB prose sample must stay far below the old per-character map.

    Local measurement of this build: tracemalloc peaked at 9,448,809 bytes
    during mask() of 999,972 bytes of short prose lines (about 9.5 bytes of
    traced allocation per input byte) and 19,128,380 bytes for 1,999,991
    input bytes. Process RSS in a fresh interpreter was 41,464 KB and
    53,360 KB for those two sizes. The previous map-backed build peaked
    around 268 MB for 1 MB.
    """
    line = "Thanks for the note. Notes stay in the folder.\n"
    text = line * (250_000 // len(line))
    tracemalloc.start()
    mask_secrets.mask(text)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 20 * len(text)
