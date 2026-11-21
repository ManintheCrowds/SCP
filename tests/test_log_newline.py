# PURPOSE: A newline at the log cut does not drop the rest of a token.

from __future__ import annotations

from scp import encounter_auto_log, mask_secrets


def _token() -> str:
    return "".join(("gh", "p_")) + ("A" * 36)


def _leaks(token: str, logged: str) -> bool:
    for index in range(len(token) - 7):
        if token[index : index + 8] in logged:
            return True
    return False


def _body(token: str, start: int, split: int, newline: str, indent: str) -> str:
    pad = ("n" * (start - 1) + " ") if start else ""
    return pad + token[:split] + newline + indent + token[split:] + " end"


def test_newline_at_the_cut_does_not_keep_a_token_fragment(tmp_path, monkeypatch) -> None:
    token = _token()
    limit = encounter_auto_log._LOG_MASK_CHARS
    monkeypatch.setenv("SCP_ENCOUNTER_AUTO_LOG", "1")
    monkeypatch.setenv("ENCOUNTER_BESTIARY_DIR", str(tmp_path / "docs" / "encounter_bestiary"))
    (tmp_path / "docs" / "encounter_bestiary").mkdir(parents=True)
    body = _body(token, limit - 20, 20, "\n", "")
    assert body[limit] == "\n"
    meta = encounter_auto_log.maybe_log_encounter(body, "reversal")
    assert meta is not None
    logged = list((tmp_path / "docs" / "encounter_bestiary").glob("*_encounters.md"))[0].read_text(
        encoding="utf-8"
    )
    leaked = _leaks(token, logged)
    assert leaked is False
    prose = ("n" * limit) + "\nThanks for the note"
    logged_prose = mask_secrets.mask(encounter_auto_log._prefix_for_mask(prose))
    assert "Thanks" not in logged_prose


def test_boundary_positions_do_not_leak_eight_characters() -> None:
    token = _token()
    limit = encounter_auto_log._LOG_MASK_CHARS
    span = len(token) - 1
    total = 20_772
    leaked = 0
    for number in range(total):
        split = (number % span) + 1
        slot = number // span
        start = limit - split + (slot - 266)
        if start < 0:
            start = 0
        indent = "  " if number % 2 == 0 else ""
        newline = "\r\n" if number % 5 == 0 else "\n"
        logged = mask_secrets.mask(
            encounter_auto_log._prefix_for_mask(_body(token, start, split, newline, indent))
        )
        if _leaks(token, logged):
            leaked += 1
    assert total == 20_772
    assert leaked == 0
