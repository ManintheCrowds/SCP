# PURPOSE: The match scan and the normalizer stay linear, and over-cap input fails closed.

from __future__ import annotations

import time

import pytest

from scp import encounter_auto_log, mask_secrets, secret_surface

_RATIO_LIMIT = 2.6


def _ratio(fn, size: int) -> float:
    def once(count: int) -> float:
        started = time.process_time()
        fn(count)
        return time.process_time() - started

    fn(max(size // 8, 1))
    samples = []
    for _ in range(3):
        small = once(size)
        large = once(size * 2)
        samples.append(large / small if small > 0 else large)
    samples.sort()
    return samples[1]


def _pwd_text(count: int) -> str:
    return "pwd=x " * count


def test_match_scan_doubling_beats_superlinear() -> None:
    def run(count: int) -> None:
        mask_secrets.credential_spans(_pwd_text(count))

    assert _ratio(run, 12_000) < _RATIO_LIMIT


def test_has_secrets_doubling_beats_superlinear() -> None:
    def run(count: int) -> None:
        mask_secrets.has_secrets(_pwd_text(count))

    assert _ratio(run, 12_000) < _RATIO_LIMIT


def test_normalization_doubling_beats_superlinear() -> None:
    def run(count: int) -> None:
        secret_surface.detection_views(("Abcdef\n") * count)

    assert _ratio(run, 8_000) < _RATIO_LIMIT


def test_doubling_limit_rejects_an_n_to_the_1_5_loop() -> None:
    def run(count: int) -> None:
        total = 0
        for _ in range(int(count**1.5)):
            total += 1
        if total < 0:
            raise RuntimeError(total)

    assert _ratio(run, 4_000) > _RATIO_LIMIT


def test_control_heavy_input_stays_under_two_seconds() -> None:
    samples = (
        "\x9b" * 1_000_000,
        "\x1b[12" * (1_000_000 // 4),
        "a\x07" * 500_000,
    )
    for text in samples:
        assert len(text) >= 999_996
        started = time.process_time()
        mask_secrets.mask(text)
        elapsed = time.process_time() - started
        assert elapsed < 2.0


def test_over_cap_fails_closed() -> None:
    text = "x" * (mask_secrets.MAX_SCAN_CHARS + 1)
    assert mask_secrets.mask(text) == "[REDACTED]"
    assert mask_secrets.has_secrets(text) is True
    with pytest.raises(mask_secrets.EgressMaskError):
        mask_secrets.prepare_outbound(text)


def test_encounter_log_truncates_before_masking(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []
    real_mask = mask_secrets.mask

    def spy(text: str) -> str:
        seen.append(len(text))
        return real_mask(text)

    monkeypatch.setattr(encounter_auto_log.mask_secrets, "mask", spy)
    monkeypatch.setenv("SCP_ENCOUNTER_AUTO_LOG", "1")
    monkeypatch.setenv("ENCOUNTER_BESTIARY_DIR", str(tmp_path / "docs" / "encounter_bestiary"))
    (tmp_path / "docs" / "encounter_bestiary").mkdir(parents=True)
    head = "pwd=zzzz "
    tail = "TAILMARKER"
    body = head + ("n" * (encounter_auto_log._LOG_MASK_CHARS + 50)) + tail
    meta = encounter_auto_log.maybe_log_encounter(body, "reversal")
    assert meta is not None
    assert seen and seen[0] <= (
        encounter_auto_log._LOG_MASK_CHARS + encounter_auto_log._LOG_TOKEN_EXTEND
    )
    logged = list((tmp_path / "docs" / "encounter_bestiary").glob("*_encounters.md"))[0].read_text(
        encoding="utf-8"
    )
    assert "pwd=zzzz" not in logged
    assert tail not in logged


def test_token_straddling_the_log_boundary_is_not_stored(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    token = "".join(("gh", "p_")) + ("A" * 36)
    assert len(token) == 40
    monkeypatch.setenv("SCP_ENCOUNTER_AUTO_LOG", "1")
    monkeypatch.setenv("ENCOUNTER_BESTIARY_DIR", str(tmp_path / "docs" / "encounter_bestiary"))
    (tmp_path / "docs" / "encounter_bestiary").mkdir(parents=True)
    # 35 token characters sit inside the 4,000-character cut and 5 sit past it.
    start = encounter_auto_log._LOG_MASK_CHARS - 35
    head = ("n" * (start - 1)) + " "
    body = head + token + " tail"
    assert body[start : start + len(token)] == token
    meta = encounter_auto_log.maybe_log_encounter(body, "reversal")
    assert meta is not None
    logged = list((tmp_path / "docs" / "encounter_bestiary").glob("*_encounters.md"))[0].read_text(
        encoding="utf-8"
    )
    assert token not in logged
    assert token[:35] not in logged
    assert token[35:] not in logged
