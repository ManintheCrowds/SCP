# PURPOSE: A token that straddles the encounter-log cap is masked before the cut.

from __future__ import annotations

from scp import encounter_auto_log


def test_token_split_by_the_log_cap_is_masked() -> None:
    token = "gh" + "p_" + ("C" * 36)
    # A space keeps the token detectable. The cap still cuts it when applied first.
    prefix = ("n" * (encounter_auto_log._LOG_MASK_CAP - len("[REDACTED]") - 1)) + " "
    logged = encounter_auto_log._sanitize_for_log(prefix + token, "reversal")
    masked = "[REDACTED]" in logged and ("gh" + "p_") not in logged
    assert masked
