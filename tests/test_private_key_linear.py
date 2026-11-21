# PURPOSE: Private-key blocks are linear, including a missing END line.

from __future__ import annotations

import time

from scp import mask_secrets

_KINDS = (
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "EC PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
)


def _block(kind: str, body: str, *, close: bool) -> str:
    text = "-----BEGIN " + kind + "-----\n" + body
    if close:
        text += "\n-----END " + kind + "-----"
    return text


def test_each_private_key_header_is_masked() -> None:
    body = "A" * 40
    for kind in _KINDS:
        for close in (True, False):
            text = "note\n" + _block(kind, body, close=close) + "\n"
            assert mask_secrets.has_secrets(text), kind
            masked = mask_secrets.mask(text)
            assert body not in masked
            assert "BEGIN " + kind not in masked
            outbound = mask_secrets.prepare_outbound(text)
            assert body not in outbound


def test_missing_end_near_the_cap_is_fast() -> None:
    filler = "B" * (mask_secrets.MAX_SCAN_CHARS - 80)
    text = "-----BEGIN PRIVATE KEY-----\n" + filler
    assert len(text) <= mask_secrets.MAX_SCAN_CHARS
    started = time.process_time()
    assert mask_secrets.has_secrets(text)
    has_elapsed = time.process_time() - started
    started = time.process_time()
    outbound = mask_secrets.prepare_outbound(text)
    egress_elapsed = time.process_time() - started
    assert filler not in outbound
    assert has_elapsed < 2.0
    assert egress_elapsed < 2.0
