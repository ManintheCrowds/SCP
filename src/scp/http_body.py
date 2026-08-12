# PURPOSE: Bounded HTTPS response body reads — fail closed before JSON parse (memory DoS).
# DEPENDENCIES: requests
# MODIFICATION NOTES: AppSec 2026-08-03 — stream with hard byte cap; distinct size vs transport errors

from __future__ import annotations

import json
from typing import Any

import requests

_CHUNK = 65536


class ResponseTooLargeError(ValueError):
    """Raised when a response body exceeds the configured byte cap."""

    def __init__(self, reason: str = "response_too_large") -> None:
        super().__init__(reason)
        self.reason = reason


class ResponseReadError(ValueError):
    """Raised when streaming the body fails for a non-size reason (e.g. transport)."""

    def __init__(self, reason: str = "fetch_failed") -> None:
        super().__init__(reason)
        self.reason = reason


def assert_content_within_cap(content: str | bytes, max_bytes: int) -> None:
    """Fail closed if UTF-8 / raw byte length exceeds ``max_bytes``."""
    if max_bytes < 1:
        raise ResponseTooLargeError("response_too_large")
    raw = content.encode("utf-8") if isinstance(content, str) else content
    if len(raw) > max_bytes:
        raise ResponseTooLargeError("response_too_large")


def read_response_bytes(resp: requests.Response, max_bytes: int) -> bytes:
    """Read at most ``max_bytes`` from a (preferably streamed) response; fail closed on overrun.

    Checks Content-Length when present, then streams via iter_content. Does not call resp.json().
    Raises ResponseTooLargeError on size overrun; ResponseReadError on transport failure.
    """
    if max_bytes < 1:
        raise ResponseTooLargeError("response_too_large")

    cl = resp.headers.get("Content-Length")
    if cl is not None:
        try:
            declared = int(cl)
        except ValueError:
            declared = -1
        if declared > max_bytes:
            resp.close()
            raise ResponseTooLargeError("response_too_large")

    buf = bytearray()
    try:
        for chunk in resp.iter_content(chunk_size=_CHUNK):
            if not chunk:
                continue
            if len(buf) + len(chunk) > max_bytes:
                resp.close()
                raise ResponseTooLargeError("response_too_large")
            buf.extend(chunk)
    except ResponseTooLargeError:
        raise
    except requests.RequestException as exc:
        resp.close()
        raise ResponseReadError("fetch_failed") from exc
    return bytes(buf)


def read_response_json(resp: requests.Response, max_bytes: int) -> Any:
    """Bounded body read then json.loads.

    Raises ResponseTooLargeError, ResponseReadError, or json.JSONDecodeError.
    """
    raw = read_response_bytes(resp, max_bytes)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise json.JSONDecodeError("invalid UTF-8", "", 0) from exc
    return json.loads(text)
