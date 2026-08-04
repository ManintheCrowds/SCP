# PURPOSE: Shared MagicMock HTTPS responses with streamed bodies (AppSec body-cap path).
from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock


def mock_json_response(data: Any, *, status: int = 200) -> MagicMock:
    """Response mock compatible with http_body.read_response_json (stream=True)."""
    raw = json.dumps(data).encode("utf-8")
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"Content-Length": str(len(raw))}
    resp.iter_content = lambda chunk_size=65536: iter([raw])
    resp.close = MagicMock()
    return resp
