# PURPOSE: promptfoo Python provider — runs SCP inspect() with no LLM calls.
# USAGE: From repo root: pip install -e . then promptfoo eval (cwd = this directory).

from __future__ import annotations

import json
from typing import Any

from scp.scp_utils import inspect


def call_api(prompt: str, options: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Return SCP classification as JSON string in output for assertions."""
    result = inspect(prompt)
    return {"output": json.dumps(result, ensure_ascii=False)}
