# PURPOSE: Semantic judge URL validation and no-network path for bad OLLAMA_BASE_URL.

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch

from scp.scp_semantic_judge import judge


class TestSemanticJudgeOllamaUrl(unittest.TestCase):
    def test_invalid_url_skips_network(self) -> None:
        long_content = "x" * 600
        with patch.dict(os.environ, {"OLLAMA_BASE_URL": "http://evil.example:11434"}):
            with patch("scp.scp_semantic_judge.requests.post") as m_post:
                out = judge(long_content, "handoff")
        m_post.assert_not_called()
        self.assertFalse(out["suspicious"])
        self.assertIn("invalid OLLAMA_BASE_URL", out["reason"])

    @patch("scp.scp_semantic_judge.requests.post")
    def test_redirect_fail_open(self, m_post: MagicMock) -> None:
        long_content = "y" * 600
        resp = MagicMock()
        resp.status_code = 302
        m_post.return_value = resp
        with patch.dict(os.environ, {"OLLAMA_BASE_URL": "http://127.0.0.1:11434"}, clear=False):
            out = judge(long_content, "handoff")
        self.assertFalse(out["suspicious"])
        self.assertIn("redirect", out["reason"].lower())
        m_post.assert_called_once()
        _, kwargs = m_post.call_args
        self.assertIs(kwargs.get("allow_redirects"), False)


if __name__ == "__main__":
    unittest.main()
