# PURPOSE: Semantic judge URL validation and no-network path for bad OLLAMA_BASE_URL.

from __future__ import annotations

import os
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from unittest.mock import MagicMock, patch

from scp.scp_semantic_judge import _post_ollama, judge


class _ProxyCaptureHandler(BaseHTTPRequestHandler):
    requests_seen: int = 0

    def do_POST(self) -> None:
        type(self).requests_seen += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"response": "NO proxy captured request"}')

    def log_message(self, format: str, *args: object) -> None:
        return


class _FakeSession:
    def __init__(self, response: MagicMock) -> None:
        self.response = response
        self.trust_env = True
        self.post_kwargs: dict | None = None

    def __enter__(self) -> "_FakeSession":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def post(self, endpoint: str, **kwargs: object) -> MagicMock:
        self.post_kwargs = kwargs
        return self.response


class TestSemanticJudgeOllamaUrl(unittest.TestCase):
    def test_invalid_url_skips_network(self) -> None:
        long_content = "x" * 600
        with patch.dict(os.environ, {"OLLAMA_BASE_URL": "http://evil.example:11434"}):
            with patch("scp.scp_semantic_judge._post_ollama") as m_post:
                out = judge(long_content, "handoff")
        m_post.assert_not_called()
        self.assertFalse(out["suspicious"])
        self.assertIn("invalid OLLAMA_BASE_URL", out["reason"])

    @patch("scp.scp_semantic_judge._post_ollama")
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

    def test_ollama_post_disables_redirects_and_proxy_environment(self) -> None:
        resp = MagicMock()
        fake_session = _FakeSession(resp)
        with patch("scp.scp_semantic_judge.requests.Session", return_value=fake_session):
            out = _post_ollama(
                "http://127.0.0.1:11434/api/generate",
                {"model": "m", "prompt": "p", "stream": False},
                {"Content-Type": "application/json"},
            )

        self.assertIs(out, resp)
        self.assertFalse(fake_session.trust_env)
        self.assertIsNotNone(fake_session.post_kwargs)
        self.assertIs(fake_session.post_kwargs["allow_redirects"], False)

    def test_ambient_proxy_is_not_used_for_ollama_requests(self) -> None:
        _ProxyCaptureHandler.requests_seen = 0
        proxy = HTTPServer(("127.0.0.1", 0), _ProxyCaptureHandler)
        thread = Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        proxy_url = f"http://127.0.0.1:{proxy.server_port}"
        env = {
            "OLLAMA_BASE_URL": "http://127.0.0.1:9",
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "NO_PROXY": "",
            "no_proxy": "",
            "OLLAMA_API_KEY": "secret-token",
        }
        try:
            with patch.dict(os.environ, env, clear=False):
                out = judge("clean content" * 50, "handoff")
        finally:
            proxy.shutdown()
            proxy.server_close()
            thread.join(timeout=2)

        self.assertFalse(out["suspicious"])
        self.assertEqual(_ProxyCaptureHandler.requests_seen, 0)


if __name__ == "__main__":
    unittest.main()
