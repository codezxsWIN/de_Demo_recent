"""Gemini analyst transport keeps the key server-side and output bounded."""

import json
from unittest.mock import patch

import pytest

from vulnassess.errors import LLMUnavailable
from vulnassess.google import GeminiClient


class Response:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, *_):
        return json.dumps(
            {"candidates": [{"content": {"parts": [{"text": '{"summary":"ok"}'}]}}]}
        ).encode()


def test_google_uses_structured_request_without_exposing_key():
    client = GeminiClient(api_key="test-only")
    with patch("vulnassess.google.urllib.request.urlopen", return_value=Response()) as send:
        assert client.generate_structured("case", {"type": "object"}) == {"summary": "ok"}
    request = send.call_args.args[0]
    body = json.loads(request.data)
    assert request.get_header("X-goog-api-key") == "test-only"
    assert "gemini-3.5-flash-lite:generateContent" in request.full_url
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert body["generationConfig"]["responseJsonSchema"] == {"type": "object"}
    assert "test-only" not in json.dumps(body)


def test_google_rejects_empty_candidate():
    class EmptyResponse(Response):
        def read(self, *_):
            return b'{"candidates":[]}'

    with patch("vulnassess.google.urllib.request.urlopen", return_value=EmptyResponse()):
        with pytest.raises(LLMUnavailable, match="structured response"):
            GeminiClient(api_key="test-only").generate_structured("case", {"type": "object"})
