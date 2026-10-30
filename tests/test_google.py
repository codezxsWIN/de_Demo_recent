"""Gemini analyst transport keeps the key server-side and output bounded."""

import json
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from vulnassess.errors import LLMUnavailable, ProviderUnavailable
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


def test_google_recovers_from_transient_503():
    error = HTTPError("https://example.invalid", 503, "unavailable", {}, None)
    client = GeminiClient(api_key="test-only")
    with patch("vulnassess.google.urllib.request.urlopen", side_effect=[error, Response()]) as send, \
         patch("vulnassess.google.time.sleep") as sleep:
        assert client.generate_structured("case", {}) == {"summary": "ok"}
    assert send.call_count == 2
    assert "gemini-3.5-flash-lite:" in send.call_args_list[0].args[0].full_url
    assert "gemini-3.1-flash-lite:" in send.call_args_list[1].args[0].full_url
    assert client.model == "gemini-3.1-flash-lite"
    assert client.source == "google_gemini_3_1_flash_lite_grounded_analysis"
    sleep.assert_called_once_with(1)


def test_google_model_recovery_is_bounded_and_retains_request_schema():
    error = HTTPError("https://example.invalid", 503, "unavailable", {}, None)
    with patch("vulnassess.google.urllib.request.urlopen", side_effect=error) as send, \
         patch("vulnassess.google.time.sleep"):
        with pytest.raises(ProviderUnavailable, match="HTTP 503"):
            GeminiClient(api_key="test-only").generate_structured("original evidence", {"type": "object"})
    assert send.call_count == 3
    bodies = [json.loads(call.args[0].data) for call in send.call_args_list]
    assert all(body == bodies[0] for body in bodies)


def test_google_does_not_retry_rate_limits():
    error = HTTPError("https://example.invalid", 429, "rate limit", {}, None)
    with patch("vulnassess.google.urllib.request.urlopen", side_effect=error) as send:
        with pytest.raises(ProviderUnavailable, match="rate limit"):
            GeminiClient(api_key="test-only").generate_structured("case", {})
    assert send.call_count == 1
