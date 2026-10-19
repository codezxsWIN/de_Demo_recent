"""Groq transport contract: bounded, explicit, and secret-safe."""

import json
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from vulnassess.errors import ConfigError, LLMUnavailable
from vulnassess.groq import ENDPOINT, MODEL, GroqClient


class Response:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, *_):
        return json.dumps({"choices": [{"message": {"content": '{"summary":"ok"}'}}]}).encode()


def test_groq_uses_bounded_structured_request():
    client = GroqClient(api_key="test-only")
    with patch("vulnassess.groq.urllib.request.urlopen", return_value=Response()) as send:
        assert client.generate_structured("case", {"type": "object"}) == {"summary": "ok"}
    request = send.call_args.args[0]
    body = json.loads(request.data)
    assert request.full_url == "https://api.groq.com/openai/v1/chat/completions"
    assert request.get_header("User-agent") == "VulnAssess/0.1"
    assert body["model"] == MODEL
    assert body["model"] == "openai/gpt-oss-120b"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["max_completion_tokens"] <= 3200
    assert "test-only" not in json.dumps(body)


def test_groq_rate_limit_does_not_echo_key():
    client = GroqClient(api_key="test-only")
    error = HTTPError(
        "https://api.groq.com/openai/v1/chat/completions", 429, "rate limit", {}, None
    )
    with patch("vulnassess.groq.urllib.request.urlopen", side_effect=error):
        with pytest.raises(LLMUnavailable, match="rate limit") as caught:
            client.generate_structured("case", {"type": "object"})
    assert "test-only" not in str(caught.value)


def test_invalid_request_schema_is_not_reported_as_provider_outage():
    body = json.dumps(
        {"error": {"message": "invalid JSON schema for response_format: PRIVATE"}}
    ).encode()
    error = HTTPError(ENDPOINT, 400, "bad request", {}, BytesIO(body))
    with patch("vulnassess.groq.urllib.request.urlopen", side_effect=error):
        with pytest.raises(ConfigError, match="request schema") as caught:
            GroqClient(api_key="test-only").generate_structured("case", {"type": "object"})
    assert "PRIVATE" not in str(caught.value)


def test_groq_allows_full_analyst_response_budget():
    client = GroqClient(api_key="test-only")
    with patch("vulnassess.groq.urllib.request.urlopen", return_value=Response()) as send:
        client.generate_structured("case", {"type": "object"}, num_predict=3200)
    assert json.loads(send.call_args.args[0].data)["max_completion_tokens"] == 3200


def test_groq_truncated_schema_error_is_specific_and_secret_safe():
    client = GroqClient(api_key="test-only")
    body = json.dumps(
        {
            "error": {
                "code": "json_validate_failed",
                "message": "max completion tokens reached before generating a valid document",
            }
        }
    ).encode()
    error = HTTPError(
        "https://api.groq.com/openai/v1/chat/completions",
        400,
        "bad request",
        {},
        BytesIO(body),
    )
    with patch("vulnassess.groq.urllib.request.urlopen", side_effect=error):
        with pytest.raises(LLMUnavailable, match="output token budget") as caught:
            client.generate_structured("case", {"type": "object"})
    assert "test-only" not in str(caught.value)


def test_groq_schema_validation_error_is_distinct_and_secret_safe():
    client = GroqClient(api_key="test-only")
    body = json.dumps(
        {"error": {"code": "json_validate_failed", "message": "bad output: PRIVATE BANNER"}}
    ).encode()
    error = HTTPError(ENDPOINT, 400, "bad request", {}, BytesIO(body))
    with patch("vulnassess.groq.urllib.request.urlopen", side_effect=error):
        with pytest.raises(LLMUnavailable, match="structured JSON validation") as caught:
            client.generate_structured("case", {"type": "object"})
    assert "PRIVATE BANNER" not in str(caught.value)


def test_secondary_groq_uses_separate_key_and_qwen_model(tmp_path, monkeypatch):
    from vulnassess.groq import GroqQwenClient

    (tmp_path / ".env.groq2").write_text("GROQ_SECONDARY_API_KEY=secondary-test-key\n")
    monkeypatch.setenv("GROQ_API_KEY", "original-test-key")
    monkeypatch.setattr("vulnassess.groq.SECONDARY_KEY_FILE", tmp_path / ".env.groq2")
    client = GroqQwenClient()
    with patch("vulnassess.groq.urllib.request.urlopen", return_value=Response()) as send:
        assert client.generate_structured("case", {"type": "object"}) == {"summary": "ok"}
    request = send.call_args.args[0]
    assert request.get_header("Authorization") == "Bearer secondary-test-key"
    assert json.loads(request.data)["model"] == "qwen/qwen3.8-27b"
    assert GroqClient(api_key="original-test-key").model == "openai/gpt-oss-120b"


def test_secondary_groq_never_falls_back_to_original_key(tmp_path, monkeypatch):
    from vulnassess.groq import GroqQwenClient

    monkeypatch.setenv("GROQ_API_KEY", "original-test-key")
    monkeypatch.delenv("GROQ_SECONDARY_API_KEY", raising=False)
    monkeypatch.setattr("vulnassess.groq.SECONDARY_KEY_FILE", tmp_path / ".env.groq2")
    with pytest.raises(LLMUnavailable, match="GROQ_SECONDARY_API_KEY"):
        GroqQwenClient().available()
