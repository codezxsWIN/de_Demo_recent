"""Exercise provider boundaries offline, without reading workstation credentials."""

import io
import json
from pathlib import Path
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest

from vulnassess import google, groq, openrouter
from vulnassess.ai_boundary import SYSTEM_BOUNDARY_PROMPT
from vulnassess.errors import ConfigError, LLMUnavailable, ProviderUnavailable

PROVIDERS = [google.GeminiClient, groq.GroqClient, groq.GroqQwenClient, openrouter.OpenRouterClient]


@pytest.fixture
def transport(monkeypatch):
    send = Mock(side_effect=AssertionError("Unexpected network request"))
    monkeypatch.setattr("urllib.request.urlopen", send)
    return send


@pytest.mark.parametrize("client_type", PROVIDERS)
@pytest.mark.parametrize("timeout", [0, -1, 121])
def test_timeout_bounds(client_type, timeout, transport):
    with pytest.raises(ConfigError, match="timeout"):
        client_type(api_key="synthetic", timeout=timeout)
    transport.assert_not_called()


@pytest.mark.parametrize("client_type", PROVIDERS)
def test_missing_credentials_never_send(client_type, transport):
    with pytest.raises(LLMUnavailable, match="missing"):
        client_type(api_key="").generate_structured("evidence", {})
    transport.assert_not_called()


@pytest.mark.parametrize("client_type", PROVIDERS)
@pytest.mark.parametrize(
    "prompt,options,reason",
    [
        ("é" * 10241, {}, "byte budget"),
        ("evidence", {"num_predict": 0}, "token budget"),
        ("evidence", {"num_predict": 3201}, "token budget"),
        ("evidence", {"num_ctx": 511}, "context budget"),
        ("evidence", {"num_ctx": 131073}, "context budget"),
    ],
    ids=["utf8-overflow", "zero-tokens", "too-many-tokens", "small-context", "large-context"],
)
def test_request_budget_rejected_before_network(client_type, prompt, options, reason, transport):
    with pytest.raises(ConfigError, match=reason):
        client_type(api_key="synthetic").generate_structured(prompt, {}, **options)
    transport.assert_not_called()


@pytest.mark.parametrize("client_type", PROVIDERS)
@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_http_errors_are_secret_safe_and_not_retried(client_type, status, transport):
    transport.side_effect = HTTPError(
        "https://example.invalid", status, "PRIVATE secret", {}, io.BytesIO(b"PRIVATE")
    )
    with pytest.raises(ProviderUnavailable) as caught:
        client_type(api_key="PRIVATE").generate_structured("evidence", {})
    assert "PRIVATE" not in str(caught.value)
    transport.assert_called_once()


@pytest.mark.parametrize("client_type", PROVIDERS)
@pytest.mark.parametrize(
    "error", [URLError("PRIVATE"), TimeoutError("PRIVATE"), OSError("PRIVATE")]
)
def test_connection_errors_are_unavailable_not_invalid_analysis(client_type, error, transport):
    transport.side_effect = error
    with pytest.raises(ProviderUnavailable, match="unavailable") as caught:
        client_type(api_key="synthetic").generate_structured("evidence", {})
    assert "PRIVATE" not in str(caught.value)
    transport.assert_called_once()


def respond(transport, raw):
    transport.side_effect = None
    transport.return_value = io.BytesIO(raw)


@pytest.mark.parametrize("client_type", PROVIDERS)
@pytest.mark.parametrize("raw", [b"not JSON", b"{}", b'{"choices":[],"candidates":[]}'])
def test_invalid_envelope_fails_closed(client_type, raw, transport):
    respond(transport, raw)
    with pytest.raises(LLMUnavailable, match="invalid structured response"):
        client_type(api_key="synthetic").generate_structured("evidence", {})


def envelope(client_type, content):
    if client_type is google.GeminiClient:
        return {"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": content}]}}]}
    return {"choices": [{"message": {"content": content}}]}


@pytest.mark.parametrize("client_type", PROVIDERS)
@pytest.mark.parametrize("content", ["[]", "null", '"text"', "false"])
def test_non_object_analysis_fails_closed(client_type, content, transport):
    respond(transport, json.dumps(envelope(client_type, content)).encode())
    with pytest.raises(LLMUnavailable, match="must be a JSON object"):
        client_type(api_key="synthetic").generate_structured("evidence", {})


@pytest.mark.parametrize("client_type", PROVIDERS)
def test_oversize_response_never_reaches_callbacks(client_type, transport):
    respond(transport, b"x" * (64 * 1024 + 1))
    progress, raw = Mock(), Mock()
    with pytest.raises(LLMUnavailable, match="byte budget"):
        client_type(api_key="synthetic").generate_structured(
            "evidence", {}, on_progress=progress, on_raw=raw
        )
    progress.assert_not_called()
    raw.assert_not_called()


@pytest.mark.parametrize("client_type", PROVIDERS)
def test_success_preserves_audit_bytes_and_system_boundary(client_type, transport):
    expected = {"summary": "Only observed evidence"}
    raw = json.dumps(envelope(client_type, json.dumps(expected))).encode()
    respond(transport, raw)
    progress, audit = Mock(), Mock()
    schema = {"type": "object", "properties": {"summary": {"type": "string"}}}
    assert (
        client_type(api_key="synthetic", timeout=12).generate_structured(
            "evidence", schema, on_progress=progress, on_raw=audit
        )
        == expected
    )
    progress.assert_called_once_with(len(raw))
    audit.assert_called_once_with(raw)
    request = transport.call_args.args[0]
    assert transport.call_args.kwargs == {"timeout": 12}
    body = json.loads(request.data)
    assert SYSTEM_BOUNDARY_PROMPT in json.dumps(body)
    if client_type is google.GeminiClient:
        assert body["generationConfig"]["responseJsonSchema"] == schema
    else:
        assert body["response_format"]["json_schema"]["schema"] == schema


def test_gemini_truncation_is_not_success(transport):
    result = envelope(google.GeminiClient, "{}")
    result["candidates"][0]["finishReason"] = "MAX_TOKENS"
    respond(transport, json.dumps(result).encode())
    with pytest.raises(LLMUnavailable, match="invalid structured response"):
        google.GeminiClient(api_key="synthetic").generate_structured("evidence", {})


@pytest.mark.parametrize("body", [b"invalid", b"[]", b'{"error":null}', b'{"error":{}}'])
def test_groq_unrecognised_bad_request_is_transport_failure(body, transport):
    transport.side_effect = HTTPError("https://example.invalid", 400, "bad", {}, io.BytesIO(body))
    with pytest.raises(ProviderUnavailable, match="HTTP 400"):
        groq.GroqClient(api_key="synthetic").generate_structured("evidence", {})
    transport.assert_called_once()


KEY_LOADERS = [
    (google, "load_api_key", "GEMINI_API_KEY"),
    (groq, "load_api_key", "GROQ_API_KEY"),
    (groq, "load_secondary_api_key", "GROQ_SECONDARY_API_KEY"),
    (openrouter, "load_api_key", "OPENROUTER_API_KEY"),
]


@pytest.mark.parametrize("module,loader,variable", KEY_LOADERS)
def test_environment_credentials_take_precedence(module, loader, variable, monkeypatch):
    monkeypatch.setenv(variable, "  synthetic-env  ")
    monkeypatch.setattr(Path, "is_file", Mock(side_effect=AssertionError("Must not read file")))
    assert getattr(module, loader)() == "synthetic-env"


@pytest.mark.parametrize("module,loader,variable", KEY_LOADERS)
@pytest.mark.parametrize("mode", ["missing", "unrelated", "quoted", "unreadable"])
def test_key_file_fallback_is_isolated(module, loader, variable, mode, monkeypatch):
    monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(Path, "is_file", lambda _: mode != "missing")
    read = Mock(return_value=f"# configuration\n{variable}='synthetic-file'\n")
    if mode == "unreadable":
        read.side_effect = PermissionError("PRIVATE")
    elif mode == "unrelated":
        read.return_value = "OTHER_KEY=never-use-this\n"
    monkeypatch.setattr(Path, "read_text", read)
    if mode == "unreadable":
        with pytest.raises(ConfigError, match="Cannot read") as caught:
            getattr(module, loader)()
        assert "PRIVATE" not in str(caught.value)
    else:
        assert getattr(module, loader)() == ("synthetic-file" if mode == "quoted" else "")
    if mode == "missing":
        read.assert_not_called()
