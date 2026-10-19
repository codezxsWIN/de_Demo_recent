"""Ollama transport tests with bounded in-memory responses, never a real model."""

import io
import json
from unittest.mock import Mock

import pytest

from vulnassess import explain
from vulnassess.errors import ConfigError, LLMUnavailable


class Response(io.BytesIO):
    def __init__(self, raw, headers=None):
        super().__init__(raw)
        self.headers = headers or {}


@pytest.fixture
def transport(monkeypatch):
    send = Mock(side_effect=AssertionError("network"))
    monkeypatch.setattr("urllib.request.urlopen", send)
    return send


def reply(send, raw, headers=None):
    send.side_effect = None
    send.return_value = Response(raw, headers)


@pytest.mark.parametrize(
    "raw,headers",
    [
        (b"{}", {"Content-Length": str(explain.MAX_RESPONSE_BYTES + 1)}),
        (b"x" * (explain.MAX_RESPONSE_BYTES + 1), {}),
        (b"bad-json", {}),
        (b"{}", {"Content-Length": "bad"}),
    ],
    ids=["declared-large", "actual-large", "bad-json", "bad-length"],
)
def test_plain_request_invalid_response(raw, headers, transport):
    reply(transport, raw, headers)
    with pytest.raises(LLMUnavailable):
        explain.OllamaClient()._request("/api/tags")
    transport.assert_called_once()


@pytest.mark.parametrize(
    "models,available",
    [
        ([], False),
        ([{"name": "other:3b"}], False),
        ([{"name": "synthetic:latest"}], True),
        ([{"name": "synthetic:3b"}], True),
    ],
)
def test_model_inventory_checked(models, available, transport):
    reply(transport, json.dumps({"models": models}).encode())
    client = explain.OllamaClient(model="synthetic:3b")
    if available:
        assert client.available()
    else:
        with pytest.raises(LLMUnavailable, match="MISSING model"):
            client.available()


def test_plain_generation_sends_deterministic_bounded_options(transport):
    reply(transport, b'{"response":"synthetic answer"}')
    assert explain.OllamaClient(model="synthetic").generate("evidence") == "synthetic answer"
    payload = json.loads(transport.call_args.args[0].data)
    assert payload["options"] == {"temperature": 0, "seed": 0, "num_predict": 120}
    assert payload["stream"] is False


@pytest.mark.parametrize(
    "options", [{"num_predict": 0}, {"num_predict": 2049}, {"num_ctx": 511}, {"num_ctx": 131073}]
)
def test_structured_budgets_fail_before_transport(options, transport):
    with pytest.raises(ConfigError):
        explain.OllamaClient().generate_structured("evidence", {}, **options)
    transport.assert_not_called()


@pytest.mark.parametrize(
    "event,reason",
    [
        ([], "JSON object"),
        ({"message": []}, "contain text"),
        ({"message": {"content": 12}}, "contain text"),
        ({"message": {"content": "{}"}, "done": False}, "explicit completion"),
        ({"message": {"content": "[]"}, "done": True}, "JSON object"),
        ({"message": {"content": "bad"}, "done": True}, "invalid structured"),
    ],
)
def test_stream_validation(event, reason, transport):
    reply(transport, json.dumps(event).encode() + b"\n")
    with pytest.raises(LLMUnavailable, match=reason):
        explain.OllamaClient().generate_structured("evidence", {})


def test_stream_total_content_budget(transport):
    # Individually bounded events can still overflow the joined JSON budget.
    event = (
        json.dumps({"message": {"content": "x" * (explain.MAX_RESPONSE_BYTES // 2)}}).encode()
        + b"\n"
    )
    reply(transport, event * 3)
    with pytest.raises(LLMUnavailable, match="structured output exceeds"):
        explain.OllamaClient().generate_structured("evidence", {})


def test_stream_deadline_enforced(transport, monkeypatch):
    reply(transport, b'{"message":{"content":"{}"},"done":true}\n')
    monkeypatch.setattr(explain.time, "monotonic", Mock(side_effect=[0, 31]))
    with pytest.raises(LLMUnavailable, match="generation exceeded"):
        explain.OllamaClient(timeout=30).generate_structured("evidence", {})


@pytest.mark.parametrize(
    "error,reason", [(TimeoutError(), "timed out"), (OSError(), "did not answer")]
)
def test_stream_transport_errors(error, reason, transport):
    transport.side_effect = error
    with pytest.raises(LLMUnavailable, match=reason):
        explain.OllamaClient().generate_structured("evidence", {})


def test_stream_progress_and_exact_raw_audit(transport):
    expected = {"summary": "x" * 600}
    content = json.dumps(expected)
    reply(transport, json.dumps({"message": {"content": content}, "done": True}).encode() + b"\n")
    progress, audit = Mock(), Mock()
    assert (
        explain.OllamaClient().generate_structured(
            "evidence", {}, on_progress=progress, on_raw=audit
        )
        == expected
    )
    progress.assert_called_once_with(len(content.encode()))
    audit.assert_called_once_with(content.encode())


def test_explanation_rejects_excessive_sentences():
    valid, reasons = explain.validate("One. Two. Three. Four. Five.", {})
    assert not valid and "more than one sentence" in reasons["problems"]
