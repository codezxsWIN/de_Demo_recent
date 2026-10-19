"""Local outages degrade to evidence-only output; rejected content never falls back."""

import io
import json
from unittest.mock import Mock

import pytest

from vulnassess import analyst, explain
from vulnassess.ai_boundary import INJECTION_SENTINEL
from vulnassess.errors import LLMUnavailable, ProviderUnavailable


def payload():
    return {
        "run": {"run_id": "synthetic-transport"},
        "hosts": [
            {
                "ip": "127.0.0.1",
                "hostname": None,
                "services": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "name": "http",
                        "banner": "80/tcp http synthetic",
                        "product": None,
                        "version": None,
                        "cpe": None,
                        "tls": False,
                    }
                ],
            }
        ],
        "findings": [],
        "scores": [],
        "enrichments": [],
        "context": [
            {
                "host_ip": "127.0.0.1",
                "role": {
                    "value": "web_frontend",
                    "source": "rule",
                    "confidence": 0.7,
                    "evidence": "80/tcp http synthetic",
                },
                "exposure": {
                    "value": "internal",
                    "source": "rule",
                    "confidence": 0.85,
                    "evidence": "ip 127.0.0.1 is private",
                },
                "controls": {},
            }
        ],
    }


@pytest.mark.parametrize("error", [TimeoutError("synthetic deadline"), OSError("synthetic reset")])
def test_ollama_generation_outage_is_unavailable_not_rejected_output(tmp_path, monkeypatch, error):
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic-audit.jsonl")
    client = explain.OllamaClient(model="synthetic")
    monkeypatch.setattr(client, "available", lambda: True)
    monkeypatch.setattr(analyst, "provider_client", lambda *_args: client)
    monkeypatch.setattr(explain.urllib.request, "urlopen", Mock(side_effect=error))

    result = analyst.analyze_optional(payload(), "127.0.0.1", "ollama", lambda *_args: None)

    assert result["ai_status"] == "unavailable"
    assert result["analyst"] is None
    assert result["ai_attempts"][0]["status"] == "unavailable"
    assert "Needs review:" not in result["ai_attempts"][0]["detail"]


def test_generation_deadline_is_a_provider_outage(monkeypatch):
    monkeypatch.setattr(
        explain.urllib.request,
        "urlopen",
        Mock(return_value=io.BytesIO(b'{"message":{"content":"{}"},"done":true}\n')),
    )
    monkeypatch.setattr(explain.time, "monotonic", Mock(side_effect=[0, 31]))

    with pytest.raises(ProviderUnavailable, match="generation exceeded"):
        explain.OllamaClient(timeout=30).generate_structured("synthetic", {})


def test_ollama_preflight_connection_error_is_a_provider_outage(monkeypatch):
    monkeypatch.setattr(
        explain.urllib.request, "urlopen", Mock(side_effect=OSError("synthetic reset"))
    )

    with pytest.raises(ProviderUnavailable, match="did not answer"):
        explain.OllamaClient().available()


@pytest.mark.parametrize(
    "raw", [b"not-json\n", b"[]\n", b'{"message":{"content":"not-json"},"done":true}\n']
)
def test_malformed_model_output_remains_rejected_not_provider_unavailable(monkeypatch, raw):
    monkeypatch.setattr(explain.urllib.request, "urlopen", Mock(return_value=io.BytesIO(raw)))

    with pytest.raises(LLMUnavailable) as error:
        explain.OllamaClient().generate_structured("synthetic", {})

    assert not isinstance(error.value, ProviderUnavailable)


class InterruptedStream(io.BytesIO):
    def readline(self, size=-1):
        line = super().readline(size)
        if not line:
            raise TimeoutError("synthetic timeout after partial output")
        return line


@pytest.mark.parametrize("split", [False, True])
def test_partial_stream_canary_cannot_turn_into_provider_outage(tmp_path, monkeypatch, split):
    chunks = [INJECTION_SENTINEL[:15], INJECTION_SENTINEL[15:]] if split else [INJECTION_SENTINEL]
    stream = b"".join(
        (json.dumps({"message": {"content": chunk}, "done": False}) + "\n").encode()
        for chunk in chunks
    )
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic-audit.jsonl")
    client = explain.OllamaClient(model="synthetic")
    monkeypatch.setattr(client, "available", lambda: True)
    calls = []

    def select(provider, *_args):
        calls.append(provider)
        return client

    monkeypatch.setattr(analyst, "provider_client", select)
    monkeypatch.setattr(analyst, "fallback_providers", lambda: ["google", "ollama"])
    monkeypatch.setattr(
        explain.urllib.request, "urlopen", Mock(return_value=InterruptedStream(stream))
    )

    result = analyst.analyze_optional(
        payload(), "127.0.0.1", "ollama", lambda *_args: None, allow_fallback=True
    )

    assert result["ai_status"] == "needs_review"
    assert result["analyst"] is None
    assert calls == ["ollama"]
    records = [
        json.loads(line) for line in (tmp_path / "synthetic-audit.jsonl").read_text().splitlines()
    ]
    assert any(record.get("canary_seen") for record in records)


def test_canary_followed_by_transport_failure_cannot_enable_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic-audit.jsonl")
    client = Mock(model="synthetic-provider", source="synthetic")
    client.available.return_value = True

    def generate(*_args, **options):
        options["on_raw"](INJECTION_SENTINEL.encode())
        raise ProviderUnavailable("synthetic connection closed")

    client.generate_structured.side_effect = generate
    select = Mock(return_value=client)
    monkeypatch.setattr(analyst, "provider_client", select)
    monkeypatch.setattr(analyst, "fallback_providers", lambda: ["google", "ollama"])

    result = analyst.analyze_optional(
        payload(), "127.0.0.1", "groq", lambda *_args: None, allow_fallback=True
    )

    assert result["ai_status"] == "needs_review"
    assert result["analyst"] is None
    assert select.call_count == 1
