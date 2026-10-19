"""Provider failures must not invalidate independently collected evidence."""

from unittest.mock import patch

import pytest

from vulnassess import analyst
from vulnassess.errors import LLMUnavailable, NeedsReview, ProviderUnavailable


@pytest.fixture(autouse=True)
def isolate_audit(tmp_path, monkeypatch):
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "audit.jsonl")


def test_outage_returns_evidence_only_and_records_failure():
    with patch.object(analyst, "analyze_target", side_effect=LLMUnavailable("endpoint down")):
        result = analyst.analyze_optional({}, "127.0.0.1", "groq", lambda *_: None)
    assert result["analyst"] is None
    assert result["ai_status"] == "unavailable"
    assert result["ai_attempts"][0]["provider"] == "groq"


def test_fallback_reuses_payload_and_records_actual_provider():
    payload = {"scores": [{"risk": 4.2}]}
    seen = []

    def analyze(value, host, *, provider, on_progress):
        seen.append((value, host, provider))
        on_progress("generation", "running", "Generating")
        if provider == "openrouter":
            raise LLMUnavailable("endpoint down")
        return {"model": "test", "analysis": {"summary": "validated"}}

    with (
        patch.object(analyst, "fallback_providers", return_value=["google"]),
        patch.object(analyst, "analyze_target", side_effect=analyze),
    ):
        result = analyst.analyze_optional(
            payload, "127.0.0.1", "openrouter", lambda *_: None, allow_fallback=True
        )
    assert result["used_provider"] == "google"
    assert result["ai_status"] == "validated"
    assert [item[2] for item in seen] == ["openrouter", "google"]
    assert all(item[0] is payload for item in seen)
    assert payload["scores"] == [{"risk": 4.2}]


def test_validation_rejection_is_visible_and_does_not_fallback():
    def reject(*_, on_progress, **__):
        on_progress("validation", "running", "Checking claims")
        raise NeedsReview("fabricated citation")

    with (
        patch.object(analyst, "fallback_providers", return_value=["google"]),
        patch.object(analyst, "analyze_target", side_effect=reject) as calls,
    ):
        result = analyst.analyze_optional(
            {}, "127.0.0.1", "groq", lambda *_: None, allow_fallback=True
        )
    assert calls.call_count == 1
    assert result["ai_status"] == "needs_review"
    assert result["analyst"] is None


def test_local_selection_never_sends_evidence_to_cloud():
    with (
        patch.object(analyst, "fallback_providers", return_value=["google"]),
        patch.object(
            analyst, "analyze_target", side_effect=LLMUnavailable("local model missing")
        ) as calls,
    ):
        analyst.analyze_optional({}, "127.0.0.1", "ollama", lambda *_: None, allow_fallback=True)
    assert calls.call_count == 1


def test_all_provider_outages_end_with_evidence_only():
    def unavailable(*_, on_progress, **__):
        on_progress("generation", "running", "Waiting")
        raise NeedsReview("endpoint unavailable") from ProviderUnavailable("HTTP 404")

    with (
        patch.object(analyst, "fallback_providers", return_value=["google", "ollama"]),
        patch.object(analyst, "analyze_target", side_effect=unavailable) as calls,
    ):
        result = analyst.analyze_optional(
            {}, "127.0.0.1", "openrouter", lambda *_: None, allow_fallback=True
        )
    assert calls.call_count == 3
    assert result["analyst"] is None
    assert result["ai_status"] == "unavailable"
    assert [item["provider"] for item in result["ai_attempts"]] == [
        "openrouter",
        "google",
        "ollama",
    ]


def test_malformed_or_injected_output_never_triggers_fallback():
    def rejected(*_, on_progress, **__):
        on_progress("generation", "running", "Waiting")
        raise NeedsReview("invalid JSON or canary") from LLMUnavailable("invalid output")

    with (
        patch.object(analyst, "fallback_providers", return_value=["google"]),
        patch.object(analyst, "analyze_target", side_effect=rejected) as calls,
    ):
        result = analyst.analyze_optional(
            {}, "127.0.0.1", "groq", lambda *_: None, allow_fallback=True
        )
    assert calls.call_count == 1
    assert result["ai_status"] == "needs_review"


def test_cloud_preflight_describes_credentials_only():
    class Configured:
        key = "test-only"

    with patch.object(analyst, "provider_client", return_value=Configured()):
        detail = analyst.configuration_detail("google")
    assert "credentials configured" in detail
    assert "during generation" in detail
    assert "is available" not in detail
