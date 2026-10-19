"""Synthetic analyst requests exercise budgets, fallback identity and complete batch review."""

import copy
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_analyst import FakeClient, demo_payload, six_finding_payload, valid_result
from vulnassess import analyst
from vulnassess.errors import ConfigError, LLMUnavailable, NeedsReview

HOST = "172.28.0.12"


def test_evidence_budget_discloses_omitted_findings(monkeypatch):
    payload = six_finding_payload()
    single = {**payload, "findings": payload["findings"][:1]}
    _, evidence, _ = analyst.build_case(single, HOST)
    monkeypatch.setattr(analyst, "MAX_EVIDENCE", len(evidence))
    case, _, aliases = analyst.build_case(payload, HOST)
    assert len(aliases) == 1
    assert case["coverage"]["findings_omitted"] == 5


def test_request_schema_does_not_bind_unknown_or_invalid_score():
    schema = analyst.analysis_schema({"F1"}, {"E1"}, {"F999": 100, "F1": "invalid"})
    raw = json.dumps(schema)
    assert "F999" not in raw and "invalid" not in raw


def test_configuration_error_does_not_claim_model_availability(monkeypatch):
    monkeypatch.setattr(
        analyst, "provider_client", Mock(side_effect=ConfigError("synthetic invalid credentials"))
    )
    assert "credentials could not be read" in analyst.configuration_detail("groq")


def test_no_finding_legacy_batch_preserves_evidence_only_output(monkeypatch):
    payload = demo_payload()
    payload["findings"] = []
    response = {"ai_status": "unavailable", "analyst": None}
    monkeypatch.setattr(analyst, "analyze_target", Mock(return_value=response))
    assert analyst.analyze_findings(payload, HOST) == response


def test_complete_batches_use_selected_client_and_publish_one_completion(tmp_path, monkeypatch):
    payload = six_finding_payload()
    original = copy.deepcopy(payload)
    case, _, _ = analyst.build_case(payload, HOST)
    client = FakeClient(valid_result("F1", case["findings"][0]["evidence_id"]))
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    events = []
    result = analyst.analyze_findings(
        payload, HOST, client=client, on_progress=lambda *row: events.append(row)
    )
    assert result["batch_coverage"]["findings_included"] == 6
    assert result["batch_coverage"]["findings_omitted"] == 0
    assert any(
        stage == "validation" and state == "complete" and "All 6 findings" in detail
        for stage, state, detail in events
    )
    assert payload == original


def test_unknown_service_assertion_is_rejected(tmp_path, monkeypatch):
    payload = demo_payload()
    case, _, _ = analyst.build_case(payload, HOST)
    response = valid_result("F1", case["findings"][0]["evidence_id"])
    response["summary"] = "A telnet daemon is exposed."
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    with pytest.raises(NeedsReview, match="unknown service"):
        analyst.analyze_target(payload, HOST, FakeClient(response))


def test_uncertainty_can_name_potential_access_without_claiming_it_observed(tmp_path, monkeypatch):
    payload = demo_payload()
    case, _, _ = analyst.build_case(payload, HOST)
    response = valid_result("F1", case["findings"][0]["evidence_id"])
    response["uncertainties"] = ["Potential unauthenticated access requires verification."]
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    result = analyst.analyze_target(payload, HOST, FakeClient(response))
    assert result["analysis"]["uncertainties"] == response["uncertainties"]


def test_prompt_over_budget_stops_before_generation(monkeypatch):
    payload = demo_payload()
    payload["findings"] = []
    payload["scores"] = []
    payload["enrichments"] = []
    monkeypatch.setattr(analyst, "MAX_PROMPT_CHARS", 1)
    client = FakeClient({})
    generate = Mock(side_effect=AssertionError("must not generate"))
    monkeypatch.setattr(client, "generate_structured", generate)
    with pytest.raises(ConfigError, match="character budget"):
        analyst.analyze_target(payload, HOST, client)
    generate.assert_not_called()


def test_self_defence_local_model_uses_extended_deadline_without_changing_budget(
    tmp_path, monkeypatch
):
    payload = demo_payload()
    payload["self_defence"] = {"boundary": "synthetic local-only", "limitations": [], "checks": []}
    client = analyst.OllamaClient(model="synthetic-local")
    monkeypatch.setattr(client, "available", Mock(return_value=True))
    generation = Mock(side_effect=LLMUnavailable("synthetic offline"))
    monkeypatch.setattr(client, "generate_structured", generation)
    monkeypatch.setattr(analyst, "provider_client", Mock(return_value=client))
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    with pytest.raises(NeedsReview, match="synthetic offline"):
        analyst.analyze_target(payload, HOST)
    assert client.timeout == 300
    assert generation.call_args.kwargs["num_predict"] == 1200


def test_citation_retry_respects_remaining_prompt_budget(tmp_path, monkeypatch):
    payload = demo_payload()
    case, evidence, aliases = analyst.build_case(payload, HOST)
    prompt = analyst.build_prompt(case, evidence, len(aliases))
    response = valid_result("F1", case["services"][0]["evidence_id"])
    client = FakeClient(response)
    monkeypatch.setattr(analyst, "MAX_PROMPT_CHARS", len(prompt) + 10)
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    with pytest.raises(NeedsReview, match="supporting evidence"):
        analyst.analyze_target(payload, HOST, client)
    assert len((tmp_path / "synthetic_audit.jsonl").read_text().splitlines()) == 1


def test_missing_validated_response_is_detected_before_grounding(tmp_path, monkeypatch):
    payload = demo_payload()
    case, _, _ = analyst.build_case(payload, HOST)
    client = FakeClient(valid_result("F1", case["findings"][0]["evidence_id"]))
    monkeypatch.setattr(analyst, "validate_analysis", Mock(return_value=None))
    audit_path = tmp_path / "synthetic_audit.jsonl"
    monkeypatch.setattr(analyst, "AUDIT_PATH", audit_path)
    events = []
    with pytest.raises(NeedsReview, match="No validated analyst response was produced"):
        analyst.analyze_target(payload, HOST, client, on_progress=lambda *row: events.append(row))
    record = json.loads(audit_path.read_text())
    assert record["reason"] == "LLMUnavailable"
    assert record["outcome"] == "needs_review"
    assert not any(stage == "validation" and state == "complete" for stage, state, _ in events)


def test_unrecorded_numeric_assertion_is_rejected(tmp_path, monkeypatch):
    payload = demo_payload()
    case, _, _ = analyst.build_case(payload, HOST)
    response = valid_result("F1", case["findings"][0]["evidence_id"])
    response["summary"] = "The assessment requires 777777 actions."
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    with pytest.raises(NeedsReview, match="unsupported numbers"):
        analyst.analyze_target(payload, HOST, FakeClient(response))


def test_explicit_verification_question_keeps_authentication_unknown(tmp_path, monkeypatch):
    payload = demo_payload()
    case, _, _ = analyst.build_case(payload, HOST)
    response = valid_result("F1", case["findings"][0]["evidence_id"])
    response["summary"] = "Whether unauthenticated access is possible is not established."
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    result = analyst.analyze_target(payload, HOST, FakeClient(response))
    assert result["analysis"]["summary"] == response["summary"]
    assert result["canonical_scores_changed"] is False


def test_fallbacks_keep_separately_configured_provider_identity(monkeypatch):
    monkeypatch.setattr(
        analyst,
        "provider_client",
        lambda provider: SimpleNamespace(
            key="synthetic-configured" if provider == "groq_qwen" else ""
        ),
    )
    assert analyst.fallback_providers() == ["groq_qwen", "ollama"]


def test_single_finding_review_returns_one_complete_analysis(tmp_path, monkeypatch):
    payload = demo_payload()
    payload["findings"] = [next(item for item in payload["findings"] if item["host_ip"] == HOST)]
    original = copy.deepcopy(payload)
    case, _, _ = analyst.build_case(payload, HOST)
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic_audit.jsonl")
    result = analyst.analyze_findings(
        payload, HOST, FakeClient(valid_result("F1", case["findings"][0]["evidence_id"]))
    )
    assert result["finding_coverage"]["included_ids"] == [payload["findings"][0]["id"]]
    assert "batches" not in result
    assert result["canonical_scores_changed"] is False
    assert payload == original


def test_invalid_selected_provider_stops_before_generation(monkeypatch):
    client = FakeClient({})
    generate = Mock(side_effect=AssertionError("must not generate"))
    monkeypatch.setattr(client, "generate_structured", generate)
    with pytest.raises(ConfigError, match="Unknown analyst provider"):
        analyst.analyze_target(demo_payload(), HOST, client, provider="synthetic-unsupported")
    generate.assert_not_called()
