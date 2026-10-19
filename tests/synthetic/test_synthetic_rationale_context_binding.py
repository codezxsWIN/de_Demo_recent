"""Synthetic score-context correspondence checks, never real-model accuracy evidence."""

import json
from copy import deepcopy
from dataclasses import replace

import pytest

from tests.test_all import WEIGHTS, FakeModel, make_enrichment, make_finding, make_profile
from vulnassess import explain, scoring
from vulnassess.ai_boundary import digest
from vulnassess.errors import ConfigError
from vulnassess.schema import Host
from vulnassess.store import Store


@pytest.fixture(autouse=True)
def synthetic_audit_path(tmp_path, monkeypatch):
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", tmp_path / "synthetic_context_audit.jsonl")


def synthetic_case():
    finding = make_finding()
    profile = make_profile(role="database", exposure="internet_facing", environment="prod")
    score = scoring.score(
        finding, make_enrichment(finding_id=finding.id, kev=False), profile, (), WEIGHTS
    )
    return finding, profile, score


@pytest.mark.parametrize(
    "changes",
    [
        {"role": "workstation"},
        {"exposure": "internal"},
        {"environment": "test"},
        {"role": "web_frontend", "exposure": "internal", "environment": "test"},
    ],
)
def test_facts_describe_retained_scoring_context_not_later_profile(changes):
    finding, profile, score = synthetic_case()
    later = make_profile(
        **{"role": "database", "exposure": "internet_facing", "environment": "prod", **changes}
    )
    before = deepcopy((score.to_json(), profile.to_json(), later.to_json()))
    facts = explain.facts_for(score, later, finding)
    assert facts["asset role"] == "database"
    assert facts["exposure"] == "internet-facing"
    assert facts["environment"] == "prod"
    assert (score.to_json(), profile.to_json(), later.to_json()) == before


def test_changed_profile_cannot_authorize_an_opposite_model_sentence(tmp_path, monkeypatch):
    finding, profile, score = synthetic_case()
    later = make_profile(role="workstation", exposure="internal", environment="test")
    client = FakeModel("Critical priority for this internal workstation, with a test environment.")
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", tmp_path / "synthetic_context_audit.jsonl")
    before = deepcopy(score.to_json())
    result = explain.rationale_for(score, later, finding, client)
    assert result.source == "template"
    assert result.validation["status"] == "needs_review"
    assert result.validation["accepted"] is False
    assert score.to_json() == before
    assert profile.role.value == "database"


def test_valid_model_sentence_can_explain_original_context_after_profile_change(
    tmp_path, monkeypatch
):
    finding, _profile, score = synthetic_case()
    later = make_profile(role="workstation", exposure="internal", environment="test")
    sentence = "Critical priority for this internet-facing database, with a prod environment."
    client = FakeModel(sentence)
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", tmp_path / "synthetic_context_audit.jsonl")
    before = deepcopy((score.to_json(), later.to_json()))
    result = explain.rationale_for(score, later, finding, client)
    assert result.source == "llm", result.validation
    assert result.text == sentence
    assert result.validation["context_basis"] == "retained_score_inputs"
    assert (score.to_json(), later.to_json()) == before


@pytest.mark.parametrize("foreign", ["finding_id", "finding_host", "profile_host", "score_host"])
def test_foreign_ownership_is_rejected_before_building_facts(foreign):
    finding, profile, score = synthetic_case()
    if foreign == "finding_id":
        finding = replace(finding, id="synthetic foreign finding")
    elif foreign == "finding_host":
        finding = replace(finding, host_ip="192.0.2.20")
    elif foreign == "profile_host":
        profile = replace(profile, host_ip="192.0.2.20")
    else:
        score = replace(score, host_ip="192.0.2.20")
    with pytest.raises(ConfigError, match="binding"):
        explain.facts_for(score, profile, finding)


@pytest.mark.parametrize("field", ["role", "exposure", "controls", "manual"])
def test_missing_retained_context_cannot_borrow_current_metadata(field):
    finding, profile, score = synthetic_case()
    inputs = deepcopy(score.inputs)
    del inputs[field]
    score = replace(score, inputs=inputs)
    before = deepcopy(score.to_json())
    with pytest.raises(ConfigError, match="retained score context"):
        explain.facts_for(score, profile, finding)
    assert score.to_json() == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", None),
        (
            "role",
            {"value": "database", "confidence": True, "source": "rule", "evidence": "synthetic"},
        ),
        (
            "role",
            {"value": "database", "confidence": 0.9, "source": "llm", "evidence": "synthetic"},
        ),
        (
            "role",
            {"value": "fictional", "confidence": 0.9, "source": "rule", "evidence": "synthetic"},
        ),
        (
            "exposure",
            {"value": "isolated", "confidence": 0.9, "source": "rule", "evidence": "synthetic"},
        ),
        ("controls", []),
        (
            "controls",
            {"waf": {"value": 1, "confidence": 0.9, "source": "rule", "evidence": "synthetic"}},
        ),
        ("manual", None),
        (
            "manual",
            {
                "environment": {
                    "value": "staging",
                    "confidence": 1.0,
                    "source": "manual",
                    "evidence": "synthetic",
                }
            },
        ),
    ],
)
def test_malformed_retained_context_fails_closed_before_any_model_call(field, value):
    finding, profile, score = synthetic_case()
    inputs = deepcopy(score.inputs)
    inputs[field] = value
    score = replace(score, inputs=inputs)
    client = FakeModel("Critical priority for this internet-facing database.")
    before = deepcopy(score.to_json())
    result = explain.rationale_for(score, profile, finding, client)
    assert result.source == "template"
    assert result.validation["accepted"] is False
    assert result.validation["status"] == "needs_review"
    assert client.prompts == []
    assert "needs review" in result.text.lower()
    assert result.text != score.reason
    assert score.to_json() == before


def test_missing_legacy_context_is_needs_review_even_without_a_model():
    finding, profile, score = synthetic_case()
    score = replace(score, inputs={}, reason="SYNTHETIC unsupported legacy narrative")
    before = deepcopy(score.to_json())
    result = explain.rationale_for(score, profile, finding)
    assert result.source == "template" and result.model is None
    assert result.validation["accepted"] is False
    assert result.validation["status"] == "needs_review"
    assert "legacy narrative" not in result.text
    assert score.to_json() == before


@pytest.mark.parametrize("policy", ["finding-scoped-controls-v1", "synthetic unknown policy", None])
def test_legacy_control_decisions_do_not_claim_current_endpoint_eligibility(policy):
    finding, profile, score = synthetic_case()
    inputs = deepcopy(score.inputs)
    inputs["context_policy"] = policy
    inputs["controls"]["waf"] = {
        "value": "synthetic-filter",
        "confidence": 0.9,
        "source": "rule",
        "evidence": "SYNTHETIC recorded filter observation",
    }
    inputs["control_applicability"]["waf"]["status"] = "applied"
    score = replace(score, inputs=inputs)
    before = deepcopy(score.to_json())
    facts = explain.facts_for(score, profile, finding)
    assert "synthetic-filter" in facts["compensating control"]
    assert "unverified" in facts["compensating control"]
    assert "on affected HTTP record" not in facts["compensating control"]
    assert score.to_json() == before


@pytest.mark.parametrize(
    "bad", [None, [], "synthetic invalid decision", {"waf": None}, {"waf": {"status": "synthetic"}}]
)
def test_invalid_control_decisions_cannot_become_none_observed(bad):
    finding, profile, score = synthetic_case()
    inputs = deepcopy(score.inputs)
    inputs["control_applicability"] = bad
    result = explain.rationale_for(replace(score, inputs=inputs), profile, finding)
    assert result.validation["status"] == "needs_review"
    assert result.validation["accepted"] is False


def test_missing_current_waf_decision_is_not_silently_accepted():
    finding, profile, score = synthetic_case()
    inputs = deepcopy(score.inputs)
    del inputs["control_applicability"]["waf"]
    with pytest.raises(ConfigError, match="finding-scoped WAF decision"):
        explain.facts_for(replace(score, inputs=inputs), profile, finding)


@pytest.mark.parametrize("unrepresentable", [float("nan"), float("inf"), {"synthetic"}])
def test_unhashable_or_nonfinite_input_metadata_fails_before_model(unrepresentable):
    finding, profile, score = synthetic_case()
    inputs = deepcopy(score.inputs)
    inputs["synthetic_extra_metadata"] = unrepresentable
    client = FakeModel("Critical priority for this internet-facing database.")
    result = explain.rationale_for(replace(score, inputs=inputs), profile, finding, client)
    assert result.validation["status"] == "needs_review"
    assert client.prompts == []


def test_actual_explain_store_path_keeps_score_context_after_profile_change(tmp_path):
    finding, profile, score = synthetic_case()
    later = make_profile(role="workstation", exposure="internal", environment="test")
    sentence = "Critical priority for this internet-facing database, with a prod environment."
    client = FakeModel(sentence)
    with Store(tmp_path / "synthetic_context_store.db") as store:
        store.start_run("synthetic-context", "synthetic configuration hash")
        store.upsert_host("synthetic-context", Host(ip=profile.host_ip))
        store.upsert_findings("synthetic-context", [finding])
        store.upsert_profile("synthetic-context", later)
        store.upsert_score("synthetic-context", score)
        original_scores = [item.to_json() for item in store.scores("synthetic-context")]
        counts = explain.explain_run("synthetic-context", store, client)
        assert counts == {"llm": 1, "template": 0}
        result = store.rationales("synthetic-context")[finding.id]
        assert result.text == sentence
        assert result.validation["context_basis"] == "retained_score_inputs"
        assert [item.to_json() for item in store.scores("synthetic-context")] == original_scores
        assert store.profiles("synthetic-context")[0].to_json() == later.to_json()
    audit = json.loads((tmp_path / "synthetic_context_audit.jsonl").read_text())
    assert audit["score_inputs_hash"] == digest(score.inputs)
    assert audit["outcome"] == "validated"


@pytest.mark.parametrize("missing", ["finding", "profile"])
def test_missing_record_in_later_score_is_not_silent_partial_success(tmp_path, missing):
    finding, profile, score = synthetic_case()
    orphan_finding = make_finding(host_ip="192.0.2.20", port=22)
    orphan_profile = make_profile(host_ip="192.0.2.20")
    orphan_score = scoring.score(orphan_finding, None, orphan_profile, (), WEIGHTS)
    client = FakeModel("Critical priority for this internet-facing database.")
    with Store(tmp_path / "synthetic_orphan_context.db") as store:
        store.start_run("synthetic-orphan", "synthetic configuration hash")
        store.upsert_findings("synthetic-orphan", [finding])
        store.upsert_profile("synthetic-orphan", profile)
        if missing == "finding":
            store.upsert_profile("synthetic-orphan", orphan_profile)
        else:
            store.upsert_findings("synthetic-orphan", [orphan_finding])
        store.upsert_score("synthetic-orphan", score)
        store.upsert_score("synthetic-orphan", orphan_score)
        assert store.scores("synthetic-orphan")[0].finding_id == score.finding_id
        before = list(store.connection.iterdump())
        with pytest.raises(ConfigError, match="MISSING:.*" + missing):
            explain.explain_run("synthetic-orphan", store, client)
        assert client.prompts == []
        assert list(store.connection.iterdump()) == before
