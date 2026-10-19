"""Synthetic model transport and report integrity tests use no external services."""

import io
import json
from dataclasses import replace
from unittest.mock import Mock

import pytest
import yaml

from tests import test_all as fixtures
from tests.test_all import FakeModel
from tests.test_assessment_snapshot import SETTINGS, prepared_store
from vulnassess import explain, pipeline, report
from vulnassess.errors import ConfigError, LLMUnavailable
from vulnassess.schema import Rationale


@pytest.mark.parametrize("endpoint", ["http://[broken", "http://127.0.0.1:invalid"])
def test_invalid_local_model_endpoint_is_rejected_before_request(endpoint):
    with pytest.raises(ConfigError, match="Invalid Ollama endpoint"):
        explain.OllamaClient(endpoint)


def test_model_sentence_cannot_contain_markup():
    accepted, validation = explain.validate("Synthetic <script> content.", {})
    assert accepted is False
    assert "contains '<'" in validation["problems"]


@pytest.mark.parametrize("failure", ["too_large", "deadline", "provider_error"])
def test_model_stream_failure_never_yields_partial_json(monkeypatch, failure):
    raw = json.dumps({"message": {"content": "{}"}, "done": True}).encode() + b"\n"
    if failure == "provider_error":
        raw = b'{"error":"SYNTHETIC unavailable"}\n'
    monkeypatch.setattr("urllib.request.urlopen", Mock(return_value=io.BytesIO(raw)))
    if failure == "too_large":
        monkeypatch.setattr(explain, "MAX_RESPONSE_BYTES", 2)
    elif failure == "deadline":
        monkeypatch.setattr(explain.time, "monotonic", Mock(side_effect=[0, 5]))
    with pytest.raises(LLMUnavailable, match="budget|exceeded|Ollama error"):
        explain.OllamaClient(timeout=1).generate_structured("synthetic", {})


@pytest.mark.parametrize(
    "failure", ["bad_schema", "wrong_finding", "nontext", "unserializable", "unexpected"]
)
def test_rejected_model_rationale_preserves_deterministic_verdict(tmp_path, monkeypatch, failure):
    finding, score, profile = fixtures.TestExplain()._fixture()
    model = FakeModel("Synthetic observed context.")
    original = model.generate_structured

    def generate(*args, **kwargs):
        response = original(*args, **kwargs)
        if failure == "bad_schema":
            response["schema_version"] = "unknown"
        elif failure == "wrong_finding":
            response["claims"][0]["finding_ids"] = []
        elif failure == "nontext":
            response["text"] = 42
        elif failure == "unserializable":
            return {"unexpected": {"synthetic"}}
        else:
            raise RuntimeError("SYNTHETIC private internals")
        return response

    monkeypatch.setattr(model, "generate_structured", generate)
    audit_path = tmp_path / "synthetic_audit.jsonl"
    monkeypatch.setattr(explain, "RATIONALE_AUDIT_PATH", audit_path)
    result = explain.rationale_for(score, profile, finding, model)
    assert result.source == "template"
    assert result.text == score.reason
    assert result.validation["status"] == "needs_review"
    record = json.loads(audit_path.read_text())
    assert record["decision"] == "reject" and record["outcome"] == "needs_review"
    assert "private internals" not in str(result.validation)


@pytest.mark.parametrize("missing", ["profile", "finding"])
def test_orphaned_score_does_not_receive_fabricated_rationale(tmp_path, monkeypatch, missing):
    with prepared_store(str(tmp_path)) as store:
        if missing == "profile":
            monkeypatch.setattr(store, "profiles", Mock(return_value=[]))
        else:
            monkeypatch.setattr(store, "findings", Mock(return_value=[]))
        before = list(store.connection.iterdump())
        with pytest.raises(ConfigError, match="MISSING:.*" + missing):
            explain.explain_run("snapshot", store)
        assert store.rationales("snapshot") == {}
        assert list(store.connection.iterdump()) == before


@pytest.mark.parametrize("native", [None, "nmap=invalid", "nmap=101"])
def test_baselines_refuse_invalid_native_provenance(tmp_path, native):
    with prepared_store(str(tmp_path)) as store:
        score = replace(store.scores("snapshot")[0], base_score=None, native_fallback=native)
        store.upsert_score("snapshot", score)
        before = [item.to_json() for item in store.scores("snapshot")]
        if native is None:
            result = pipeline.baseline_orders(store, "snapshot")
            assert score.finding_id in result["cvss_only"]
        else:
            with pytest.raises(ConfigError, match="native severity provenance"):
                pipeline.baseline_orders(store, "snapshot")
        assert [item.to_json() for item in store.scores("snapshot")] == before


def test_rank_requires_recorded_context(tmp_path, monkeypatch):
    with prepared_store(str(tmp_path)) as store:
        monkeypatch.setattr(store, "profiles", Mock(return_value=[]))
        with pytest.raises(ConfigError, match="no context profiles"):
            pipeline.do_rank(SETTINGS, store, "snapshot")


def test_expert_truth_cannot_rank_a_fabricated_finding(tmp_path):
    path = tmp_path / "synthetic_truth.yaml"
    path.write_text(
        yaml.safe_dump(
            {"experts": [{"name": "synthetic", "ranking": ["fabricated"]}], "expert_critical": []}
        )
    )
    with prepared_store(str(tmp_path)) as store:
        with pytest.raises(ConfigError, match="not a finding"):
            pipeline.do_eval(store, "snapshot", path)


def test_comparison_discloses_unavailable_cve_identity(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        for score in store.scores("snapshot"):
            store.upsert_score("snapshot", replace(score, cve_id=None))
        text = pipeline.two_machine_table(store, "snapshot")
    assert "No CVE appears" in text


def test_report_preserves_model_attribution_and_skips_missing_provenance(tmp_path):
    finding, score, profile = fixtures.TestExplain()._fixture()
    rationale = Rationale(
        finding.id, "Synthetic attributed explanation.", "llm", model="synthetic-model"
    )
    rendered = report._ranked(
        [score], {finding.id: finding}, {profile.host_ip: profile}, {finding.id: rationale}
    )
    assert "reworded by synthetic-model" in rendered
    assert finding.id not in report._provenance([score], {})


def test_legacy_control_mapping_is_not_reinterpreted_as_observed(tmp_path):
    _, score, _ = fixtures.TestExplain()._fixture()
    assert report._control_applicability([replace(score, inputs={})], {}) == ""
    assert (
        report._control_applicability(
            [replace(score, inputs={"control_applicability": {"waf": "invalid"}})], {}
        )
        == ""
    )


def test_report_discloses_context_disagreement_and_rescan_unknowns():
    payload = {
        "rows": [],
        "artifacts": {
            "context": {
                "rule_model_disagreements": [
                    {
                        "host_ip": "192.0.2.1",
                        "truth": "database",
                        "rule": "unknown",
                        "model": "web_frontend",
                        "rule_evidence": "<SYNTHETIC>",
                    }
                ]
            },
            "rescan": {
                "outcomes": [
                    {
                        "finding_id": "synthetic",
                        "host_ip": "192.0.2.1",
                        "outcome": "not_observable",
                        "evidence": "<SYNTHETIC>",
                        "evidence_loss": True,
                    }
                ]
            },
        },
    }
    rendered = report._audit(payload)
    assert "Context-evaluation disagreements" in rendered
    assert "Re-scan outcomes requiring human adjudication" in rendered
    assert "not_observable" in rendered and "&lt;SYNTHETIC&gt;" in rendered
