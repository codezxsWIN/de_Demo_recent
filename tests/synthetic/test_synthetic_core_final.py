"""Remaining canonical-model, context, ranking, and merge contracts use synthetic inputs."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from tests.test_all import make_finding, make_profile
from tests.test_assessment_snapshot import ROOT, SETTINGS, prepared_store
from tests.test_rescan import observation
from tests.test_role_model import examples
from vulnassess import context, context_eval, diff, rescan, role_model, schema, scoring, unify
from vulnassess.errors import ConfigError
from vulnassess.readers.nmap_xml import _cve_line


def test_evidence_truncation_is_explicit_and_preserves_original_prefix():
    text = "synthetic " * schema.EVIDENCE_MAX
    assert schema.cap_evidence(text) == text[: schema.EVIDENCE_MAX] + schema.TRUNCATION_MARKER


@pytest.mark.parametrize(
    "source,text,message", [("unknown", "synthetic", "source"), ("llm", "  ", "empty")]
)
def test_invalid_rationale_cannot_enter_canonical_model(source, text, message):
    with pytest.raises(ValueError, match=message):
        schema.Rationale("synthetic-finding", text, source)


def test_context_exposure_handles_invalid_address_without_claiming_external_reachability():
    scope = SimpleNamespace(tags=lambda _: {}, name=lambda _: None, segment=lambda _: None)
    feature, segment = context.infer_exposure(schema.Host("synthetic-invalid-ip"), scope)
    assert feature.value != "internet_facing"
    assert segment is None


def test_human_context_truth_requires_provenance():
    with pytest.raises(ValueError, match="requires provenance"):
        context_eval.ContextTruth(
            "192.0.2.1", "synthetic", "database", "internal", reviewer="synthetic-test"
        )


def test_context_truth_round_trip_preserves_label_provenance():
    truth = context_eval.ContextTruth(
        "192.0.2.1",
        "synthetic",
        "database",
        "internal",
        label_source="synthetic",
        provenance="synthetic labelled record",
    )
    assert truth.to_json()["provenance"] == "synthetic labelled record"
    assert truth.to_json()["label_source"] == "synthetic"


@pytest.mark.parametrize("mode", ["empty_truth", "duplicate_profiles"])
def test_context_evaluation_rejects_ambiguous_inputs(mode):
    profile = make_profile()
    truth = context_eval.ContextTruth(
        profile.host_ip, "synthetic", "web_frontend", "internal", label_source="synthetic"
    )
    with pytest.raises(ConfigError, match="labelled host|duplicate host"):
        context_eval.evaluate_context(
            [profile, profile] if mode == "duplicate_profiles" else [profile],
            [] if mode == "empty_truth" else [truth],
        )


def test_context_evaluation_accepts_real_shadow_prediction_without_mutating_profile():
    model = role_model.load_model(ROOT / "models/synthetic-role-model.json")
    profile = make_profile()
    prediction = model.predict(schema.Host(profile.host_ip))
    truth = context_eval.ContextTruth(
        profile.host_ip, "synthetic", "web_frontend", "internal", label_source="synthetic"
    )
    result = context_eval.evaluate_context([profile], [truth], {profile.host_ip: prediction})
    assert result["model_role"]["abstention_rate"] == 1
    assert profile.role.source == "rule"


def test_diff_renders_actual_score_change_without_claiming_remediation(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        old = store.scores("snapshot")[0]
        finding = next(item for item in store.findings("snapshot") if item.id == old.finding_id)
        store.start_run("synthetic-after", SETTINGS.config_hash())
        store.upsert_findings("synthetic-after", [finding])
        store.upsert_score("synthetic-after", replace(old, risk=1, band="Low"))
        result = diff.diff_runs(store, "snapshot", "synthetic-after")
    assert result["changed"][0]["risk_before"] == old.risk
    assert result["changed"][0]["risk_after"] == 1
    rendered = diff.markdown_table(result)
    assert f"{old.risk} -> 1" in rendered
    assert "before claiming a fix" in rendered


def test_legacy_score_description_retains_recorded_control(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        score = replace(store.scores("snapshot")[0], inputs={})
    original = score.to_json()
    rendered = scoring.describe(score, make_profile(host_ip=score.host_ip, waf="synthetic-filter"))
    assert "synthetic-filter recorded signal" in rendered
    assert "applicability and mitigation unverified" in rendered
    assert "behind synthetic-filter" not in rendered
    assert score.to_json() == original


def test_invalid_cvss_requirement_is_not_silently_defaulted():
    with pytest.raises(ConfigError, match="CR.*must be one of"):
        SETTINGS._requirements(
            ROOT / "config/weights.yaml", {"CR": "INVALID", "IR": "H", "AR": "H"}, "synthetic"
        )


def test_three_scanner_agreement_merges_transitively_without_losing_sources():
    findings = [
        make_finding(
            tool=tool,
            tool_native_id=f"synthetic-{tool}",
            url="http://172.28.0.10/synthetic-instance",
        )
        for tool in ("nmap", "nikto", "nessus")
    ]
    result = unify.unify_findings(findings)
    assert result.raw_count == 3 and result.unified_count == 1
    assert set(result.groups[0].source_finding_ids) == {item.id for item in findings}
    assert set(result.groups[0].tools) == {"nmap", "nikto", "nessus"}


def test_empty_titles_do_not_create_duplicate_candidates():
    findings = [
        make_finding(title="", cve_ids=[], tool_native_id=f"synthetic-{i}") for i in range(2)
    ]
    result = unify.unify_findings(findings)
    assert result.unified_count == 2 and result.candidates == ()


def test_nmap_quote_fallback_preserves_only_supplied_evidence():
    assert (
        _cve_line("  SYNTHETIC no CVE was provided  ", "CVE-1999-9001")
        == "SYNTHETIC no CVE was provided"
    )


@pytest.mark.parametrize("mode", ["duplicate", "unknown"])
def test_rescan_rejects_scores_without_unique_corresponding_findings(tmp_path, mode):
    with prepared_store(str(tmp_path)) as store:
        score = store.scores("snapshot")[0]
    source = observation("synthetic")
    with pytest.raises(ConfigError, match="duplicate score|score references missing finding"):
        rescan.build_observation_artifact(
            source, [score, score] if mode == "duplicate" else [score], evidence_status="NOT RUN"
        )


def test_model_deserialization_rejects_missing_fields():
    with pytest.raises(ConfigError, match="invalid role-model artifact"):
        role_model.RoleModel.from_json({})


def test_cpe23_features_retain_service_banner_as_evidence():
    host = schema.Host(
        "192.0.2.1",
        services=(
            schema.Service(
                80,
                "tcp",
                "http",
                cpe="cpe:2.3:a:synthetic_vendor:synthetic_product:1:*:*:*:*:*:*:*",
                banner="synthetic observed banner",
            ),
        ),
    )
    values, evidence = role_model.extract_features(host)
    assert values["cpe_vendor=synthetic_vendor"] == 1
    assert values["cpe_product=synthetic_product"] == 1
    assert evidence["cpe_product=synthetic_product"] == "synthetic observed banner"


@pytest.mark.parametrize("operation", ["calibrate", "evaluate"])
@pytest.mark.parametrize("mode", ["empty", "unknown_class"])
def test_model_metrics_require_compatible_labelled_data(operation, mode):
    rows = examples("synthetic-edge", per_class=2)
    model = role_model.train(rows, epochs=1)
    data = [] if mode == "empty" else [replace(rows[0], label="mail")]
    with pytest.raises(ConfigError, match="validation set|labelled hosts|absent from"):
        getattr(role_model, operation)(model, data)


def test_cross_validation_requires_independent_groups_per_role():
    with pytest.raises(ConfigError, match="independent groups"):
        role_model.cross_validate(examples("synthetic-one-group", per_class=1), epochs=1)
