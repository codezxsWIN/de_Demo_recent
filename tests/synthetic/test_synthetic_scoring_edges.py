"""Synthetic scoring inputs exercise rejection and deterministic fallbacks."""

import copy
from dataclasses import replace

import pytest

from tests.test_all import BASE_VECTOR, WEIGHTS, make_enrichment, make_finding, make_profile
from vulnassess import context, cvss31, scoring
from vulnassess.errors import IntelUnavailable
from vulnassess.schema import Feature, Host, Service


@pytest.mark.parametrize("metric", ["AV:N", "AV:P", "PR:H", "C:N"])
def test_duplicate_base_metrics_are_rejected_instead_of_silently_overriding_scores(metric):
    with pytest.raises(ValueError, match="duplicate metric"):
        cvss31.parse(f"{BASE_VECTOR}/{metric}")


def test_duplicate_environmental_metric_cannot_silently_override_context():
    with pytest.raises(ValueError, match="duplicate metric"):
        cvss31.parse(f"{BASE_VECTOR}/MAV:N/MAV:P")


@pytest.mark.parametrize(
    "vector,message",
    [
        (BASE_VECTOR + "/broken", "malformed metric"),
        (BASE_VECTOR + "/UNKNOWN:N", "unknown metric"),
        (BASE_VECTOR.replace("AV:N", "AV:unknown"), "invalid value"),
        ("CVSS:3.1/AV:N", "missing base metric"),
    ],
)
def test_invalid_vectors_are_rejected_before_scoring(vector, message):
    with pytest.raises(ValueError, match=message):
        cvss31.parse(vector)


@pytest.mark.parametrize("criticality", [None, "invalid", {}, []])
def test_malformed_manual_criticality_cannot_change_environmental_requirements(criticality):
    profile = make_profile()
    malformed = replace(
        profile,
        manual={"criticality": Feature(criticality, 1.0, "manual", "synthetic malformed import")},
    )
    assert scoring.environmental_vector(
        BASE_VECTOR, malformed, WEIGHTS
    ) == scoring.environmental_vector(BASE_VECTOR, profile, WEIGHTS)


def test_criticality_steps_saturate_requirements_and_do_not_mutate_inputs():
    weights = copy.deepcopy(WEIGHTS)
    profile = make_profile(role="iot_embedded", criticality=5)
    vector, modifications = scoring.environmental_vector(BASE_VECTOR, profile, weights)
    assert {key: modifications[key] for key in ("CR", "IR", "AR")} == {
        "CR": "H",
        "IR": "H",
        "AR": "H",
    }
    assert cvss31.parse(vector)["MAV"] == "A"
    assert weights == WEIGHTS


@pytest.mark.parametrize("fallback", [None, {}])
def test_no_native_weight_rejects_an_unsupported_priority_without_fabricating_cvss(fallback):
    finding = make_finding(cve_ids=[])
    weights = {**WEIGHTS, "native_fallback": fallback}
    original = finding.to_json()
    with pytest.raises(IntelUnavailable, match="no priority or Low band was assigned"):
        scoring.score(finding, None, make_profile(), (), weights)
    assert finding.to_json() == original
    assert weights == {**WEIGHTS, "native_fallback": fallback}


@pytest.mark.parametrize("severity", [None, "unrecognized"])
def test_unrecognized_native_severity_does_not_select_a_minimum_weight(severity):
    finding = make_finding(tool="nessus", native_severity=severity, cve_ids=[])
    original = finding.to_json()
    with pytest.raises(IntelUnavailable, match="native_fallback.nessus"):
        scoring.score(finding, None, make_profile(), (), WEIGHTS)
    assert finding.to_json() == original
    assert finding.cve_ids == ()


def test_low_epss_reason_uses_percentile_without_claiming_active_exploitation():
    finding = make_finding()
    result = scoring.score(
        finding,
        make_enrichment(finding_id=finding.id, kev=False, epss_percentile=0.12),
        make_profile(),
        (),
        WEIGHTS,
    )
    assert "EPSS relative ranking: 12th percentile" in result.reason
    assert "likelihood" not in result.reason
    assert "actively exploited" not in result.reason


@pytest.mark.parametrize(
    "rule", [{"match": "port"}, {"match": "service"}, {"match": "unsupported", "regex": "http"}]
)
def test_incomplete_or_unknown_role_rules_cannot_manufacture_context(rule):
    host = Host(ip="127.0.0.1", services=(Service(port=80, protocol="tcp", name="http"),))
    feature = context.infer_role(host, {"roles": {"database": [{**rule, "weight": 1.0}]}})
    assert feature.value == "unknown"
    assert feature.evidence == "none observed"
