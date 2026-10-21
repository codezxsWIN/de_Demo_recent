"""Report-only priority traces: retained facts and policy replay remain distinct."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from vulnassess.priority_trace import priority_trace
from vulnassess.scoring import risk, weights_hash


def test_download_and_browser_use_identical_scoring_policy(tmp_path, redis, weights):
    from tests.test_assessment_report import setup_report
    from tests.test_finding_assurance import finding
    from vulnassess import capture_history
    from vulnassess.ui import assessment_report

    _, directory = setup_report(tmp_path, ai=False)
    record = capture_history.load(directory.parent, directory.name)
    observed = finding()
    record["payload"]["findings"] = [observed]
    record["payload"]["scores"] = [{**redis, "finding_id": observed["id"], "band": "Critical"}]
    before = deepcopy(record)
    browser = assessment_report.render(record, policy=weights)
    download = assessment_report.render(record, standalone=True, policy=weights)
    assert "Trace: verified" in browser and "Trace: verified" in download
    assert "91 + 10 = 101" in browser and "91 + 10 = 101" in download
    assert record == before


@pytest.fixture
def weights():
    return yaml.safe_load((Path(__file__).parents[1] / "config" / "weights.yaml").read_text())


@pytest.fixture
def redis(weights):
    # Retained Redis example: probability .99351 is distinct from percentile .9994.
    return {
        "cvss_version_used": "3.1",
        "native_fallback": None,
        "base_score": 9.8,
        "env_score": 9.1,
        "env_modifications": {"CR": "L", "IR": "L", "AR": "L"},
        "epss_percentile": 0.9994,
        "epss": 0.99351,
        "threat_multiplier": 1.0,
        "kev": True,
        "risk": 100.0,
        "weights_hash": weights_hash(weights),
        "inputs": {
            "role": {"value": "database", "confidence": 1.0},
            "exposure": {"value": "internet_facing", "confidence": 1.0},
            "manual": {"environment": {"value": "test"}},
            "control_applicability": {
                "waf": {
                    "status": "withheld",
                    "reason_code": "web_control_not_applicable_to_affected_service",
                },
            },
        },
    }


def by_label(trace):
    return {step["label"]: step for step in trace["steps"]}


def replay(row, weights, *, env=9.1, percentile=0.9994, kev=True, internet=True):
    row.update(
        env_score=env, epss_percentile=percentile, kev=kev, weights_hash=weights_hash(weights)
    )
    row["inputs"]["exposure"]["value"] = "internet_facing" if internet else "internal"
    row["risk"], row["threat_multiplier"] = risk(env, percentile, kev, None, weights, internet)
    return row


def test_redis_arithmetic_and_context_are_explained_without_mutation(redis, weights):
    before = deepcopy((redis, weights))
    trace = priority_trace(redis, weights)
    assert (redis, weights) == before
    assert trace["status"] == "verified"
    assert trace["matched_hash"] is True
    assert trace["computed_risk"] == 100
    steps = by_label(trace)
    assert steps["EPSS percentile"]["value"] == 0.9994
    assert "not exploit probability" in steps["EPSS percentile"]["detail"]
    assert steps["EPSS multiplier"]["value"] == 0.9997
    assert steps["KEV multiplier minimum"]["value"] == 1
    assert steps["Scale to priority"]["value"] == 91
    assert steps["Threat adjusted priority"]["value"] == 91
    assert steps["KEV boost"]["value"] == 101
    assert "91 + 10 = 101" in steps["KEV boost"]["detail"]
    assert steps["Internet-facing KEV floor"]["value"] == 101
    assert "90" in steps["Internet-facing KEV floor"]["detail"]
    assert "nonbinding" in steps["Internet-facing KEV floor"]["detail"]
    assert steps["Priority cap"]["value"] == 100
    assert "binding" in steps["Priority cap"]["detail"]
    assert steps["Control: waf"]["value"] == "withheld"
    assert "no score reduction" in steps["Control: waf"]["detail"]
    assert (
        "Configured database role: CR=H, IR=H, AR=H" in steps["Test environment override"]["detail"]
    )
    assert (
        "overrides role requirements with CR=L, IR=L, AR=L"
        in steps["Test environment override"]["detail"]
    )
    assert "no numeric role bonus" in steps["Test environment override"]["detail"]
    assert "0.99351" not in json.dumps(trace)
    json.dumps(trace, allow_nan=False)


@pytest.mark.parametrize("supplied", ["absent", "changed", "only_threat"])
def test_no_matching_policy_only_returns_retained_values(redis, weights, supplied):
    policy = deepcopy(weights)
    if supplied == "absent":
        policy = None
    elif supplied == "changed":
        policy["threat"]["kev_boost"] = 0
    else:
        policy = {"threat": weights["threat"]}
    trace = priority_trace(redis, policy)
    assert trace["status"] == "retained_only"
    assert trace["reason"]
    assert trace["matched_hash"] is False
    assert "computed_risk" not in trace
    assert "KEV boost" not in by_label(trace)
    assert by_label(trace)["Retained risk"]["value"] == 100


@pytest.mark.parametrize(
    "env,percentile,kev,internet,expected,multiplier",
    [
        (9.1, 0.9994, True, True, 100, 1),
        (1, 0, True, True, 90, 1),
        (1, 0, True, False, 20, 1),
        (0, 0, False, True, 0, 0.5),
        (9.1, 0, False, True, 45.5, 0.5),
        (9.1, None, False, True, 91, None),
        (9.1, None, True, True, 100, 1),
        (0, None, True, False, 10, 1),
        (0, None, False, False, 0, None),
        (8, 1, True, True, 90, 1),
        (9, 1, True, True, 100, 1),
        (10, 1, False, True, 100, 1),
        (1.23, 0.1234, False, False, 6.9, 0.5617),
    ],
)
def test_boundaries_and_missing_epss(
    redis, weights, env, percentile, kev, internet, expected, multiplier
):
    replay(redis, weights, env=env, percentile=percentile, kev=kev, internet=internet)
    trace = priority_trace(redis, weights)
    assert trace["status"] == "verified", trace
    assert trace["computed_risk"] == expected
    assert by_label(trace)["Retained threat multiplier"]["value"] == multiplier
    steps = by_label(trace)
    if percentile is None:
        assert steps["EPSS multiplier"]["value"] is None
        assert "missing" in steps["EPSS multiplier"]["detail"]
    if kev and internet:
        assert ("nonbinding" not in steps["Internet-facing KEV floor"]["detail"]) == (
            env * multiplier * 10 + weights["threat"]["kev_boost"] < 90
        )


def test_policy_coefficients_are_supplied_not_hardcoded(redis, weights):
    weights["threat"].update(
        base_multiplier=0.2,
        epss_weight=0.3,
        kev_multiplier=0.6,
        kev_boost=7,
        kev_floor_internet_facing=35,
    )
    replay(redis, weights, env=4, percentile=0.5)
    trace = priority_trace(redis, weights)
    assert trace["status"] == "verified"
    assert trace["computed_risk"] == 35
    steps = by_label(trace)
    assert steps["EPSS multiplier"]["value"] == 0.35
    assert steps["KEV multiplier minimum"]["value"] == 0.6
    assert steps["KEV boost"]["value"] == 31


@pytest.mark.parametrize("field", ["risk", "threat_multiplier"])
def test_matching_hash_does_not_verify_inconsistent_retained_arithmetic(redis, weights, field):
    redis[field] = 0.1
    before = deepcopy(redis)
    trace = priority_trace(redis, weights)
    assert trace["status"] == "unavailable"
    assert field in trace["reason"]
    assert trace["matched_hash"] is True
    assert trace["steps"] == []
    assert "computed_risk" not in trace
    assert redis == before


@pytest.mark.parametrize(
    "field",
    [
        "cvss_version_used",
        "native_fallback",
        "env_score",
        "env_modifications",
        "epss_percentile",
        "threat_multiplier",
        "kev",
        "risk",
        "weights_hash",
        "inputs",
    ],
)
def test_missing_fields_do_not_get_defaults(redis, weights, field):
    del redis[field]
    trace = priority_trace(redis, weights)
    assert trace["status"] == "unavailable"
    assert field in trace["reason"]
    assert "computed_risk" not in trace


@pytest.mark.parametrize(
    "value", [True, False, "0.5", float("nan"), float("inf"), float("-inf"), -1, 10**1000]
)
@pytest.mark.parametrize(
    "field", ["env_score", "epss_percentile", "threat_multiplier", "risk", "base_score", "epss"]
)
def test_invalid_numeric_score_inputs_are_unavailable(redis, weights, field, value):
    redis[field] = value
    trace = priority_trace(redis, weights)
    assert trace["status"] == "unavailable"
    assert field in trace["reason"]
    assert "computed_risk" not in trace
    json.dumps(trace, allow_nan=False)


@pytest.mark.parametrize(
    "field,maximum",
    [("env_score", 10), ("epss_percentile", 1), ("threat_multiplier", 1), ("risk", 100)],
)
def test_out_of_range_values_are_unavailable(redis, weights, field, maximum):
    redis[field] = maximum + 0.1
    assert priority_trace(redis, weights)["status"] == "unavailable"


@pytest.mark.parametrize(
    "field",
    ["base_multiplier", "epss_weight", "kev_multiplier", "kev_boost", "kev_floor_internet_facing"],
)
@pytest.mark.parametrize("value", [True, "0.5", float("nan"), float("inf"), -1, None])
def test_matching_hash_does_not_allow_invalid_policy_arithmetic(redis, weights, field, value):
    weights["threat"][field] = value
    redis["weights_hash"] = weights_hash(weights)
    trace = priority_trace(redis, weights)
    assert trace["status"] == "unavailable"
    assert trace["matched_hash"] is True
    assert field in trace["reason"]
    assert "computed_risk" not in trace


@pytest.mark.parametrize("policy_change", ["missing", "too_large", "kev_minimum", "version"])
def test_unsupported_policy_is_unavailable(redis, weights, policy_change):
    if policy_change == "missing":
        del weights["threat"]["kev_boost"]
    elif policy_change == "too_large":
        weights["threat"]["epss_weight"] = 0.6
    elif policy_change == "kev_minimum":
        weights["threat"]["kev_multiplier"] = 0.1
    else:
        weights["version"] = 2
    redis["weights_hash"] = weights_hash(weights)
    assert priority_trace(redis, weights)["status"] == "unavailable"


@pytest.mark.parametrize("policy_supplied", [True, False])
def test_native_fallback_never_fabricates_environmental_trace(redis, weights, policy_supplied):
    redis.update(cvss_version_used=None, env_score=None, native_fallback="nmap:default=25")
    trace = priority_trace(redis, weights if policy_supplied else None)
    assert trace["status"] == "unavailable"
    assert "Native fallback" in trace["reason"]
    assert trace["steps"] == []
    assert "computed_risk" not in trace


@pytest.mark.parametrize("change", ["version", "exposure", "kev", "modifier", "controls"])
def test_malformed_retained_context_is_unavailable(redis, weights, change):
    if change == "version":
        redis["cvss_version_used"] = "4.0"
    elif change == "exposure":
        redis["inputs"]["exposure"] = {}
    elif change == "kev":
        redis["kev"] = 1
    elif change == "modifier":
        redis["env_modifications"]["CR"] = True
    else:
        redis["inputs"]["control_applicability"]["waf"].pop("status")
    assert priority_trace(redis, weights)["status"] == "unavailable"


def test_malformed_root_inputs_return_simple_json(redis):
    for score in (None, [], True):
        assert priority_trace(score)["status"] == "unavailable"
    assert priority_trace(redis, [])["status"] == "unavailable"


def test_output_has_no_mutable_aliases_to_inputs(redis, weights):
    before = deepcopy((redis, weights))
    trace = priority_trace(redis, weights)
    trace["steps"][0]["value"] = 0
    trace["steps"].clear()
    assert (redis, weights) == before


def test_environmental_explanation_uses_supplied_mappings(redis, weights):
    weights["environmental"]["role_requirements"]["database"] = dict(CR="M", IR="L", AR="M")
    weights["environmental"]["environment_test"] = dict(CR="H", IR="M", AR="L")
    redis["weights_hash"] = weights_hash(weights)
    trace = priority_trace(redis, weights)
    assert trace["status"] == "verified"
    detail = by_label(trace)["Test environment override"]["detail"]
    assert "Configured database role: CR=M, IR=L, AR=M" in detail
    assert "overrides role requirements with CR=H, IR=M, AR=L" in detail
    assert "Environmental derivation is not replayed" in detail


def test_retained_zero_multiplier_is_not_treated_as_missing(redis, weights):
    weights["threat"].update(base_multiplier=0, epss_weight=0, kev_multiplier=0)
    replay(redis, weights, percentile=0, kev=False)
    trace = priority_trace(redis, weights)
    assert trace["status"] == "verified"
    assert trace["computed_risk"] == 0
    assert by_label(trace)["EPSS multiplier"]["value"] == 0
    assert by_label(trace)["Threat adjusted priority"]["value"] == 0
