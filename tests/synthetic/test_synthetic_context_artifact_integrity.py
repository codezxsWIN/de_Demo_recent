"""Synthetic artifact-integrity cases, never evidence of human review or H1 accuracy."""

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from vulnassess import audit
from vulnassess.context_eval import ContextTruth, _classification, evaluate_context
from vulnassess.errors import ConfigError
from vulnassess.schema import ContextProfile, Feature


def synthetic_metrics(correct: int = 20) -> dict[str, Any]:
    return _classification(
        ["database"] * 20,
        ["database"] * correct + ["workstation"] * (20 - correct),
        ("database", "workstation"),
    )


@pytest.fixture
def synthetic_context() -> dict[str, Any]:
    # "human" and "VERIFIED" here are simulated claims for loader tests only.
    return {
        "run_id": "synthetic-context-integrity",
        "status": "VERIFIED",
        "evidence_status": "VERIFIED",
        "data_kind": "human",
        "manual_tags_used": False,
        "truth_hosts": 20,
        "truth_groups": 4,
        "missing_profile_hosts": [],
        "unlabelled_profile_hosts": [],
        "rule_role": synthetic_metrics(17),
        "model_role": synthetic_metrics(),
        "exposure": _classification(
            ["internal"] * 20,
            ["internal"] * 19 + ["internet_facing"],
            ("internal", "internet_facing"),
        ),
        "controls": {"waf": _classification([], [], ("false", "true"))},
        "rule_model_disagreements": [],
        "h1": {
            "eligible": True,
            "reason": "synthetic simulation of an eligibility claim",
            "role_target": 0.85,
            "exposure_target": 0.95,
            "role_pass": True,
            "exposure_pass": True,
        },
    }


def synthetic_write(tmp_path: Path, payload: dict[str, Any]) -> Path:
    core = {key: value for key, value in payload.items() if key != "evaluation_hash"}
    payload = {**core, "evaluation_hash": audit._digest(core)}
    path = tmp_path / "synthetic_context_integrity.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def synthetic_set(payload: dict[str, Any], field: str, value: Any) -> None:
    parts = field.split(".")
    parent = payload
    for part in parts[:-1]:
        parent = parent[part]
    parent[parts[-1]] = value


@pytest.mark.parametrize(
    "field,value",
    [
        ("manual_tags_used", True),
        ("data_kind", "synthetic"),
        ("data_kind", "machine"),
        ("missing_profile_hosts", ["192.0.2.20"]),
        ("h1.eligible", False),
        ("status", "NOT RUN"),
        ("status", "finished"),
        ("h1.role_pass", False),
        ("h1.exposure_pass", False),
        ("h1.role_pass", None),
        ("h1.exposure_pass", None),
        ("h1.role_target", 0.80),
        ("h1.exposure_target", 0.90),
        ("h1.role_target", "0.85"),
        ("h1.exposure_target", True),
        ("rule_role.accuracy", 0.8),
        ("exposure.accuracy", 0.9),
        ("rule_role.accuracy", None),
        ("exposure.accuracy", None),
        ("truth_hosts", 0),
        ("truth_hosts", -1),
        ("truth_hosts", True),
        ("truth_hosts", 20.0),
        ("truth_groups", 0),
        ("truth_groups", 21),
        ("truth_groups", -1),
        ("truth_groups", False),
        ("missing_profile_hosts", ""),
        ("missing_profile_hosts", [None]),
        ("missing_profile_hosts", ["192.0.2.1"] * 21),
        ("unlabelled_profile_hosts", 0),
        ("unlabelled_profile_hosts", [""]),
        ("unlabelled_profile_hosts", ["192.0.2.1", "192.0.2.1"]),
        ("rule_role.examples", 19),
        ("exposure.examples", 21),
        ("model_role.examples", 19),
        ("controls.waf.examples", 21),
        ("rule_role.examples", True),
        ("exposure.examples", -1),
        ("rule_role.accuracy", True),
        ("exposure.accuracy", "0.95"),
        ("rule_role.coverage", 1.1),
        ("exposure.missing_rate", -0.1),
        ("rule_role.abstention_rate", True),
        ("rule_role.missing_rate", 0.5),
        ("exposure.coverage", 0.5),
        ("rule_role.selective_accuracy", 0.5),
        ("rule_role.macro_f1", 1.1),
        ("rule_role.macro_f1", 1.0),
        ("rule_role.per_class.database.precision", 0.5),
        ("rule_role.per_class.database.recall", 1.0),
        ("rule_role.per_class.database.f1", 1.0),
        ("model_role", []),
        ("controls", []),
        ("controls.waf.accuracy", 1.0),
        ("exposure.confusion_matrix.internal.internal", 18),
        ("rule_role.confusion_matrix.database.database", True),
        ("exposure.per_class.internal.support", 19),
    ],
)
def test_synthetic_rehash_does_not_hide_context_contradictions(
    tmp_path, synthetic_context, field, value
):
    synthetic_set(synthetic_context, field, value)
    path = synthetic_write(tmp_path, synthetic_context)
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact("context", path, synthetic_context["run_id"])


@pytest.mark.parametrize(
    "field", ["manual_tags_used", "h1.eligible", "h1.role_pass", "h1.exposure_pass"]
)
@pytest.mark.parametrize("value", [0, 1, "false", "true", [], {}])
def test_synthetic_flags_require_actual_booleans(tmp_path, synthetic_context, field, value):
    synthetic_set(synthetic_context, field, value)
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact(
            "context", synthetic_write(tmp_path, synthetic_context), synthetic_context["run_id"]
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("manual_tags_used", True),
        ("data_kind", "synthetic"),
        ("missing_profile_hosts", ["192.0.2.1"]),
    ],
)
def test_synthetic_not_run_cannot_hide_ineligible_h1_claim(
    tmp_path, synthetic_context, field, value
):
    synthetic_context.update(status="NOT RUN", evidence_status="NOT RUN")
    synthetic_set(synthetic_context, field, value)
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact(
            "context", synthetic_write(tmp_path, synthetic_context), synthetic_context["run_id"]
        )


@pytest.mark.parametrize("field", ["role_pass", "exposure_pass"])
@pytest.mark.parametrize("value", [True, False])
def test_synthetic_ineligible_results_have_no_pass_or_fail(
    tmp_path, synthetic_context, field, value
):
    synthetic_context.update(status="NOT RUN", evidence_status="NOT RUN", data_kind="synthetic")
    synthetic_context["h1"].update(eligible=False, role_pass=None, exposure_pass=None)
    synthetic_context["h1"][field] = value
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact(
            "context", synthetic_write(tmp_path, synthetic_context), synthetic_context["run_id"]
        )


@pytest.mark.parametrize(
    "field",
    [
        "status",
        "data_kind",
        "manual_tags_used",
        "truth_hosts",
        "truth_groups",
        "missing_profile_hosts",
        "h1.eligible",
        "h1.role_target",
        "h1.exposure_target",
        "h1.role_pass",
        "h1.exposure_pass",
        "rule_role.examples",
        "rule_role.accuracy",
        "rule_role.coverage",
        "rule_role.abstention_rate",
        "rule_role.missing_rate",
        "exposure.examples",
        "exposure.accuracy",
        "exposure.coverage",
        "exposure.abstention_rate",
        "exposure.missing_rate",
    ],
)
def test_synthetic_verified_claims_require_relevant_facts(tmp_path, synthetic_context, field):
    parts = field.split(".")
    parent = synthetic_context
    for part in parts[:-1]:
        parent = parent[part]
    del parent[parts[-1]]
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact(
            "context", synthetic_write(tmp_path, synthetic_context), synthetic_context["run_id"]
        )


@pytest.mark.parametrize(
    "facts",
    [
        {"status": "VERIFIED"},
        {"manual_tags_used": "false"},
        {"h1": {"eligible": 0}},
        {"h1": {"eligible": None}},
        {"manual_tags_used": None},
        {"h1": {"eligible": False, "role_pass": False}},
        {"h1": {"role_pass": True}},
        {"h1": {"eligible": True, "role_pass": None}, "rule_role": {"accuracy": 0.85}},
        {"h1": {"eligible": True}, "rule_role": {"missing_rate": 0.5}},
        {"h1": {"role_target": 0.1}},
        {"truth_hosts": -1},
        {"truth_hosts": 1, "truth_groups": 2},
        {"truth_hosts": 1, "missing_profile_hosts": ["192.0.2.1", "192.0.2.2"]},
        {"missing_profile_hosts": ["192.0.2.1"], "unlabelled_profile_hosts": ["192.0.2.1"]},
        {"rule_role": {"accuracy": "1.0"}},
        {"exposure": {"accuracy": 2.0}},
        {"rule_role": {"examples": 2}, "exposure": {"examples": 3}},
        {"rule_role": {"coverage": 0.5, "abstention_rate": 0.0, "missing_rate": 0.0}},
    ],
)
def test_synthetic_sparse_not_run_still_rejects_provided_contradictions(tmp_path, facts):
    payload = {
        "run_id": "synthetic-context-integrity",
        "evidence_status": "NOT RUN",
        "rule_role": {},
        "exposure": {},
        "h1": {},
        **facts,
    }
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact("context", synthetic_write(tmp_path, payload), payload["run_id"])


@pytest.mark.parametrize(
    "metric,passed", [("rule_role", "role_pass"), ("exposure", "exposure_pass")]
)
def test_synthetic_below_target_accuracy_cannot_pass_using_model_metrics(
    tmp_path, synthetic_context, metric, passed
):
    synthetic_context[metric] = synthetic_metrics(0)
    assert synthetic_context["model_role"]["accuracy"] == 1.0
    assert synthetic_context["h1"][passed] is True
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact(
            "context", synthetic_write(tmp_path, synthetic_context), synthetic_context["run_id"]
        )


@pytest.mark.parametrize("role_correct,exposure_correct", [(17, 19), (16, 18), (0, 0), (20, 20)])
def test_synthetic_coherent_pass_and_fail_claims_round_trip(
    tmp_path, synthetic_context, role_correct, exposure_correct
):
    synthetic_context["rule_role"] = synthetic_metrics(role_correct)
    synthetic_context["exposure"] = _classification(
        ["internal"] * 20,
        ["internal"] * exposure_correct + ["internet_facing"] * (20 - exposure_correct),
        ("internal", "internet_facing"),
    )
    synthetic_context["h1"].update(
        role_pass=role_correct >= 17, exposure_pass=exposure_correct >= 19
    )
    expected = deepcopy(synthetic_context)
    result = audit.load_artifact(
        "context", synthetic_write(tmp_path, synthetic_context), synthetic_context["run_id"]
    )
    assert result.evidence_status == "VERIFIED"
    assert {
        key: value for key, value in result.payload.items() if key != "evaluation_hash"
    } == expected


@pytest.mark.parametrize("reason", ["synthetic", "manual", "missing"])
def test_synthetic_ineligible_metrics_remain_descriptive(tmp_path, synthetic_context, reason):
    synthetic_context.update(status="NOT RUN", evidence_status="NOT RUN")
    synthetic_context["h1"].update(eligible=False, role_pass=None, exposure_pass=None)
    if reason == "synthetic":
        synthetic_context["data_kind"] = "synthetic"
    elif reason == "manual":
        synthetic_context["manual_tags_used"] = True
    else:
        synthetic_context["missing_profile_hosts"] = ["192.0.2.20"]
        synthetic_context["rule_role"] = _classification(
            ["database"] * 20, ["database"] * 19 + [None], ("database", "workstation")
        )
        synthetic_context["exposure"] = _classification(
            ["internal"] * 20, ["internal"] * 19 + [None], ("internal", "internet_facing")
        )
    path = synthetic_write(tmp_path, synthetic_context)
    result = audit.load_artifact("context", path, synthetic_context["run_id"])
    assert result.evidence_status == "NOT RUN"
    assert result.payload["rule_role"] == synthetic_context["rule_role"]
    assert result.payload["h1"]["role_pass"] is None
    assert result.payload["h1"]["exposure_pass"] is None


@pytest.mark.parametrize("h1", [{}, {"eligible": False}, {"eligible": False, "role_pass": None}])
def test_synthetic_sparse_legacy_not_run_stays_unknown(tmp_path, h1):
    payload = {
        "run_id": "synthetic-context-integrity",
        "evidence_status": "NOT RUN",
        "rule_role": {},
        "exposure": {},
        "h1": h1,
    }
    result = audit.load_artifact("context", synthetic_write(tmp_path, payload), payload["run_id"])
    assert result.evidence_status == "NOT RUN"
    assert "accuracy=None" in result.summary
    assert result.payload["h1"] == h1
    assert "data_kind" not in result.payload
    assert "manual_tags_used" not in result.payload


def test_synthetic_real_evaluator_shape_remains_attachable(tmp_path):
    profile = ContextProfile(
        host_ip="192.0.2.1",
        role=Feature("database", 0.9, "rule", "synthetic role evidence"),
        exposure=Feature("internal", 0.9, "rule", "synthetic exposure evidence"),
        controls={},
        manual={},
    )
    truth = ContextTruth(
        "192.0.2.1", "synthetic-group", "database", "internal", label_source="synthetic"
    )
    payload = {**evaluate_context([profile], [truth]), "run_id": "synthetic-context-integrity"}
    result = audit.load_artifact("context", synthetic_write(tmp_path, payload), payload["run_id"])
    assert result.evidence_status == "NOT RUN"
    assert result.payload["h1"]["eligible"] is False
    assert result.payload["h1"]["role_pass"] is None


@pytest.mark.parametrize("status", ["NOT RUN", "TESTED WITH MOCKS", "MISSING"])
def test_synthetic_ineligible_evidence_status_cannot_claim_h1_ready(
    tmp_path, synthetic_context, status
):
    synthetic_context.update(status=status, evidence_status=status)
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact(
            "context", synthetic_write(tmp_path, synthetic_context), synthetic_context["run_id"]
        )


@pytest.mark.parametrize("metric", ["rule_role", "exposure"])
@pytest.mark.parametrize(
    "field", ["confusion_matrix", "per_class", "selective_accuracy", "macro_f1"]
)
def test_synthetic_verified_result_cannot_drop_published_metric_evidence(
    tmp_path, synthetic_context, metric, field
):
    del synthetic_context[metric][field]
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact(
            "context", synthetic_write(tmp_path, synthetic_context), synthetic_context["run_id"]
        )


@pytest.mark.parametrize("metric", ["rule_role", "exposure", "model_role", "controls.waf"])
def test_synthetic_classification_cannot_invent_actual_or_prediction_labels(
    tmp_path, synthetic_context, metric
):
    metrics = _classification(["invented"] * 20, ["invented"] * 20, ("invented",))
    synthetic_set(synthetic_context, metric, metrics)
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact(
            "context", synthetic_write(tmp_path, synthetic_context), synthetic_context["run_id"]
        )


def test_synthetic_per_class_cannot_disappear_under_verified_claim(tmp_path, synthetic_context):
    synthetic_context["rule_role"]["per_class"] = {}
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact(
            "context", synthetic_write(tmp_path, synthetic_context), synthetic_context["run_id"]
        )


@pytest.mark.parametrize("count", [1, 3, 7, 19, 31])
@pytest.mark.parametrize("kind", ["rule", "unknown", "manual", "missing"])
def test_synthetic_full_evaluator_output_round_trips_with_rounded_metrics(tmp_path, count, kind):
    profiles = []
    labels = []
    for index in range(count):
        host = f"192.0.2.{index + 1}"
        profile = ContextProfile(
            host_ip=host,
            role=Feature(
                "unknown" if kind == "unknown" or index % 3 == 1 else "database",
                0.9,
                "manual" if kind == "manual" else "rule",
                "SYNTHETIC declared input, not an empirical result",
            ),
            exposure=Feature("internal", 0.9, "rule", "SYNTHETIC internal observation"),
        )
        if kind != "missing" or index % 2 == 0:
            profiles.append(profile)
        labels.append(
            ContextTruth(
                host,
                f"SYNTHETIC group-{index}",
                "database",
                "internal",
                label_source="human",
                reviewer="SYNTHETIC simulated reviewer",
                provenance="SYNTHETIC contract test; no independent study",
            )
        )
    payload = {**evaluate_context(profiles, labels), "run_id": "synthetic-context-integrity"}
    result = audit.load_artifact("context", synthetic_write(tmp_path, payload), payload["run_id"])
    assert result.payload["rule_role"] == payload["rule_role"]
    assert result.payload["h1"] == payload["h1"]
