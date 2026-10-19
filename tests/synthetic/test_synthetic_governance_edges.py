"""Synthetic promotion manifests exercise policy gates, not real model approval."""

import json
from dataclasses import replace
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_assessment_snapshot import ROOT
from vulnassess import model_governance as governance
from vulnassess.errors import ConfigError
from vulnassess.role_model import PREPROCESSING_VERSION, load_model
from vulnassess.schema import Feature, Host


@pytest.fixture
def promoted():
    model = load_model(ROOT / "models/synthetic-role-model.json")
    manifest = governance.PromotionManifest(
        model_hash=model.model_hash,
        preprocessing_version=PREPROCESSING_VERSION,
        test_dataset_hash="a" * 64,
        test_evidence_status="VERIFIED",
        label_source="human",
        groups_disjoint=True,
        manual_tags_used=False,
        test_groups=4,
        metrics={"role_accuracy": 0.9, "coverage": 0.9, "expected_calibration_error": 0.05},
        thresholds={
            "minimum_role_accuracy": 0.85,
            "minimum_coverage": 0.8,
            "maximum_ece": 0.1,
            "prediction_confidence": 0.55,
            "prediction_margin": 0.1,
        },
        reviewer="synthetic-policy-test",
        approval_id="synthetic-only",
        mentor_approval_id="synthetic-only",
        issued_on="2026-10-01",
        expires_on="2026-10-31",
    )
    return model, manifest


@pytest.mark.parametrize(
    "field,value",
    [
        ("groups_disjoint", "false"),
        ("groups_disjoint", 1),
        ("manual_tags_used", "false"),
        ("manual_tags_used", None),
        ("test_groups", 3.9),
        ("test_groups", "4"),
        ("schema_version", True),
        ("reviewer", None),
        ("approval_id", []),
        ("mentor_approval_id", 42),
        ("metrics", []),
        ("thresholds", None),
        ("metrics", {"role_accuracy": True}),
        ("metrics", {"role_accuracy": "0.9"}),
    ],
)
def test_manifest_loader_must_not_coerce_malformed_approval_data(promoted, tmp_path, field, value):
    payload = promoted[1].to_json()
    payload[field] = value
    path = tmp_path / "synthetic_promotion.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ConfigError, match="invalid.*promotion manifest"):
        governance.load_manifest(path)


@pytest.mark.parametrize(
    "mutation,message",
    [
        ("artifact_preprocessing", "artifact preprocessing"),
        ("synthetic_labels", "human-supplied"),
        ("too_few_groups", "independent groups"),
        ("missing_threshold", "threshold.*missing"),
        ("weak_maximum", "weakens policy maximum"),
        ("missing_metric", "metric.*missing"),
    ],
)
def test_policy_rejects_incomplete_or_weakened_evaluation(promoted, mutation, message):
    model, manifest = promoted
    if mutation == "artifact_preprocessing":
        model = replace(
            model, training={**model.training, "preprocessing_version": "synthetic-unsupported"}
        )
        manifest = replace(manifest, model_hash=model.model_hash)
    elif mutation == "synthetic_labels":
        manifest = replace(manifest, label_source="synthetic")
    elif mutation == "too_few_groups":
        manifest = replace(manifest, test_groups=2)
    elif mutation == "missing_threshold":
        manifest = replace(manifest, thresholds={})
    elif mutation == "weak_maximum":
        manifest = replace(manifest, thresholds={**manifest.thresholds, "maximum_ece": 0.5})
    else:
        manifest = replace(manifest, metrics={})
    with pytest.raises(ConfigError, match=message):
        governance.validate_promotion(model, manifest, as_of=date(2026, 10, 11))


@pytest.mark.parametrize("mutation", ["hash", "confidence", "margin"])
def test_hybrid_recommendation_never_trusts_mismatched_or_weak_prediction(promoted, mutation):
    model, manifest = promoted
    prediction = replace(
        model.predict(Host("192.0.2.1")),
        label="web_frontend",
        abstained=False,
        confidence=0.9,
        margin=0.5,
    )
    rule = Feature("database", 0.2, "rule", "synthetic evidence")
    if mutation == "hash":
        prediction = replace(prediction, model_hash="wrong")
        with pytest.raises(ConfigError, match="model hash"):
            governance.recommend_hybrid_role(
                rule, prediction, model, manifest, as_of=date(2026, 10, 11)
            )
    else:
        prediction = replace(prediction, **{mutation: 0.01})
        result = governance.recommend_hybrid_role(
            rule, prediction, model, manifest, as_of=date(2026, 10, 11)
        )
        assert result.action == "keep_rule_model_below_threshold"
        assert result.selected_source == "rule"
        assert result.selected_label == "database"
    assert rule.value == "database"


def test_missing_promotion_file_never_grants_approval(tmp_path):
    with pytest.raises(ConfigError, match="MISSING"):
        governance.load_manifest(tmp_path / "synthetic_missing.json")


def test_unreadable_manifest_is_controlled_configuration_failure(promoted, tmp_path, monkeypatch):
    path = tmp_path / "synthetic_manifest.json"
    path.write_text(json.dumps(promoted[1].to_json()))
    monkeypatch.setattr(Path, "open", Mock(side_effect=PermissionError("synthetic")))
    with pytest.raises(ConfigError, match="invalid role-model promotion manifest"):
        governance.load_manifest(path)


def test_policy_rechecks_dates_at_the_validation_boundary(promoted):
    model, manifest = promoted
    decoded = SimpleNamespace(**manifest.to_json())
    decoded.issued_on = "synthetic-invalid-date"
    with pytest.raises(ConfigError, match="validity dates are invalid"):
        governance.validate_promotion(model, decoded, as_of=date(2026, 10, 12))


def test_strong_rule_and_model_agreement_keeps_canonical_rule(promoted):
    model, manifest = promoted
    prediction = replace(
        model.predict(Host("192.0.2.1")),
        label="database",
        abstained=False,
        confidence=0.9,
        margin=0.5,
    )
    rule = Feature("database", 0.9, "rule", "synthetic database service")
    result = governance.recommend_hybrid_role(
        rule, prediction, model, manifest, as_of=date(2026, 10, 12)
    )
    assert result.action == "keep_rule_agreement"
    assert result.selected_source == "rule"
    assert result.selected_label == rule.value
