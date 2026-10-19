"""Fail-closed governance for learned role inference.

A valid manifest can produce a hybrid recommendation. It does not mutate a
ContextProfile or authorize model-derived scoring by itself.
"""

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from vulnassess.audit import load_json_payload
from vulnassess.errors import ConfigError
from vulnassess.role_model import PREPROCESSING_VERSION, RoleModel, RolePrediction
from vulnassess.schema import Feature

MANIFEST_SCHEMA_VERSION = 1
MODEL_POLICY_VERSION = "role-promotion-v1"
MIN_ROLE_ACCURACY = 0.85
MIN_COVERAGE = 0.80
MAX_ECE = 0.10
MIN_TEST_GROUPS = 3
MIN_PREDICTION_CONFIDENCE = 0.55
MIN_PREDICTION_MARGIN = 0.10
MAX_RULE_CONFIDENCE_FOR_MODEL_CANDIDATE = 0.50
SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class PromotionManifest:
    model_hash: str
    preprocessing_version: str
    test_dataset_hash: str
    test_evidence_status: str
    label_source: str
    groups_disjoint: bool
    manual_tags_used: bool
    test_groups: int
    metrics: dict[str, float]
    thresholds: dict[str, float]
    reviewer: str
    approval_id: str
    mentor_approval_id: str
    issued_on: str
    expires_on: str
    schema_version: int = MANIFEST_SCHEMA_VERSION
    policy_version: str = MODEL_POLICY_VERSION

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {MANIFEST_SCHEMA_VERSION}")
        for field_name in (
            "policy_version",
            "model_hash",
            "preprocessing_version",
            "test_dataset_hash",
            "test_evidence_status",
            "label_source",
            "reviewer",
            "approval_id",
            "mentor_approval_id",
            "issued_on",
            "expires_on",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} is required and must be non-empty text")
        if self.policy_version != MODEL_POLICY_VERSION:
            raise ValueError(f"policy_version must be {MODEL_POLICY_VERSION!r}")
        if not SHA256.fullmatch(self.test_dataset_hash):
            raise ValueError("test_dataset_hash must be a lowercase SHA-256")
        for field_name in ("groups_disjoint", "manual_tags_used"):
            if type(getattr(self, field_name)) is not bool:
                raise ValueError(f"{field_name} must be a boolean")
        if type(self.test_groups) is not int:
            raise ValueError("test_groups must be an integer")
        if self.test_groups < 0:
            raise ValueError("test_groups must not be negative")
        for name, values in (("metrics", self.metrics), ("thresholds", self.thresholds)):
            if not isinstance(values, dict):
                raise ValueError(f"{name} must be an object")
            for key, value in values.items():
                if type(value) not in (int, float) or not 0 <= value <= 1:
                    raise ValueError(f"{name}.{key} must be in [0, 1]")
        try:
            issued = date.fromisoformat(self.issued_on)
            expires = date.fromisoformat(self.expires_on)
        except ValueError as error:
            raise ValueError("issued_on and expires_on must be ISO dates") from error
        if expires < issued:
            raise ValueError("expires_on precedes issued_on")

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_version": self.policy_version,
            "model_hash": self.model_hash,
            "preprocessing_version": self.preprocessing_version,
            "test_dataset_hash": self.test_dataset_hash,
            "test_evidence_status": self.test_evidence_status,
            "label_source": self.label_source,
            "groups_disjoint": self.groups_disjoint,
            "manual_tags_used": self.manual_tags_used,
            "test_groups": self.test_groups,
            "metrics": dict(self.metrics),
            "thresholds": dict(self.thresholds),
            "reviewer": self.reviewer,
            "approval_id": self.approval_id,
            "mentor_approval_id": self.mentor_approval_id,
            "issued_on": self.issued_on,
            "expires_on": self.expires_on,
        }


@dataclass(frozen=True)
class HybridRecommendation:
    action: str
    selected_label: str
    selected_source: str
    reason: str
    rule_label: str
    rule_confidence: float
    model_label: str
    model_confidence: float
    model_margin: float
    model_hash: str
    manifest_approval_id: str

    def to_json(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "selected_label": self.selected_label,
            "selected_source": self.selected_source,
            "reason": self.reason,
            "rule_label": self.rule_label,
            "rule_confidence": self.rule_confidence,
            "model_label": self.model_label,
            "model_confidence": self.model_confidence,
            "model_margin": self.model_margin,
            "model_hash": self.model_hash,
            "manifest_approval_id": self.manifest_approval_id,
        }


def load_manifest(path: str | Path) -> PromotionManifest:
    path = Path(path)
    payload = load_json_payload(path, "role-model promotion manifest")
    if not isinstance(payload, dict):
        raise ConfigError(f"invalid role-model promotion manifest {path}: expected an object")
    allowed = {
        "schema_version",
        "policy_version",
        "model_hash",
        "preprocessing_version",
        "test_dataset_hash",
        "test_evidence_status",
        "label_source",
        "groups_disjoint",
        "manual_tags_used",
        "test_groups",
        "metrics",
        "thresholds",
        "reviewer",
        "approval_id",
        "mentor_approval_id",
        "issued_on",
        "expires_on",
    }
    extra = sorted(set(payload) - allowed)
    if extra:
        raise ConfigError(f"invalid promotion manifest {path}: unknown key {extra[0]!r}")
    try:
        return PromotionManifest(
            schema_version=payload["schema_version"],
            policy_version=payload["policy_version"],
            model_hash=payload["model_hash"],
            preprocessing_version=payload["preprocessing_version"],
            test_dataset_hash=payload["test_dataset_hash"],
            test_evidence_status=payload["test_evidence_status"],
            label_source=payload["label_source"],
            groups_disjoint=payload["groups_disjoint"],
            manual_tags_used=payload["manual_tags_used"],
            test_groups=payload["test_groups"],
            metrics=payload["metrics"],
            thresholds=payload["thresholds"],
            reviewer=payload["reviewer"],
            approval_id=payload["approval_id"],
            mentor_approval_id=payload["mentor_approval_id"],
            issued_on=payload["issued_on"],
            expires_on=payload["expires_on"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigError(f"invalid role-model promotion manifest {path}: {error}") from error


def validate_promotion(
    model: RoleModel,
    manifest: PromotionManifest,
    *,
    as_of: date,
) -> dict[str, Any]:
    failures: list[str] = []
    if manifest.model_hash != model.model_hash:
        failures.append("manifest model_hash does not match the artifact")
    if manifest.preprocessing_version != PREPROCESSING_VERSION:
        failures.append("manifest preprocessing_version is unsupported")
    if model.training.get("preprocessing_version") != PREPROCESSING_VERSION:
        failures.append("artifact preprocessing_version is unsupported")
    if manifest.test_evidence_status != "VERIFIED":
        failures.append("test evidence status is not VERIFIED")
    if manifest.label_source != "human":
        failures.append("test labels are not human-supplied")
    if not manifest.groups_disjoint:
        failures.append("train/calibration/test groups are not declared disjoint")
    if manifest.manual_tags_used:
        failures.append("test evaluation used manual context tags")
    if manifest.test_groups < MIN_TEST_GROUPS:
        failures.append(f"test set has fewer than {MIN_TEST_GROUPS} independent groups")
    if manifest.test_dataset_hash == model.training.get("dataset_hash"):
        failures.append("test dataset hash equals the training dataset hash")

    required_thresholds = {
        "minimum_role_accuracy": (MIN_ROLE_ACCURACY, "minimum"),
        "minimum_coverage": (MIN_COVERAGE, "minimum"),
        "maximum_ece": (MAX_ECE, "maximum"),
        "prediction_confidence": (MIN_PREDICTION_CONFIDENCE, "minimum"),
        "prediction_margin": (MIN_PREDICTION_MARGIN, "minimum"),
    }
    for key, (policy, direction) in required_thresholds.items():
        value = manifest.thresholds.get(key)
        if value is None:
            failures.append(f"threshold {key!r} is missing")
        elif direction == "minimum" and value < policy:
            failures.append(f"threshold {key!r} weakens policy minimum {policy}")
        elif direction == "maximum" and value > policy:
            failures.append(f"threshold {key!r} weakens policy maximum {policy}")

    checks = (
        ("role_accuracy", "minimum_role_accuracy", lambda value, threshold: value >= threshold),
        ("coverage", "minimum_coverage", lambda value, threshold: value >= threshold),
        ("expected_calibration_error", "maximum_ece", lambda value, threshold: value <= threshold),
    )
    for metric, threshold, passes in checks:
        value = manifest.metrics.get(metric)
        target = manifest.thresholds.get(threshold)
        if value is None:
            failures.append(f"metric {metric!r} is missing")
        elif target is not None and not passes(value, target):
            failures.append(f"metric {metric!r}={value} misses threshold {target}")

    try:
        issued = date.fromisoformat(manifest.issued_on)
        expires = date.fromisoformat(manifest.expires_on)
    except ValueError:
        failures.append("manifest validity dates are invalid")
    else:
        if as_of < issued:
            failures.append("manifest is not yet valid")
        if as_of > expires:
            failures.append("manifest has expired")

    if failures:
        raise ConfigError("role-model promotion denied: " + "; ".join(failures))
    return {
        "authorized": True,
        "policy_version": MODEL_POLICY_VERSION,
        "model_hash": model.model_hash,
        "test_dataset_hash": manifest.test_dataset_hash,
        "approval_id": manifest.approval_id,
        "mentor_approval_id": manifest.mentor_approval_id,
        "valid_as_of": as_of.isoformat(),
    }


def recommend_hybrid_role(
    rule_role: Feature,
    prediction: RolePrediction,
    model: RoleModel,
    manifest: PromotionManifest,
    *,
    as_of: date,
) -> HybridRecommendation:
    """Recommend a source without changing a canonical context profile."""
    validate_promotion(model, manifest, as_of=as_of)
    if prediction.model_hash != model.model_hash:
        raise ConfigError("role prediction model hash does not match the promoted artifact")
    rule_label = str(rule_role.value)
    strong_rule = (
        rule_label != "unknown" and rule_role.confidence > MAX_RULE_CONFIDENCE_FOR_MODEL_CANDIDATE
    )
    confidence = manifest.thresholds["prediction_confidence"]
    margin = manifest.thresholds["prediction_margin"]

    if prediction.abstained:
        action = "keep_rule_model_abstained"
        selected_label = rule_label
        selected_source = "rule"
        reason = "model abstained"
    elif prediction.confidence < confidence or prediction.margin < margin:
        action = "keep_rule_model_below_threshold"
        selected_label = rule_label
        selected_source = "rule"
        reason = "model confidence or margin is below the approved threshold"
    elif strong_rule and prediction.label != rule_label:
        action = "keep_rule_conflict_requires_review"
        selected_label = rule_label
        selected_source = "rule"
        reason = "strong rule and model disagree; no automatic override"
    elif strong_rule:
        action = "keep_rule_agreement"
        selected_label = rule_label
        selected_source = "rule"
        reason = "strong rule and model agree"
    else:
        action = "model_candidate_requires_context_adr"
        selected_label = prediction.label
        selected_source = "model_candidate"
        reason = (
            "approved model resolves an unknown or low-confidence rule result, but canonical "
            "activation still requires the context-source ADR"
        )
    return HybridRecommendation(
        action=action,
        selected_label=selected_label,
        selected_source=selected_source,
        reason=reason,
        rule_label=rule_label,
        rule_confidence=rule_role.confidence,
        model_label=prediction.label,
        model_confidence=prediction.confidence,
        model_margin=prediction.margin,
        model_hash=model.model_hash,
        manifest_approval_id=manifest.approval_id,
    )
