"""RQ1 evaluation for evidence-derived deployment context.

Truth is host-level and independently reviewed. Synthetic truth can exercise the
arithmetic, but is never eligible to establish H1.
"""

import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from vulnassess.errors import ConfigError
from vulnassess.role_model import ROLES, RolePrediction
from vulnassess.schema import ContextProfile, Feature

TRUTH_SCHEMA_VERSION = 1
EXPOSURES = ("internal", "internet_facing")
CONTROL_KEYS = ("waf", "auth_required", "tls", "rate_limiting")
MISSING = "__missing__"
ABSTAIN = "__abstain__"


class _DuplicateTruthKey(ValueError):
    """A truth declaration must not silently replace another declaration."""


class _TruthLoader(yaml.SafeLoader):
    pass


def _truth_mapping(loader: _TruthLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in result:
            raise _DuplicateTruthKey()
        result[key] = loader.construct_object(value_node)
    return result


_TruthLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _truth_mapping)


@dataclass(frozen=True)
class ContextTruth:
    host_ip: str
    group: str
    role: str
    exposure: str
    controls: dict[str, bool | None] = field(default_factory=dict)
    label_source: str = "human"
    reviewer: str | None = None
    provenance: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.host_ip, str) or not self.host_ip.strip():
            raise ValueError("host_ip is required")
        if not isinstance(self.group, str) or not self.group.strip():
            raise ValueError("group must identify an independent host/capture unit")
        if self.role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}, got {self.role!r}")
        if self.exposure not in EXPOSURES:
            raise ValueError(f"exposure must be one of {EXPOSURES}, got {self.exposure!r}")
        if not isinstance(self.controls, dict):
            raise ValueError("control truth must be a mapping")
        unknown = set(self.controls) - set(CONTROL_KEYS)
        if unknown:
            raise ValueError(f"unknown control truth key {min(unknown, key=repr)!r}")
        if any(value is not None and type(value) is not bool for value in self.controls.values()):
            raise ValueError("control truth values must be true, false, or null")
        if self.label_source not in ("human", "synthetic"):
            raise ValueError("label_source must be 'human' or 'synthetic'")
        if self.reviewer is not None and not isinstance(self.reviewer, str):
            raise ValueError("reviewer must be a string or null")
        if not isinstance(self.provenance, str):
            raise ValueError("provenance must be a string")
        if self.label_source == "human" and not (self.reviewer or "").strip():
            raise ValueError("human context truth requires a reviewer identifier")
        if self.label_source == "human" and not self.provenance.strip():
            raise ValueError("human context truth requires provenance")

    def to_json(self) -> dict[str, Any]:
        return {
            "host_ip": self.host_ip,
            "group": self.group,
            "role": self.role,
            "exposure": self.exposure,
            "controls": dict(self.controls),
            "label_source": self.label_source,
            "reviewer": self.reviewer,
            "provenance": self.provenance,
        }


def load_context_truth(path: str | Path) -> list[ContextTruth]:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"MISSING: host-context truth file {path}")
    try:
        payload = yaml.load(path.read_text(encoding="utf-8"), Loader=_TruthLoader)
    except _DuplicateTruthKey as error:
        raise ConfigError(f"{path}: duplicate context truth key") from error
    except (OSError, UnicodeError, yaml.YAMLError, TypeError, RecursionError) as error:
        raise ConfigError(f"{path}: unreadable context truth ({type(error).__name__})") from error
    if not isinstance(payload, dict):
        raise ConfigError(f"{path}: context truth must be a mapping")
    unknown = set(payload) - {"version", "hosts", "_comment"}
    if unknown:
        raise ConfigError(f"{path}: unknown key {min(unknown, key=repr)!r}")
    if type(payload.get("version")) is not int or payload["version"] != TRUTH_SCHEMA_VERSION:
        raise ConfigError(
            f"{path}: version must be {TRUTH_SCHEMA_VERSION}, got {payload.get('version')!r}"
        )
    comment = payload.get("_comment", "")
    if not isinstance(comment, str):
        raise ConfigError(f"{path}: _comment must be a string")
    synthetic_document = "synthetic" in comment.casefold()
    rows = payload.get("hosts")
    if not isinstance(rows, list) or not rows:
        raise ConfigError(f"{path}: key 'hosts' must be a non-empty list")

    truth: list[ContextTruth] = []
    seen: set[str] = set()
    allowed = {
        "host_ip",
        "group",
        "role",
        "exposure",
        "controls",
        "label_source",
        "reviewer",
        "provenance",
    }
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ConfigError(f"{path}: hosts[{index}] must be a mapping")
        extra = set(row) - allowed
        if extra:
            raise ConfigError(f"{path}: unknown key 'hosts[{index}].{min(extra, key=repr)}'")
        try:
            item = ContextTruth(
                host_ip=row["host_ip"],
                group=row["group"],
                role=row["role"],
                exposure=row["exposure"],
                controls=row.get("controls", {}),
                label_source=row.get("label_source", "human"),
                reviewer=row.get("reviewer"),
                provenance=row.get("provenance", ""),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ConfigError(f"{path}: invalid hosts[{index}]: {error}") from error
        if synthetic_document:
            item = replace(item, label_source="synthetic")
        if item.host_ip in seen:
            raise ConfigError(f"{path}: host {item.host_ip!r} is labelled more than once")
        seen.add(item.host_ip)
        truth.append(item)
    return truth


def _classification(
    actual: Sequence[str],
    predicted: Sequence[str | None],
    classes: Sequence[str],
    abstained: Sequence[bool] | None = None,
) -> dict[str, Any]:
    if len(actual) != len(predicted):
        raise ValueError("actual and predicted lengths differ")
    flags = list(abstained or [False] * len(actual))
    if len(flags) != len(actual):
        raise ValueError("abstention flags and labels differ")
    labels = tuple(sorted(set(classes) | set(actual)))
    columns = (*labels, ABSTAIN, MISSING)
    matrix = {label: {column: 0 for column in columns} for label in labels}
    covered = 0
    correct = 0
    for truth, prediction, did_abstain in zip(actual, predicted, flags, strict=True):
        if prediction is None:
            column = MISSING
        elif did_abstain:
            column = ABSTAIN
        else:
            column = prediction
            covered += 1
            correct += prediction == truth
        if column not in matrix[truth]:
            matrix[truth][column] = 0
        matrix[truth][column] += 1

    per_class: dict[str, dict[str, float | int]] = {}
    f1_values: list[float] = []
    for label in labels:
        support = sum(value == label for value in actual)
        true_positive = sum(
            1
            for truth, prediction, did_abstain in zip(actual, predicted, flags, strict=True)
            if truth == label and prediction == label and not did_abstain
        )
        false_positive = sum(
            1
            for truth, prediction, did_abstain in zip(actual, predicted, flags, strict=True)
            if truth != label and prediction == label and not did_abstain
        )
        false_negative = sum(
            1
            for truth, prediction, did_abstain in zip(actual, predicted, flags, strict=True)
            if truth == label and (prediction != label or did_abstain)
        )
        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 0.0
        )
        recall = (
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else 0.0
        )
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        if support:
            f1_values.append(f1)
        per_class[label] = {
            "support": support,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
        }

    total = len(actual)
    return {
        "examples": total,
        "accuracy": round(correct / total, 6) if total else None,
        "coverage": round(covered / total, 6) if total else None,
        "abstention_rate": round(sum(flags) / total, 6) if total else None,
        "missing_rate": round(sum(value is None for value in predicted) / total, 6)
        if total
        else None,
        "selective_accuracy": round(correct / covered, 6) if covered else None,
        "macro_f1": round(sum(f1_values) / len(f1_values), 6) if f1_values else None,
        "confusion_matrix": matrix,
        "per_class": per_class,
    }


def _prediction_map(
    predictions: Mapping[str, RolePrediction | Mapping[str, Any]] | None,
) -> dict[str, tuple[str | None, bool, float | None]]:
    if predictions is not None and not isinstance(predictions, Mapping):
        raise ConfigError("invalid shadow predictions: expected a host-keyed mapping")
    result: dict[str, tuple[str | None, bool, float | None]] = {}
    for host_ip, prediction in (predictions or {}).items():
        if not isinstance(host_ip, str) or not host_ip.strip():
            raise ConfigError(
                "invalid shadow prediction host identifier: expected a nonempty string"
            )
        if isinstance(prediction, RolePrediction):
            label, abstained, confidence = (
                prediction.label,
                prediction.abstained,
                prediction.confidence,
            )
        elif isinstance(prediction, Mapping):
            label = prediction.get("label")
            abstained = prediction.get("abstained", False)
            confidence = prediction.get("confidence")
        else:
            raise ConfigError(f"invalid shadow prediction for {host_ip}: expected an object")
        if label is not None and (not isinstance(label, str) or label not in ROLES):
            raise ConfigError(f"invalid shadow prediction for {host_ip}: unsupported role label")
        if type(abstained) is not bool:
            raise ConfigError(f"invalid shadow prediction for {host_ip}: abstained must be boolean")
        if confidence is not None and (
            type(confidence) not in (int, float) or not 0 <= confidence <= 1
        ):
            raise ConfigError(
                f"invalid shadow prediction for {host_ip}: confidence must be in [0, 1]"
            )
        result[host_ip] = (label, abstained, confidence)
    return result


def _evaluated_features(profile: ContextProfile, truth: ContextTruth) -> list[tuple[str, Feature]]:
    """Only prediction inputs used for this labelled host, not unused owner metadata."""
    features = [("role", profile.role), ("exposure", profile.exposure)]
    features.extend(
        (key, profile.controls[key])
        for key in CONTROL_KEYS
        if truth.controls.get(key) is not None and key in profile.controls
    )
    return features


def _prediction_provenance(
    profiles: Mapping[str, ContextProfile], truth: Sequence[ContextTruth]
) -> tuple[bool, list[str]]:
    """Check declared provenance without relabelling or changing any prediction.

    Legacy external-vantage metadata can have source='rule'. Its generated
    evidence quote must still disqualify a zero-manual-tag inference claim.
    This is not authentication of source declarations or independent truth.
    """
    manual_used = False
    issues: list[str] = []
    for item in truth:
        profile = profiles.get(item.host_ip)
        if profile is None:
            continue
        used, found = _feature_provenance(item.host_ip, _evaluated_features(profile, item))
        manual_used |= used
        issues.extend(found)
    return manual_used, issues


def _feature_provenance(
    host_ip: str, features: Sequence[tuple[str, Feature]]
) -> tuple[bool, list[str]]:
    """Shared declaration checks; neither caller authenticates the original source."""
    manual_used = False
    issues = []
    for name, feature in features:
        metadata = re.search(
            r"\bscope\.yaml\s+lab_targets\[.*?\]\.tags\.",
            feature.evidence,
            re.IGNORECASE | re.DOTALL,
        )
        manual_used |= feature.source == "manual" or metadata is not None
        if feature.source != "rule":
            issues.append(f"{host_ip} {name}: {feature.source} source, not rule-only")
        if metadata is not None:
            issues.append(f"{host_ip} {name}: scope metadata used as prediction evidence")
    return manual_used, issues


def _control_label(feature: Feature | None) -> str | None:
    """The evaluator's observation semantics, shared with report compatibility checks."""
    if (
        feature is None
        or feature.value is None
        or (
            feature.value is False
            and feature.source == "rule"
            and feature.evidence == "none observed"
        )
    ):
        return None
    return str(bool(feature.value)).lower()


def evaluate_context(
    profiles: Sequence[ContextProfile],
    truth: Sequence[ContextTruth],
    model_predictions: Mapping[str, RolePrediction | Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare rule context and optional shadow-model roles against host truth."""
    if not truth:
        raise ConfigError("context evaluation needs at least one labelled host")
    truth_hosts: set[str] = set()
    for item in truth:
        try:
            item.__post_init__()
        except ValueError as error:
            raise ConfigError(f"invalid context truth: {error}") from error
        if item.host_ip in truth_hosts:
            raise ConfigError(f"context truth host {item.host_ip!r} is labelled more than once")
        truth_hosts.add(item.host_ip)
    profile_by_ip = {profile.host_ip: profile for profile in profiles}
    if len(profile_by_ip) != len(profiles):
        raise ConfigError("context evaluation received duplicate host profiles")
    model_by_ip = _prediction_map(model_predictions)

    actual_roles = [item.role for item in truth]
    rule_roles: list[str | None] = []
    rule_abstained: list[bool] = []
    model_roles: list[str | None] = []
    model_abstained: list[bool] = []
    actual_exposure = [item.exposure for item in truth]
    inferred_exposure: list[str | None] = []
    missing_profiles: list[str] = []
    disagreements: list[dict[str, Any]] = []

    for item in truth:
        profile = profile_by_ip.get(item.host_ip)
        if profile is None:
            missing_profiles.append(item.host_ip)
            rule_roles.append(None)
            rule_abstained.append(False)
            inferred_exposure.append(None)
        else:
            for name, value, allowed in (
                ("role", profile.role.value, ROLES),
                ("exposure", profile.exposure.value, EXPOSURES),
            ):
                if not isinstance(value, str) or value not in allowed:
                    raise ConfigError(
                        f"invalid context prediction for {item.host_ip}: unsupported {name} label"
                    )
            rule_label = str(profile.role.value)
            rule_roles.append(rule_label)
            rule_abstained.append(rule_label == "unknown")
            inferred_exposure.append(str(profile.exposure.value))

        model_label, did_abstain, confidence = model_by_ip.get(item.host_ip, (None, False, None))
        model_roles.append(model_label)
        model_abstained.append(did_abstain)
        if (
            profile is not None
            and model_label is not None
            and not did_abstain
            and model_label != str(profile.role.value)
        ):
            disagreements.append(
                {
                    "host_ip": item.host_ip,
                    "truth": item.role,
                    "rule": str(profile.role.value),
                    "model": model_label,
                    "model_confidence": confidence,
                    "rule_evidence": profile.role.evidence,
                }
            )

    role_rule = _classification(actual_roles, rule_roles, ROLES, rule_abstained)
    role_model = (
        None
        if model_predictions is None
        else _classification(actual_roles, model_roles, ROLES, model_abstained)
    )
    exposure = _classification(actual_exposure, inferred_exposure, EXPOSURES)

    control_results: dict[str, Any] = {}
    for key in CONTROL_KEYS:
        applicable = [item for item in truth if item.controls.get(key) is not None]
        expected = [str(bool(item.controls[key])).lower() for item in applicable]
        observed: list[str | None] = []
        for item in applicable:
            profile = profile_by_ip.get(item.host_ip)
            feature = None if profile is None else profile.controls.get(key)
            observed.append(_control_label(feature))
        control_results[key] = _classification(expected, observed, ("false", "true"))

    human_only = all(item.label_source == "human" for item in truth)
    manual_tags_used, provenance_issues = _prediction_provenance(profile_by_ip, truth)
    eligibility_issues = []
    if not human_only:
        eligibility_issues.append("synthetic labels cannot establish H1")
    if missing_profiles:
        eligibility_issues.append(f"missing profiles for {missing_profiles}")
    eligibility_issues.extend(provenance_issues)
    eligible = not eligibility_issues
    h1 = {
        "eligible": eligible,
        "reason": "; ".join(eligibility_issues)
        if eligibility_issues
        else "eligible for H1 interpretation",
        "role_target": 0.85,
        "exposure_target": 0.95,
        "role_pass": (
            role_rule["accuracy"] >= 0.85
            if eligible and role_rule["accuracy"] is not None
            else None
        ),
        "exposure_pass": (
            exposure["accuracy"] >= 0.95 if eligible and exposure["accuracy"] is not None else None
        ),
    }
    evidence_status = "VERIFIED" if eligible else "NOT RUN"
    return {
        "status": evidence_status,
        "evidence_status": evidence_status,
        "data_kind": "human" if human_only else "synthetic",
        "manual_tags_used": manual_tags_used,
        "truth_hosts": len(truth),
        "truth_groups": len({item.group for item in truth}),
        "missing_profile_hosts": missing_profiles,
        "unlabelled_profile_hosts": sorted(set(profile_by_ip) - {item.host_ip for item in truth}),
        "rule_role": role_rule,
        "model_role": role_model,
        "exposure": exposure,
        "controls": control_results,
        "rule_model_disagreements": disagreements,
        "h1": h1,
    }
