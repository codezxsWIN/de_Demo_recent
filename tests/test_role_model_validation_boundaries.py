"""Malformed learned-model artifacts and labels cannot enter context inference."""

from dataclasses import replace

import pytest

from tests.test_assessment_snapshot import ROOT
from tests.test_role_model import examples
from vulnassess import role_model
from vulnassess.errors import ConfigError
from vulnassess.schema import Host


@pytest.fixture
def model():
    return role_model.load_model(ROOT / "models/synthetic-role-model.json")


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"schema_version": 99}, "unsupported"),
        ({"classes": ("database", "database")}, "unique classes"),
        ({"classes": ("invented", "database")}, "unknown class"),
        ({"features": ()}, "feature count"),
        ({"intercepts": ()}, "class dimensions"),
        ({"temperature": 0}, "finite and positive"),
        ({"confidence_threshold": float("nan")}, "thresholds"),
    ],
)
def test_artifact_shape_rejected(model, changes, reason):
    with pytest.raises(ValueError, match=reason):
        replace(model, **changes)


def test_artifact_invalid_coefficients_rejected(model):
    with pytest.raises(ValueError, match="feature dimensions"):
        replace(model, coefficients=tuple(() for _ in model.classes))
    with pytest.raises(ValueError, match="coefficients must be finite"):
        replace(model, intercepts=tuple(float("inf") for _ in model.classes))


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"label": "invented"}, "label must"),
        ({"group": " "}, "group"),
        ({"label_source": "model"}, "label_source"),
    ],
)
def test_labelled_host_metadata(changes, reason):
    params = {
        "host": Host(ip="192.0.2.1"),
        "label": "database",
        "group": "synthetic",
        "label_source": "synthetic",
    }
    with pytest.raises(ValueError, match=reason):
        role_model.LabelledHost(**{**params, **changes})


@pytest.mark.parametrize(
    "options",
    [
        {"epochs": 0},
        {"learning_rate": 0},
        {"l2": -1},
        {"min_feature_count": 0},
        {"minimum_feature_coverage": 2},
    ],
)
def test_invalid_training_hyperparameters_fail_before_training(options):
    with pytest.raises(ConfigError, match="hyperparameters"):
        role_model.train(examples("bounds"), **options)


def test_training_requires_diverse_sufficient_data():
    rows = examples("bounds")
    with pytest.raises(ConfigError, match="four labelled"):
        role_model.train(rows[:3])
    with pytest.raises(ConfigError, match="two role classes"):
        role_model.train(rows[:4])
    with pytest.raises(ConfigError, match="no model features"):
        role_model.train(rows, min_feature_count=100)


def test_training_vocabulary_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(role_model, "MAX_FEATURES", 1)
    with pytest.raises(ConfigError, match="vocabulary exceeds"):
        role_model.train(examples("bounds"))


@pytest.mark.parametrize(
    "loader,budget", [("load_model", "MAX_ARTIFACT_BYTES"), ("load_examples", "MAX_LABEL_BYTES")]
)
def test_model_file_size_and_presence_bounds(tmp_path, monkeypatch, loader, budget):
    path = tmp_path / "artifact.json"
    with pytest.raises(ConfigError, match="MISSING"):
        getattr(role_model, loader)(path)
    path.write_text("12345")
    monkeypatch.setattr(role_model, budget, 4)
    with pytest.raises(ConfigError, match="exceeds"):
        getattr(role_model, loader)(path)


@pytest.mark.parametrize(
    "raw,reason", [("bad", "invalid role-model"), ("[]", "expected an object")]
)
def test_model_json_shape(tmp_path, raw, reason):
    path = tmp_path / "model.json"
    path.write_text(raw)
    with pytest.raises(ConfigError, match=reason):
        role_model.load_model(path)


def test_empty_labels_and_blank_lines(tmp_path):
    path = tmp_path / "labels.jsonl"
    path.write_text("\n \n")
    with pytest.raises(ConfigError, match="no examples"):
        role_model.load_examples(path)
