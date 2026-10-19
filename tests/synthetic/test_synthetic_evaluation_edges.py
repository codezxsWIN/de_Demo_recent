"""Synthetic expert input cannot silently become valid research evidence."""

from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from vulnassess import evaluate
from vulnassess.errors import ConfigError


@pytest.mark.parametrize(
    "payload,message",
    [
        ([], "mapping"),
        ({}, "experts.*required"),
        ({"experts": []}, "non-empty list"),
        ({"experts": [None]}, "every expert"),
        ({"experts": [{"name": "synthetic", "ranking": ["a", "a"]}]}, "twice"),
        ({"experts": [{"name": "synthetic", "ranking": ["a"]}]}, "expert_critical"),
        (
            {
                "evidence_status": "VERIFIED",
                "experts": [{"name": "synthetic", "ranking": ["a"]}],
                "expert_critical": [],
            },
            "reviewer and provenance",
        ),
    ],
)
def test_invalid_expert_truth_is_rejected(tmp_path, payload, message):
    path = tmp_path / "synthetic_truth.yaml"
    path.write_text(yaml.safe_dump(payload))
    with pytest.raises(ConfigError, match=message):
        evaluate.load_truth(path)


def test_missing_truth_does_not_produce_empty_evaluation(tmp_path):
    with pytest.raises(ConfigError, match="MISSING"):
        evaluate.load_truth(tmp_path / "synthetic_missing.yaml")


@pytest.mark.parametrize("failure", ["syntax", "permission"])
def test_unreadable_truth_is_a_controlled_configuration_error(tmp_path, monkeypatch, failure):
    path = tmp_path / "synthetic_truth.yaml"
    path.write_text("experts: [")
    if failure == "permission":
        monkeypatch.setattr(Path, "read_text", Mock(side_effect=PermissionError("synthetic")))
    with pytest.raises(ConfigError, match="unreadable YAML"):
        evaluate.load_truth(path)


@pytest.mark.parametrize("rankings", [[[], []], [["a"], ["a"]], [[["a", "b"]], [["a", "b"]]]])
def test_concordance_without_variation_is_unknown_not_perfect(rankings):
    assert evaluate.kendall_w(rankings) is None


@pytest.mark.parametrize("expert", [[], ["a"]])
def test_ndcg_without_ranking_gain_is_zero(expert):
    assert evaluate.ndcg_at_k(["a"], expert) == 0


def test_critical_queue_distinguishes_no_critical_findings_from_missing_ones():
    assert evaluate.critical_queue_at_full_recall(["a"], []) == 0
    assert evaluate.critical_queue_at_full_recall(["a"], ["b"]) is None


def test_two_agreeing_synthetic_raters_report_concordance_without_human_validation():
    truth = {
        "_comment": "SYNTHETIC agreement fixture",
        "experts": [
            {"name": name, "ranking": ["a", "b"], "critical": ["a"]}
            for name in ("synthetic-one", "synthetic-two")
        ],
    }
    result = evaluate.evaluate({"ours": ["a", "b"]}, truth)
    assert result["kendall_w"] == 1.0
    assert "Kendall's W across 2 experts: 1.0" in evaluate.markdown_table(result)
    assert result["evidence_status"] == "NOT RUN"
    assert result["h3"]["eligible"] is False
