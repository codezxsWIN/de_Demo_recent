"""Pure synthetic truth fixtures exercise validation, never establish research evidence."""

from copy import deepcopy

import pytest
import yaml

from vulnassess import evaluate
from vulnassess.errors import ConfigError


def truth_fixture():
    # Fabricated metadata intentionally exercises the claimed-human wire contract.
    return {
        "evidence_status": "VERIFIED",
        "experts": [
            {
                "name": name,
                "reviewer": "fixture-reviewer",
                "provenance": "fixture-review-record",
                "ranking": ["a", "b", "c", "d"],
                "critical": ["a"],
            }
            for name in ("fixture-expert-a", "fixture-expert-b")
        ],
    }


def methods_fixture():
    return {
        "ours": ["a", "b", "c", "d"],
        "cvss_only": ["d", "c", "b", "a"],
        "cvss_epss": ["c", "d", "b", "a"],
    }


def assert_ineligible(result):
    assert result["h2"]["eligible"] is False
    assert all(value is None for value in result["h2"]["passes"].values())
    assert result["h3"]["eligible"] is False
    assert result["h3"]["pass"] is None


@pytest.mark.parametrize("entrypoint", ["direct", "loaded"])
@pytest.mark.parametrize("marker", ["comment", "data_kind", "label_source", "expert_source"])
@pytest.mark.parametrize("marker_value", ["synthetic", " SYNTHETIC "])
def test_synthetic_verified_claims_never_authorize_hypotheses(
    tmp_path, entrypoint, marker, marker_value
):
    truth = truth_fixture()
    if marker == "comment":
        truth["_comment"] = f"{marker_value} arithmetic fixture; fabricated approval metadata"
    elif marker == "expert_source":
        truth["experts"][1]["label_source"] = marker_value
    else:
        truth[marker] = marker_value
    if entrypoint == "loaded":
        path = tmp_path / "synthetic-truth.yaml"
        path.write_text(yaml.safe_dump(truth), encoding="utf-8")
        truth = evaluate.load_truth(path)

    result = evaluate.evaluate(methods_fixture(), truth)

    assert result["evidence_status"] == "NOT RUN"
    assert result["data_kind"] == "synthetic"
    assert result["h2"]["deltas"]["cvss_only"] == 2.0
    assert result["h3"]["mean_reduction_percent"] == 75.0
    assert_ineligible(result)


INVALID_EXPERT_FIELDS = [
    pytest.param("name", None, "name", id="null-name"),
    pytest.param("name", [], "name", id="unhashable-name"),
    pytest.param("name", 7, "name", id="numeric-name"),
    pytest.param("name", " \t", "name", id="blank-name"),
    pytest.param("ranking", None, "ranking", id="null-ranking"),
    pytest.param("ranking", "abcd", "ranking", id="string-ranking"),
    pytest.param("ranking", {"a": 1}, "ranking", id="mapping-ranking"),
    pytest.param("ranking", [], "ranking", id="empty-ranking"),
    pytest.param("ranking", ["a", []], "ranking", id="empty-tie"),
    pytest.param("ranking", ["a", [["b"]]], "ranking", id="nested-tie"),
    pytest.param("ranking", ["a", None], "ranking", id="null-id"),
    pytest.param("ranking", ["a", 1], "ranking", id="numeric-id"),
    pytest.param("ranking", ["a", " "], "ranking", id="blank-id"),
    pytest.param("ranking", ["a", ["b", "a"]], "twice", id="duplicate-ranked-id"),
    pytest.param("critical", None, "critical", id="null-critical"),
    pytest.param("critical", "a", "critical", id="string-critical"),
    pytest.param("critical", {"a": True}, "critical", id="mapping-critical"),
    pytest.param("critical", [["a"]], "critical", id="nested-critical"),
    pytest.param("critical", [1], "critical", id="numeric-critical-id"),
    pytest.param("critical", [" "], "critical", id="blank-critical-id"),
    pytest.param("critical", ["a", "a"], "critical", id="duplicate-critical-id"),
    pytest.param("critical", ["absent"], "critical", id="critical-outside-ranking"),
    pytest.param("reviewer", " ", "reviewer and provenance", id="blank-reviewer"),
    pytest.param("reviewer", ["reviewer"], "reviewer and provenance", id="list-reviewer"),
    pytest.param("provenance", "\t", "reviewer and provenance", id="blank-provenance"),
    pytest.param("provenance", {"signed": True}, "reviewer and provenance", id="dict-provenance"),
]


@pytest.mark.parametrize("entrypoint", ["direct", "loaded"])
@pytest.mark.parametrize("field,value,message", INVALID_EXPERT_FIELDS)
def test_invalid_expert_fields_fail_closed(tmp_path, entrypoint, field, value, message):
    truth = truth_fixture()
    truth["experts"][0][field] = value
    path = tmp_path / "synthetic-invalid-truth.yaml"
    path.write_text(yaml.safe_dump(truth), encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        if entrypoint == "loaded":
            evaluate.load_truth(path)
        else:
            evaluate.evaluate(methods_fixture(), truth)


@pytest.mark.parametrize("entrypoint", ["direct", "loaded"])
@pytest.mark.parametrize("padded", [False, True])
def test_duplicate_expert_names_cannot_overwrite_panel_results(tmp_path, entrypoint, padded):
    truth = truth_fixture()
    name = truth["experts"][0]["name"]
    truth["experts"][1]["name"] = f" {name} " if padded else name
    truth["experts"][1]["ranking"].reverse()
    path = tmp_path / "synthetic-duplicate-experts.yaml"
    path.write_text(yaml.safe_dump(truth), encoding="utf-8")

    with pytest.raises(ConfigError, match="duplicate.*name|name.*duplicate"):
        if entrypoint == "loaded":
            evaluate.load_truth(path)
        else:
            evaluate.evaluate(methods_fixture(), truth)


@pytest.mark.parametrize("entrypoint", ["direct", "loaded"])
@pytest.mark.parametrize("field", ["name", "ranking", "critical", "reviewer", "provenance"])
def test_missing_expert_fields_are_controlled_errors(tmp_path, entrypoint, field):
    truth = truth_fixture()
    del truth["experts"][0][field]
    path = tmp_path / "synthetic-incomplete-truth.yaml"
    path.write_text(yaml.safe_dump(truth), encoding="utf-8")

    with pytest.raises(ConfigError):
        if entrypoint == "loaded":
            evaluate.load_truth(path)
        else:
            evaluate.evaluate(methods_fixture(), truth)


@pytest.mark.parametrize("payload", [None, [], {}, {"experts": []}, {"experts": [None]}])
def test_direct_evaluation_cannot_bypass_document_validation(payload):
    with pytest.raises(ConfigError):
        evaluate.evaluate(methods_fixture(), payload)


@pytest.mark.parametrize("critical", [None, "a", ["a", "a"], ["missing"]])
@pytest.mark.parametrize("entrypoint", ["direct", "loaded"])
def test_default_critical_set_is_validated_for_each_expert(tmp_path, entrypoint, critical):
    truth = truth_fixture()
    truth["expert_critical"] = critical
    for expert in truth["experts"]:
        del expert["critical"]
    path = tmp_path / "synthetic-default-critical.yaml"
    path.write_text(yaml.safe_dump(truth), encoding="utf-8")

    with pytest.raises(ConfigError, match="critical"):
        if entrypoint == "loaded":
            evaluate.load_truth(path)
        else:
            evaluate.evaluate(methods_fixture(), truth)


def test_valid_default_and_per_expert_critical_sets_preserve_wire_contract(tmp_path):
    truth = truth_fixture()
    truth.update(cohort_id="fixture-cohort", cohort_hash="a" * 64, expert_critical=["a"])
    del truth["experts"][0]["critical"]
    truth["experts"][1]["critical"] = ["c"]
    truth["experts"][1]["ranking"] = ["a", ["b", "c"], "d"]
    original = deepcopy(truth)
    path = tmp_path / "synthetic-contract.yaml"
    path.write_text(yaml.safe_dump(truth), encoding="utf-8")

    loaded = evaluate.load_truth(path)
    result = evaluate.evaluate(methods_fixture(), loaded)

    assert loaded == original
    assert truth == original
    assert result["critical_sets"] == {"fixture-expert-a": ["a"], "fixture-expert-b": ["c"]}
    assert result["methods"]["ours"]["critical_queue_by_expert"] == {
        "fixture-expert-a": 1,
        "fixture-expert-b": 3,
    }
    assert result["evidence_status"] == "VERIFIED"
    assert result["h2"]["eligible"] is True
    assert result["h3"]["eligible"] is True


@pytest.mark.parametrize(
    "change", ["missing", "missing-critical", "extra", "different-expert-population"]
)
def test_population_mismatch_keeps_diagnostics_but_blocks_hypotheses(change):
    truth = truth_fixture()
    methods = methods_fixture()
    if change == "missing":
        methods["ours"].remove("d")
    elif change == "missing-critical":
        methods["ours"].remove("a")
    elif change == "extra":
        methods["ours"].append("unreviewed")
    else:
        truth["experts"][1]["ranking"].remove("d")

    result = evaluate.evaluate(methods, truth)

    assert "tau_b_mean" in result["methods"]["ours"]
    assert_ineligible(result)


@pytest.mark.parametrize("order", [None, "abcd", ["a", "a"], ["a", []], ["a", {"b": 1}]])
def test_invalid_method_rankings_cannot_feed_hypothesis_arithmetic(order):
    methods = methods_fixture()
    methods["ours"] = order
    with pytest.raises(ConfigError, match="ranking|twice"):
        evaluate.evaluate(methods, truth_fixture())


def test_missing_baselines_and_undefined_metrics_are_not_eligible():
    truth = truth_fixture()
    result = evaluate.evaluate({"ours": ["a", "b", "c", "d"]}, truth)
    assert_ineligible(result)

    methods = {name: [["a", "b", "c", "d"]] for name in methods_fixture()}
    result = evaluate.evaluate(methods, truth)
    assert result["h2"]["eligible"] is False
    assert all(value is None for value in result["h2"]["passes"].values())


@pytest.mark.parametrize("all_empty", [False, True])
def test_empty_critical_sets_do_not_authorize_partial_panel_h3_claims(all_empty):
    truth = truth_fixture()
    truth["experts"][0]["critical"] = []
    if all_empty:
        truth["experts"][1]["critical"] = []

    result = evaluate.evaluate(methods_fixture(), truth)

    assert result["methods"]["ours"]["critical_queue_by_expert"]["fixture-expert-a"] == 0
    assert result["h3"]["eligible"] is False
    assert result["h3"]["pass"] is None


def test_unverified_and_full_method_contracts_remain_supported():
    truth = truth_fixture()
    del truth["evidence_status"]
    for expert in truth["experts"]:
        del expert["reviewer"]
        del expert["provenance"]
    methods = methods_fixture()
    methods["full"] = methods.pop("ours")

    result = evaluate.evaluate(methods, truth)

    assert result["h2"]["primary_method"] == "full"
    assert result["evidence_status"] == "NOT RUN"
    assert result["data_kind"] == "human"
    assert_ineligible(result)


def test_h2_cannot_discard_an_expert_with_undefined_agreement():
    truth = truth_fixture()
    truth["experts"][1]["ranking"] = [["a", "b", "c", "d"]]

    result = evaluate.evaluate(methods_fixture(), truth)

    assert result["methods"]["ours"]["tau_b"]["fixture-expert-b"] is None
    assert result["methods"]["ours"]["tau_b_mean"] == 1.0
    assert result["h2"]["eligible"] is False
    assert all(value is None for value in result["h2"]["passes"].values())


def test_invalid_utf8_truth_is_a_controlled_configuration_error(tmp_path):
    path = tmp_path / "synthetic-invalid-encoding.yaml"
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ConfigError, match="unreadable YAML"):
        evaluate.load_truth(path)
