"""Synthetic RQ1 boundary cases, never independent human/expert evidence.

Declared-human labels below exercise eligibility logic only. No reviewer or real
inference result is established by these synthetic examples.
"""

import copy
import io
import json
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from tests.test_assessment_snapshot import ROOT, prepared_store
from vulnassess import context, context_eval
from vulnassess.cli import main
from vulnassess.errors import ConfigError
from vulnassess.schema import ContextProfile, Feature, Host
from vulnassess.settings import Scope


def synthetic_profile(host="192.0.2.10"):
    return ContextProfile(
        host_ip=host,
        role=Feature("database", 0.9, "rule", "SYNTHETIC redis service observation"),
        exposure=Feature("internal", 0.9, "rule", "SYNTHETIC private-address observation"),
        controls={"waf": Feature(True, 0.9, "rule", "SYNTHETIC control observation")},
    )


def synthetic_truth(host="192.0.2.10", **changes):
    return context_eval.ContextTruth(
        **{
            "host_ip": host,
            "group": f"SYNTHETIC-{host}",
            "role": "database",
            "exposure": "internal",
            "controls": {},
            "label_source": "human",
            "reviewer": "SYNTHETIC declared reviewer, not an actual expert",
            "provenance": "SYNTHETIC pure-logic input, not empirical evidence",
            **changes,
        }
    )


def assert_ineligible(result):
    assert result["h1"]["eligible"] is False
    assert result["h1"]["role_pass"] is None
    assert result["h1"]["exposure_pass"] is None
    assert result["status"] == result["evidence_status"] == "NOT RUN"


@pytest.mark.parametrize("field", ["role", "exposure", "waf"])
@pytest.mark.parametrize("source", ["manual", "model", "llm"])
def test_non_rule_evaluated_features_cannot_claim_rule_only_h1(field, source):
    profile = synthetic_profile()
    old = profile.controls[field] if field == "waf" else getattr(profile, field)
    changed = replace(old, source=source)
    if field == "waf":
        profile.controls[field] = changed
    else:
        setattr(profile, field, changed)
    before = copy.deepcopy(profile.to_json())

    result = context_eval.evaluate_context([profile], [synthetic_truth(controls={"waf": True})])

    assert_ineligible(result)
    assert result["manual_tags_used"] is (source == "manual")
    assert source in result["h1"]["reason"]
    assert field in result["h1"]["reason"]
    assert profile.host_ip in result["h1"]["reason"]
    assert result["rule_role"]["accuracy"] == 1.0
    assert result["exposure"]["accuracy"] == 1.0
    assert profile.to_json() == before


@pytest.mark.parametrize("field", ["role", "exposure", "waf"])
@pytest.mark.parametrize(
    "quote",
    [
        "scope.yaml lab_targets[SYNTHETIC].tags.vantage=external",
        "scope.yaml lab_targets[SYNTHETIC].tags.environment=test",
        "SYNTHETIC observation; scope.yaml lab_targets[SYNTHETIC].tags.role=database",
        "SCOPE.YAML lab_targets[SYNTHETIC].tags.vantage=external",
    ],
)
def test_rule_label_cannot_hide_metadata_used_as_evaluated_evidence(field, quote):
    profile = synthetic_profile()
    feature = profile.controls[field] if field == "waf" else getattr(profile, field)
    contaminated = replace(feature, evidence=quote)
    if field == "waf":
        profile.controls[field] = contaminated
    else:
        setattr(profile, field, contaminated)

    result = context_eval.evaluate_context([profile], [synthetic_truth(controls={"waf": True})])

    assert_ineligible(result)
    assert result["manual_tags_used"] is True
    assert "metadata" in result["h1"]["reason"]


def test_actual_exposure_rule_cannot_bypass_zero_manual_tag_eligibility():
    class SyntheticScope:
        def tags(self, host):
            return {"vantage": "external"}

        def name(self, host):
            return "SYNTHETIC external-vantage override"

        def segment(self, host):
            return "SYNTHETIC lab"

    profile = synthetic_profile()
    profile.exposure, profile.segment = context.infer_exposure(
        Host(profile.host_ip), SyntheticScope()
    )
    assert profile.exposure.source == "manual"
    assert profile.manual == {}

    result = context_eval.evaluate_context([profile], [synthetic_truth(exposure="internet_facing")])

    assert_ineligible(result)
    assert result["manual_tags_used"] is True
    assert result["exposure"]["accuracy"] == 1.0


@pytest.mark.parametrize(
    "name", ["SYNTHETIC\ntarget", "SYNTHETIC\rtarget", "SYNTHETIC\r\ntarget", "\n"]
)
@pytest.mark.parametrize("field", ["role", "exposure", "waf"])
def test_legacy_multiline_scope_names_cannot_hide_manual_provenance(name, field):
    profile = synthetic_profile("172.28.0.12")
    scope = Scope(
        {
            "allowed_hosts": [profile.host_ip],
            "lab_targets": [{"name": name, "ip": profile.host_ip, "tags": {"vantage": "external"}}],
        },
        Path("tests/synthetic/synthetic_multiline_scope.yaml"),
    )
    actual, _ = context.infer_exposure(Host(profile.host_ip), scope)
    assert actual.source == "manual"
    assert name in actual.evidence
    previous = profile.controls[field] if field == "waf" else getattr(profile, field)
    legacy = replace(previous, source="rule", evidence=actual.evidence)
    if field == "waf":
        profile.controls[field] = legacy
    else:
        setattr(profile, field, legacy)
    before = copy.deepcopy(profile.to_json())
    result = context_eval.evaluate_context(
        [profile], [synthetic_truth(profile.host_ip, controls={"waf": True})]
    )
    assert_ineligible(result)
    assert result["manual_tags_used"] is True
    assert "metadata" in result["h1"]["reason"]
    assert result["rule_role"]["accuracy"] == 1.0
    assert result["exposure"]["accuracy"] == 1.0
    assert profile.to_json() == before


def test_ordinary_multiline_observations_do_not_become_manual_metadata():
    profile = synthetic_profile()
    profile.role = replace(profile.role, evidence="SYNTHETIC redis\nservice observation")
    result = context_eval.evaluate_context([profile], [synthetic_truth()])
    assert result["evidence_status"] == "VERIFIED"
    assert result["h1"]["eligible"] is True
    assert result["manual_tags_used"] is False


def test_unused_metadata_shadow_predictions_and_unlabelled_profiles_do_not_taint_cohort():
    labelled = synthetic_profile()
    labelled.manual["environment"] = Feature(
        "test", 1, "manual", "scope.yaml lab_targets[SYNTHETIC].tags.environment=test"
    )
    labelled.controls["waf"] = Feature(True, 0.9, "manual", "SYNTHETIC unused control")
    other = synthetic_profile("192.0.2.11")
    other.exposure = replace(other.exposure, source="manual")
    result = context_eval.evaluate_context(
        [labelled, other],
        [synthetic_truth(controls={"waf": None})],
        {labelled.host_ip: {"label": "database", "confidence": 1, "abstained": False}},
    )

    assert result["h1"]["eligible"] is True
    assert result["h1"]["role_pass"] is True
    assert result["h1"]["exposure_pass"] is True
    assert result["manual_tags_used"] is False
    assert result["unlabelled_profile_hosts"] == [other.host_ip]
    assert result["controls"]["waf"]["examples"] == 0


def test_metadata_tainted_member_stays_in_full_accuracy_denominator():
    first = synthetic_profile()
    second = synthetic_profile("192.0.2.11")
    second.role = Feature("web_frontend", 1, "manual", "SYNTHETIC owner label")
    result = context_eval.evaluate_context(
        [first, second], [synthetic_truth(), synthetic_truth(second.host_ip)]
    )

    assert_ineligible(result)
    assert result["manual_tags_used"] is True
    assert result["truth_hosts"] == result["rule_role"]["examples"] == 2
    assert result["rule_role"]["accuracy"] == 0.5
    assert result["exposure"]["accuracy"] == 1.0


def test_missing_human_labelled_profile_has_no_verified_eligibility():
    result = context_eval.evaluate_context([], [synthetic_truth()])
    assert_ineligible(result)
    assert result["missing_profile_hosts"] == ["192.0.2.10"]
    assert result["rule_role"]["accuracy"] == 0.0


@pytest.mark.parametrize("source", ["rule", "manual", "model", "llm"])
def test_synthetic_truth_never_establishes_h1(source):
    profile = synthetic_profile()
    profile.role = replace(profile.role, source=source)
    result = context_eval.evaluate_context(
        [profile], [synthetic_truth(label_source="synthetic", reviewer=None)]
    )
    assert_ineligible(result)
    assert "synthetic" in result["h1"]["reason"]


def test_duplicate_truth_hosts_fail_closed_even_without_yaml_loader():
    item = synthetic_truth()
    with pytest.raises(ConfigError, match="labelled more than once|duplicate.*truth"):
        context_eval.evaluate_context([synthetic_profile()], [item, replace(item, group="other")])


@pytest.mark.parametrize("value", [0, 1, 0.0, 1.0, "false", "true", [], {}])
def test_control_truth_requires_real_boolean_or_null(value):
    with pytest.raises(ValueError, match="control truth"):
        synthetic_truth(controls={"waf": value})


@pytest.mark.parametrize("field", ["host_ip", "group", "reviewer", "provenance"])
@pytest.mark.parametrize("value", [True, 5, [], {}])
def test_truth_identity_metadata_is_not_coerced_or_attribute_error(field, value):
    with pytest.raises(ValueError, match=field):
        synthetic_truth(**{field: value})


def test_truth_cannot_be_mutated_after_construction_to_invent_controls():
    item = synthetic_truth()
    item.controls["waf"] = "false"
    with pytest.raises(ConfigError, match="control truth"):
        context_eval.evaluate_context([synthetic_profile()], [item])


@pytest.mark.parametrize("value", [True, 1.0, "1"])
def test_truth_schema_version_is_strict_integer(tmp_path, value):
    path = tmp_path / "synthetic_context_truth.yaml"
    path.write_text(yaml.safe_dump({"version": value, "hosts": [synthetic_truth().to_json()]}))
    with pytest.raises(ConfigError, match="version"):
        context_eval.load_context_truth(path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("host_ip", None),
        ("group", None),
        ("reviewer", 1),
        ("provenance", ["SYNTHETIC"]),
        ("controls", False),
        ("controls", None),
        ("controls", [["waf", True]]),
    ],
)
def test_truth_loader_rejects_wrong_declared_types_with_config_error(tmp_path, field, value):
    row = {**synthetic_truth().to_json(), field: value}
    path = tmp_path / "synthetic_context_truth.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "hosts": [row]}))
    with pytest.raises(ConfigError, match="hosts\\[0\\]"):
        context_eval.load_context_truth(path)


@pytest.mark.parametrize("comment", ["SYNTHETIC arithmetic fixture", "synthetic evaluation"])
def test_document_level_synthetic_marker_cannot_claim_human_h1(tmp_path, comment):
    path = tmp_path / "synthetic_context_truth.yaml"
    path.write_text(
        yaml.safe_dump({"version": 1, "_comment": comment, "hosts": [synthetic_truth().to_json()]})
    )
    loaded = context_eval.load_context_truth(path)
    result = context_eval.evaluate_context([synthetic_profile()], loaded)
    assert_ineligible(result)
    assert result["data_kind"] == "synthetic"
    assert result["rule_role"]["accuracy"] == 1.0


def test_invalid_truth_encoding_is_a_controlled_input_error(tmp_path):
    path = tmp_path / "synthetic_context_truth.yaml"
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ConfigError, match="unreadable context truth"):
        context_eval.load_context_truth(path)


@pytest.mark.parametrize(
    "changes",
    [
        {"label": ["database"]},
        {"label": "invented"},
        {"confidence": "0.9"},
        {"confidence": True},
        {"confidence": float("nan")},
        {"confidence": float("inf")},
        {"confidence": -0.1},
        {"confidence": 1.1},
        {"abstained": "false"},
        {"abstained": 0},
        {"abstained": None},
    ],
)
def test_shadow_prediction_metadata_cannot_be_coerced_into_verified_metrics(changes):
    prediction = {"label": "database", "confidence": 0.9, "abstained": False, **changes}
    with pytest.raises(ConfigError, match="shadow prediction"):
        context_eval.evaluate_context(
            [synthetic_profile()], [synthetic_truth()], {"192.0.2.10": prediction}
        )


@pytest.mark.parametrize("value", [None, [], True, "database"])
def test_shadow_prediction_wrong_shape_is_controlled(value):
    with pytest.raises(ConfigError, match="shadow prediction"):
        context_eval.evaluate_context(
            [synthetic_profile()], [synthetic_truth()], {"192.0.2.10": value}
        )


def test_absent_shadow_fields_remain_missing_instead_of_fabricating_predictions():
    result = context_eval.evaluate_context(
        [synthetic_profile()], [synthetic_truth()], {"192.0.2.10": {}}
    )
    assert result["h1"]["eligible"] is True
    assert result["model_role"]["missing_rate"] == 1.0
    assert result["model_role"]["accuracy"] == 0.0


@pytest.mark.parametrize("predictions", [[], "not a mapping", False, 1])
def test_shadow_collection_requires_mapping_not_truthiness(predictions):
    with pytest.raises(ConfigError, match="shadow prediction"):
        context_eval.evaluate_context([synthetic_profile()], [synthetic_truth()], predictions)


@pytest.mark.parametrize("host", ["", " ", 5, False])
def test_shadow_host_identity_requires_nonempty_string(host):
    with pytest.raises(ConfigError, match="shadow prediction"):
        context_eval.evaluate_context(
            [synthetic_profile()], [synthetic_truth()], {host: {"label": "database"}}
        )


@pytest.mark.parametrize("comment", [True, None, [], {}])
def test_synthetic_comment_declaration_must_be_text(tmp_path, comment):
    path = tmp_path / "synthetic_context_truth.yaml"
    path.write_text(
        yaml.safe_dump({"version": 1, "_comment": comment, "hosts": [synthetic_truth().to_json()]})
    )
    with pytest.raises(ConfigError, match="_comment must be a string"):
        context_eval.load_context_truth(path)


@pytest.mark.parametrize("field", ["role", "exposure"])
@pytest.mark.parametrize("value", [None, False, [], "invented"])
def test_context_prediction_labels_follow_the_declared_vocabulary(field, value):
    profile = synthetic_profile()
    setattr(profile, field, replace(getattr(profile, field), value=value))
    with pytest.raises(ConfigError, match="context prediction"):
        context_eval.evaluate_context([profile], [synthetic_truth()])


@pytest.mark.parametrize("level", ["root", "row", "control"])
def test_duplicate_yaml_keys_cannot_hide_context_truth_declarations(tmp_path, level):
    path = tmp_path / "synthetic_context_truth.yaml"
    content = yaml.safe_dump({"version": 1, "hosts": [synthetic_truth().to_json()]})
    if level == "root":
        content += "version: 1\n"
    elif level == "row":
        content = content.replace(
            "  label_source: human", "  label_source: synthetic\n  label_source: human"
        )
    else:
        content = content.replace("controls: {}", "controls: {waf: false, waf: true}")
    assert content != yaml.safe_dump({"version": 1, "hosts": [synthetic_truth().to_json()]})
    path.write_text(content)
    with pytest.raises(ConfigError, match="duplicate"):
        context_eval.load_context_truth(path)


@pytest.mark.parametrize("keys", ["3: x\nother: y\n", "{true: x, other: y}"])
def test_mixed_unknown_keys_are_controlled_errors_not_sort_failures(tmp_path, keys):
    path = tmp_path / "synthetic_context_truth.yaml"
    path.write_text(keys)
    with pytest.raises(ConfigError, match="unknown key"):
        context_eval.load_context_truth(path)


def test_persisted_context_cli_cannot_publish_metadata_assisted_h1_pass(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        profiles = store.profiles("snapshot")
        assert any(".tags.vantage=external" in item.exposure.evidence for item in profiles)
        before_profiles = [item.to_json() for item in profiles]
        before_scores = [item.to_json() for item in store.scores("snapshot")]
    path = tmp_path / "synthetic_context_truth.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "hosts": [
                    synthetic_truth(
                        item.host_ip, role=item.role.value, exposure=item.exposure.value
                    ).to_json()
                    for item in profiles
                ],
            }
        )
    )
    artifact = tmp_path / "synthetic_context_evaluation.json"
    output = io.StringIO()
    with redirect_stdout(output):
        code = main(
            [
                "--config",
                str(ROOT / "config"),
                "--db",
                str(tmp_path / "assessment.db"),
                "research",
                "context-eval",
                "--run-id",
                "snapshot",
                "--truth",
                str(path),
                "--out",
                str(artifact),
                "--json",
            ]
        )
    assert code == 0
    result = json.loads(output.getvalue())
    assert_ineligible(result)
    assert result["manual_tags_used"] is True
    assert result["rule_role"]["examples"] == len(profiles)
    assert result["rule_role"]["accuracy"] == round(
        sum(item.role.value != "unknown" for item in profiles) / len(profiles), 6
    )
    assert result["exposure"]["accuracy"] == 1.0
    assert json.loads(artifact.read_text())["h1"] == result["h1"]
    from vulnassess.store import Store

    with Store(tmp_path / "assessment.db") as store:
        assert [item.to_json() for item in store.profiles("snapshot")] == before_profiles
        assert [item.to_json() for item in store.scores("snapshot")] == before_scores
