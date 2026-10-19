"""Research artifacts cannot manufacture approval, provenance, or evaluation validity."""

import json
from dataclasses import replace

import pytest

from tests.test_cohort import synthetic_snapshot
from vulnassess import cohort, context_eval, model_governance
from vulnassess.errors import ConfigError


@pytest.fixture
def frozen():
    snapshot = synthetic_snapshot()
    manifest, items = cohort.freeze_cohort(
        snapshot,
        [item["id"] for item in snapshot["findings"]],
        cohort_id="synthetic",
        created_on="2026-10-09",
        evidence_status="NOT RUN",
    )
    return snapshot, manifest, items


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"schema_version": 99}, "schema_version"),
        ({"cohort_id": " "}, "required"),
        ({"config_hash": "BAD"}, "config_hash"),
        ({"snapshot_hash": "x" * 64}, "snapshot_hash"),
        ({"item_hashes": {"finding-00": "BAD"}}, "item_hash"),
        ({"model_hash": "BAD"}, "model_hash"),
        ({"finding_mode": "merged"}, "raw cohorts"),
        ({"finding_ids": ("finding-00", "finding-00")}, "duplicates"),
        ({"finding_ids": ()}, "at least one"),
        ({"item_hashes": {}}, "item_hashes"),
        ({"grouping_map": {}}, "grouping_map"),
        ({"grouping_map": {f"finding-{i:02d}": ("wrong",) for i in range(3)}}, "map each finding"),
        ({"ndcg_k": 5}, "cutoff"),
        ({"tie_policy": "ignore ties"}, "preregistration"),
        ({"created_on": "tomorrow"}, "ISO date"),
        ({"evidence_status": "COMPLETE"}, "VERIFIED or NOT RUN"),
        ({"evidence_status": "VERIFIED"}, "cohort size"),
    ],
)
def test_manifest_contract_rejects_invalid_values(frozen, changes, reason):
    with pytest.raises(ValueError, match=reason):
        replace(frozen[1], **changes)


def test_large_verified_cohort_still_requires_human_approval():
    snapshot = synthetic_snapshot(20)
    with pytest.raises(ConfigError, match="reviewer and approval_id"):
        cohort.freeze_cohort(
            snapshot,
            [row["id"] for row in snapshot["findings"]],
            cohort_id="synthetic",
            created_on="2026-10-09",
            evidence_status="VERIFIED",
        )


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("snapshot_hash", "a" * 64, "snapshot hash"),
        ("run_id", "other", "run"),
        ("config_hash", "a" * 16, "configuration"),
        ("weights_hash", "a" * 64, "weights"),
        ("feed_snapshot_hash", "a" * 64, "feeds"),
        ("model_hash", "a" * 16, "model"),
        ("item_hashes", {f"finding-{i:02d}": "a" * 64 for i in range(3)}, "evidence"),
    ],
)
def test_manifest_cannot_be_rebound_to_other_inputs(frozen, field, value, reason):
    with pytest.raises(ConfigError, match=reason):
        cohort.validate_snapshot_against_manifest(frozen[0], replace(frozen[1], **{field: value}))


@pytest.mark.parametrize(
    "mode,reason", [("duplicate", "duplicates"), ("missing", "not in"), ("host", "missing host")]
)
def test_blinding_requires_complete_original_evidence(frozen, mode, reason):
    snapshot, manifest, _ = frozen
    ids = list(manifest.finding_ids)
    if mode == "duplicate":
        ids.append(ids[0])
    elif mode == "missing":
        ids.append("invented")
    else:
        snapshot["hosts"] = []
    with pytest.raises(ConfigError, match=reason):
        cohort.blinded_items(snapshot, ids)


@pytest.mark.parametrize(
    "payload,reason",
    [
        (None, "list of objects"),
        ([{}], "missing finding_id"),
        ([{"finding_id": "a"}, {"finding_id": "a"}], "duplicate finding_id"),
    ],
)
def test_evidence_artifact_shape(frozen, tmp_path, payload, reason):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ConfigError, match=reason):
        cohort.load_evidence(path, frozen[1])


@pytest.mark.parametrize(
    "payload,reason",
    [
        ([], "expected an object"),
        ({"unknown": True}, "unknown key"),
        ({}, "invalid cohort manifest"),
    ],
)
def test_manifest_file_shape(tmp_path, payload, reason):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ConfigError, match=reason):
        cohort.load_manifest(path)


def test_save_refuses_changed_evidence(frozen, tmp_path):
    _, manifest, items = frozen
    items[0]["finding"]["evidence"] = "changed"
    with pytest.raises(ConfigError, match="content does not match"):
        cohort.save_cohort(manifest, items, tmp_path)
    assert not (tmp_path / "manifest.json").exists()


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("id", "cohort_id"),
        ("verified", "VERIFIED cohort"),
        ("empty", "non-empty"),
        ("entry", "name and ranking"),
        ("duplicate", "more than once"),
        ("critical", "non-cohort ID"),
    ],
)
def test_truth_cannot_claim_unsupported_review(frozen, mode, reason):
    manifest = frozen[1]
    truth = {
        "cohort_id": manifest.cohort_id,
        "cohort_hash": manifest.manifest_hash,
        "experts": [{"name": "synthetic", "ranking": list(manifest.finding_ids)}],
    }
    if mode == "id":
        truth["cohort_id"] = "different"
    elif mode == "verified":
        truth["evidence_status"] = "VERIFIED"
    elif mode == "empty":
        truth["experts"] = []
    elif mode == "entry":
        truth["experts"] = [{}]
    elif mode == "duplicate":
        truth["experts"][0]["ranking"].append(manifest.finding_ids[0])
    else:
        truth["experts"][0]["critical"] = ["invented"]
    with pytest.raises(ConfigError, match=reason):
        cohort.validate_truth_against_cohort(truth, manifest)


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"host_ip": ""}, "host_ip"),
        ({"group": ""}, "group"),
        ({"role": "invalid"}, "role"),
        ({"exposure": "maybe"}, "exposure"),
        ({"controls": {"unknown": True}}, "unknown control"),
        ({"controls": {"tls": "yes"}}, "true, false, or null"),
        ({"label_source": "ai"}, "label_source"),
        ({"label_source": "human", "reviewer": None}, "reviewer"),
        ({"label_source": "human", "reviewer": "reviewer", "provenance": ""}, "provenance"),
    ],
)
def test_context_truth_rejects_invalid_labels(changes, reason):
    params = {
        "host_ip": "192.0.2.1",
        "group": "synthetic",
        "role": "database",
        "exposure": "internal",
        "label_source": "synthetic",
    }
    with pytest.raises(ValueError, match=reason):
        context_eval.ContextTruth(**{**params, **changes})


@pytest.mark.parametrize(
    "payload,reason",
    [
        ([], "mapping"),
        ({"x": 1}, "unknown key"),
        ({"version": 99}, "version"),
        ({"version": 1, "hosts": []}, "non-empty list"),
        ({"version": 1, "hosts": [1]}, "mapping"),
        ({"version": 1, "hosts": [{"unknown": 1}]}, "unknown key"),
    ],
)
def test_context_truth_document_shape(tmp_path, payload, reason):
    path = tmp_path / "truth.yaml"
    path.write_text(json.dumps(payload))
    with pytest.raises(ConfigError, match=reason):
        context_eval.load_context_truth(path)


def test_context_truth_missing_and_malformed_file(tmp_path):
    path = tmp_path / "truth.yaml"
    with pytest.raises(ConfigError, match="MISSING"):
        context_eval.load_context_truth(path)
    path.write_text("[broken")
    with pytest.raises(ConfigError, match="unreadable"):
        context_eval.load_context_truth(path)


def test_classification_mismatched_lengths_and_unknown_prediction():
    with pytest.raises(ValueError, match="lengths differ"):
        context_eval._classification(["database"], [], ["database"])
    with pytest.raises(ValueError, match="flags"):
        context_eval._classification(["database"], ["database"], ["database"], [False, True])
    result = context_eval._classification(["database"], ["other"], ["database"])
    assert result["accuracy"] == 0


@pytest.fixture
def promotion():
    return model_governance.PromotionManifest(
        model_hash="a" * 16,
        preprocessing_version="test",
        test_dataset_hash="b" * 64,
        test_evidence_status="NOT RUN",
        label_source="synthetic",
        groups_disjoint=True,
        manual_tags_used=False,
        test_groups=3,
        metrics={},
        thresholds={},
        reviewer="synthetic",
        approval_id="synthetic",
        mentor_approval_id="synthetic",
        issued_on="2026-10-01",
        expires_on="2026-10-31",
    )


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"schema_version": 2}, "schema_version"),
        ({"policy_version": "other"}, "policy_version"),
        ({"test_dataset_hash": "bad"}, "SHA-256"),
        ({"test_groups": -1}, "negative"),
        ({"metrics": {"accuracy": float("nan")}}, "must be in"),
        ({"thresholds": {"coverage": 2}}, "must be in"),
        ({"reviewer": " "}, "required"),
        ({"issued_on": "bad"}, "ISO dates"),
        ({"expires_on": "2026-09-30"}, "precedes"),
    ],
)
def test_promotion_metadata_cannot_bypass_validation(promotion, changes, reason):
    with pytest.raises(ValueError, match=reason):
        replace(promotion, **changes)


@pytest.mark.parametrize("contents,reason", [("not json", "invalid"), ("[]", "expected an object")])
def test_promotion_file_rejects_bad_json(tmp_path, contents, reason):
    path = tmp_path / "promotion.json"
    path.write_text(contents)
    with pytest.raises(ConfigError, match=reason):
        model_governance.load_manifest(path)
