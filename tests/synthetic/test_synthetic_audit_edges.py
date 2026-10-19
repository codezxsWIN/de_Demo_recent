"""Synthetic report attachments must agree on the run, cohort, and captured state."""

import json
from dataclasses import replace
from unittest.mock import Mock

import pytest

from tests.test_assessment_snapshot import SETTINGS, prepared_store
from vulnassess import assessment_snapshot, audit, cohort, experiments, unify
from vulnassess.errors import ConfigError


@pytest.fixture
def bundle(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        snapshot = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        snapshot_path = assessment_snapshot.save_snapshot(
            snapshot, tmp_path / "synthetic_snapshot.json"
        )
        manifest, evidence = cohort.freeze_cohort(
            snapshot,
            [item["id"] for item in snapshot["findings"]],
            cohort_id="synthetic-report",
            created_on="2026-10-11",
            evidence_status="NOT RUN",
        )
        directory = tmp_path / "synthetic_cohort"
        cohort.save_cohort(manifest, evidence, directory)
        yield (
            store,
            snapshot,
            manifest,
            {
                "snapshot_path": snapshot_path,
                "cohort_manifest_path": directory / "manifest.json",
                "cohort_evidence_path": directory / "evidence.json",
            },
        )


def write_artifact(tmp_path, kind, payload):
    field = audit.ARTIFACT_SPECS[kind][0]
    payload = {key: value for key, value in payload.items() if key != field}
    payload[field] = audit._digest(payload)
    path = tmp_path / f"synthetic_{kind}.json"
    path.write_text(json.dumps(payload))
    return path


@pytest.mark.parametrize("kind", ["ranking", "ablation"])
@pytest.mark.parametrize("matched", [True, False])
def test_report_requires_attachment_cohort_to_match(bundle, tmp_path, kind, matched):
    store, _, manifest, paths = bundle
    cohort_hash = manifest.manifest_hash if matched else "a" * 64
    if kind == "ranking":
        payload = {
            "run_id": "snapshot",
            "evidence_status": "NOT RUN",
            "cohort_hash": cohort_hash,
            "methods": {},
            "h2": {},
            "h3": {},
        }
    else:
        payload = experiments.run_ablations(
            SETTINGS,
            store,
            "snapshot",
            scenarios=["full"],
            research_binding={"cohort_hash": cohort_hash},
        )
    path = write_artifact(tmp_path, kind, payload)
    scores = [item.to_json() for item in store.scores("snapshot")]
    if matched:
        result = audit.collect_report_audit(
            SETTINGS, store, "snapshot", **paths, artifact_paths={kind: path}
        )
        assert result["cohort_hash"] == manifest.manifest_hash
        assert result["artifacts"][kind]["evidence_status"] == "NOT RUN"
        row = next(row for row in result["rows"] if row["component"] == "expert cohort")
        assert row["artifact_hash"] == manifest.manifest_hash
        assert row["evidence_status"] == "NOT RUN"
    else:
        with pytest.raises(ConfigError, match="does not match the report cohort"):
            audit.collect_report_audit(
                SETTINGS, store, "snapshot", **paths, artifact_paths={kind: path}
            )
    assert [item.to_json() for item in store.scores("snapshot")] == scores


def test_report_rejects_cohort_from_another_run(bundle):
    store, _, manifest, paths = bundle
    wrong = replace(manifest, run_id="synthetic-other")
    paths["cohort_manifest_path"].write_text(json.dumps(wrong.to_json()))
    with pytest.raises(ConfigError, match="cohort manifest belongs to run"):
        audit.collect_report_audit(SETTINGS, store, "snapshot", **paths)


def test_report_rejects_unification_from_another_snapshot(bundle, tmp_path):
    store, _, _, paths = bundle
    payload = {
        **unify.unify_run(store, "snapshot").to_json(),
        "run_id": "snapshot",
        "evidence_status": "NOT RUN",
        "snapshot_hash": "a" * 64,
    }
    path = write_artifact(tmp_path, "unification", payload)
    with pytest.raises(ConfigError, match="unification artifact does not match"):
        audit.collect_report_audit(
            SETTINGS, store, "snapshot", **paths, artifact_paths={"unification": path}
        )


def test_report_does_not_replace_missing_history_with_current_feed_cache(bundle, monkeypatch):
    store, _, _, _ = bundle
    monkeypatch.setattr(store, "intelligence_trace", Mock(return_value=None))
    result = audit.collect_report_audit(SETTINGS, store, "snapshot")
    row = next(row for row in result["rows"] if row["component"] == "intelligence trace")
    assert row["evidence_status"] == "MISSING"
    assert "not historical evidence" in row["summary"]
    assert result["intelligence"] == {"trace_counts": {}, "unmatched": []}


@pytest.mark.parametrize("cohort_ids", [["unknown"], ["duplicate", "duplicate"]])
def test_ablation_rejects_invalid_cohort_without_score_writes(bundle, cohort_ids):
    store, _, _, _ = bundle
    scores = [item.to_json() for item in store.scores("snapshot")]
    with pytest.raises(ConfigError, match="cohort"):
        experiments.run_ablations(
            SETTINGS, store, "snapshot", scenarios=["full"], cohort_ids=cohort_ids
        )
    assert [item.to_json() for item in store.scores("snapshot")] == scores


@pytest.mark.parametrize("missing", ["all", "one"])
def test_ablation_requires_context_for_every_finding(bundle, monkeypatch, missing):
    store, _, _, _ = bundle
    profiles = store.profiles("snapshot")
    monkeypatch.setattr(
        store, "profiles", Mock(return_value=[] if missing == "all" else profiles[1:])
    )
    with pytest.raises(ConfigError, match="MISSING: context profile"):
        experiments.score_scenario(SETTINGS, store, "snapshot", "full")


@pytest.mark.parametrize("command", ["ablation", "stability"])
def test_deleted_run_is_not_reported_as_a_verified_experiment(bundle, monkeypatch, command):
    store, _, _, _ = bundle
    monkeypatch.setattr(store, "run_info", Mock(return_value=None))
    with pytest.raises(ConfigError, match="MISSING: run"):
        if command == "ablation":
            experiments.run_ablations(SETTINGS, store, "snapshot", scenarios=["full"])
        else:
            experiments.stability_check(SETTINGS, store, "snapshot", repeats=2)


def test_comparison_discloses_added_and_removed_scores(bundle):
    store, _, _, _ = bundle
    first, second = store.scores("snapshot")[:2]
    result = experiments._comparison([first], [second])
    changes = {item["finding_id"]: item for item in result["changes"]}
    assert result["changed_findings"] == 2
    assert result["inactive"] is False
    assert changes[first.finding_id]["risk_before"] == first.risk
    assert changes[first.finding_id]["risk_after"] is None
    assert changes[second.finding_id]["risk_before"] is None
    assert changes[second.finding_id]["risk_after"] == second.risk
