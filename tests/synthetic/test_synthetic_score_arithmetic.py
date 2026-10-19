"""Synthetic arithmetic replay; not independent CVSS conformance or real risk truth."""

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy

import pytest

from tests.synthetic.test_synthetic_snapshot_score_binding import (
    synthetic_rehash,
    synthetic_scored_row,
)
from tests.synthetic.test_synthetic_snapshot_score_binding import (
    synthetic_snapshot as synthetic_snapshot,
)
from tests.test_assessment_snapshot import ROOT, SETTINGS, prepared_store
from vulnassess import assessment_snapshot, cvss31, scoring
from vulnassess.cli import main
from vulnassess.errors import ConfigError

CASES = (
    "risk_with_consistent_band",
    "band",
    "base_score",
    "env_score",
    "threat_multiplier",
    "env_vector",
    "env_modifications",
    "effective_controls",
    "control_decision",
    "native_fallback",
    "native_risk",
)


def synthetic_change(payload, case):
    row = synthetic_scored_row(payload)
    if case == "risk_with_consistent_band":
        row["risk"] = 1.0 if row["risk"] != 1.0 else 2.0
        row["band"] = scoring.band(
            row["risk"], payload["configuration"]["validated"]["weights.yaml"]
        )
    elif case == "band":
        row["band"] = "Low" if row["band"] != "Low" else "Critical"
    elif case in {"base_score", "env_score", "threat_multiplier"}:
        row[case] = 1.123456 if row[case] != 1.123456 else 2.123456
    elif case == "env_vector":
        metrics = cvss31.parse(row["env_vector"])
        metrics["MAV"] = "P" if metrics.get("MAV") != "P" else "N"
        row["env_vector"] = cvss31.to_vector(metrics)
    elif case == "env_modifications":
        row["env_modifications"]["CR"] = "L" if row["env_modifications"].get("CR") != "L" else "H"
    elif case == "effective_controls":
        row["inputs"]["controls"]["waf"]["value"] = "SYNTHETIC invented eligible WAF"
    elif case == "control_decision":
        decision = next(iter(row["inputs"]["control_applicability"].values()))
        decision["status"] = "applied" if decision["status"] != "applied" else "withheld"
    elif case == "native_fallback":
        row["native_fallback"] = "SYNTHETIC wrong native basis"
    elif case == "native_risk":
        row = next(item for item in payload["scores"] if item["cvss_version_used"] is None)
        row["risk"] = 1.0 if row["risk"] != 1.0 else 2.0
        row["band"] = scoring.band(
            row["risk"], payload["configuration"]["validated"]["weights.yaml"]
        )
    else:
        raise AssertionError(case)
    return synthetic_rehash(payload)


@pytest.mark.parametrize("case", CASES)
def test_rehashed_numerical_contradiction_is_not_snapshot_verified(synthetic_snapshot, case):
    payload = synthetic_change(deepcopy(synthetic_snapshot), case)
    assert payload != synthetic_snapshot
    before = assessment_snapshot._canonical(payload)
    with pytest.raises(ConfigError, match="assessment snapshot"):
        assessment_snapshot.validate_snapshot(payload)
    assert assessment_snapshot._canonical(payload) == before


@pytest.mark.parametrize("case", ["risk_with_consistent_band", "base_score", "native_risk"])
def test_cli_rejects_wrong_arithmetic_without_publishing_success(
    tmp_path, synthetic_snapshot, case
):
    path = tmp_path / "synthetic_wrong_arithmetic.json"
    path.write_text(json.dumps(synthetic_change(deepcopy(synthetic_snapshot), case)))
    before = path.read_bytes()
    output, error = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(error):
        status = main(
            [
                "--config",
                str(ROOT / "config"),
                "research",
                "snapshot-verify",
                "--run-id",
                "snapshot",
                "--snapshot",
                str(path),
                "--json",
            ]
        )
    assert status == 2
    assert output.getvalue() == ""
    assert "assessment snapshot" in error.getvalue()
    assert "Traceback" not in error.getvalue()
    assert path.read_bytes() == before


def test_current_scores_replay_without_changing_any_encoded_input(synthetic_snapshot):
    before = assessment_snapshot._canonical(synthetic_snapshot)
    summary = assessment_snapshot._score_arithmetic_summary(synthetic_snapshot)
    assert summary["total"] == len(synthetic_snapshot["scores"])
    assert summary["replayed"] == summary["total"]
    assert summary["cvss_checked"] > 0
    assert summary["unknown"] == []
    assert assessment_snapshot._canonical(synthetic_snapshot) == before


@pytest.mark.parametrize("change", ["vector_order", "narrative", "extra_notes"])
def test_non_numeric_representation_changes_do_not_mutate_or_block_replay(
    synthetic_snapshot, change
):
    payload = deepcopy(synthetic_snapshot)
    row = synthetic_scored_row(payload)
    if change == "vector_order":
        prefix, *metrics = row["env_vector"].split("/")
        row["env_vector"] = "/".join([prefix, *reversed(metrics)])
    elif change == "narrative":
        row["reason"] = "SYNTHETIC alternate explanation, unchanged mathematics"
        row["fix"] = "SYNTHETIC alternative safe wording"
        for decision in row["inputs"]["control_applicability"].values():
            decision["limitation"] = "SYNTHETIC alternate caveat"
    else:
        row["inputs"]["synthetic_extra_notes"] = "SYNTHETIC uninterpreted metadata"
    synthetic_rehash(payload)
    before = assessment_snapshot._canonical(payload)
    assessment_snapshot.validate_snapshot(payload)
    summary = assessment_snapshot._score_arithmetic_summary(payload)
    assert summary["replayed"] == summary["total"]
    assert summary["unknown"] == []
    assert assessment_snapshot._canonical(payload) == before


def test_known_band_mapping_still_checks_legacy_input_records(synthetic_snapshot):
    payload = deepcopy(synthetic_snapshot)
    row = synthetic_scored_row(payload)
    row["inputs"] = {}
    row["band"] = "Low" if row["band"] != "Low" else "Critical"
    synthetic_rehash(payload)
    with pytest.raises(ConfigError, match="scores.band"):
        assessment_snapshot.validate_snapshot(payload)


@pytest.mark.parametrize("value", [True, 1, None, []])
def test_legacy_policy_does_not_waive_declared_environment_metric_types(synthetic_snapshot, value):
    payload = deepcopy(synthetic_snapshot)
    row = synthetic_scored_row(payload)
    row["inputs"] = {}
    row["env_modifications"]["MAV"] = value
    synthetic_rehash(payload)
    with pytest.raises(ConfigError, match="scores.env_modifications"):
        assessment_snapshot.validate_snapshot(payload)


@pytest.mark.parametrize(
    "missing", ["policy", "inputs", "weights", "matching_weights", "field", "services", "profile"]
)
def test_unavailable_history_is_explicitly_unreplayed_not_replaced(synthetic_snapshot, missing):
    payload = deepcopy(synthetic_snapshot)
    row = synthetic_scored_row(payload)
    if missing == "policy":
        row["inputs"]["context_policy"] = "SYNTHETIC unsupported historical policy"
    elif missing == "inputs":
        row["inputs"] = {}
    elif missing == "weights":
        payload["configuration"]["validated"].pop("weights.yaml")
    elif missing == "matching_weights":
        row["weights_hash"] = "SYNTHETIC unavailable historical weights"
    elif missing == "field":
        row.pop("threat_multiplier")
    elif missing == "services":
        next(host for host in payload["hosts"] if host["ip"] == row["host_ip"]).pop("services")
    else:
        row["inputs"] = {"context_policy": row["inputs"]["context_policy"]}
        payload["profiles"] = [
            item for item in payload["profiles"] if item["host_ip"] != row["host_ip"]
        ]
    synthetic_rehash(payload)
    before = assessment_snapshot._canonical(payload)
    assessment_snapshot.validate_snapshot(payload)
    summary = assessment_snapshot._score_arithmetic_summary(payload)
    assert summary["replayed"] < summary["total"]
    assert summary["unknown"]
    assert all(isinstance(item, str) and item for item in summary["unknown"])
    assert assessment_snapshot._canonical(payload) == before


def test_a_missing_optional_field_cannot_hide_a_known_current_risk_contradiction(
    synthetic_snapshot,
):
    payload = synthetic_change(deepcopy(synthetic_snapshot), "risk_with_consistent_band")
    synthetic_scored_row(payload).pop("threat_multiplier")
    synthetic_rehash(payload)
    with pytest.raises(ConfigError, match="scores.risk"):
        assessment_snapshot.validate_snapshot(payload)


def test_v4_metadata_is_not_reinterpreted_as_supported_v3_arithmetic(synthetic_snapshot):
    payload = deepcopy(synthetic_snapshot)
    row = synthetic_scored_row(payload)
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    selected = next(
        item
        for item in payload["enrichments"][row["finding_id"]]
        if item["cve_id"] == row["cve_id"]
    )
    selected["cvss40_vector"] = vector
    row.update(cvss_version_used="4.0", base_vector=vector, env_vector=vector)
    synthetic_rehash(payload)
    before = assessment_snapshot._canonical(payload)
    assessment_snapshot.validate_snapshot(payload)
    summary = assessment_snapshot._score_arithmetic_summary(payload)
    assert summary["replayed"] < summary["total"]
    assert any("4.0 arithmetic is not implemented" in item for item in summary["unknown"])
    assert assessment_snapshot._canonical(payload) == before


def test_empty_assessment_does_not_invent_a_score_replay(synthetic_snapshot):
    payload = deepcopy(synthetic_snapshot)
    payload["scores"] = []
    synthetic_rehash(payload)
    assert assessment_snapshot._score_arithmetic_summary(payload) == {
        "total": 0,
        "replayed": 0,
        "cvss_checked": 0,
        "unknown": [],
    }


def test_rejected_export_preserves_the_wrong_record_for_review(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        payload = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        synthetic_change(payload, "risk_with_consistent_band")
        row = synthetic_scored_row(payload)
        changed = store.connection.execute(
            "UPDATE scores SET json=? WHERE run_id=? AND finding_id=?",
            (json.dumps(row), "snapshot", row["finding_id"]),
        )
        assert changed.rowcount == 1
        store.connection.commit()
        before = tuple(store.connection.iterdump())
        with pytest.raises(ConfigError, match="assessment snapshot"):
            assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        assert tuple(store.connection.iterdump()) == before
