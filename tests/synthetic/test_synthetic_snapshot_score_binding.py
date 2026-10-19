"""Synthetic cross-record consistency, not proof of capture origin or score accuracy."""

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy

import pytest

from tests.test_assessment_snapshot import ROOT, SETTINGS, prepared_store
from vulnassess import assessment_snapshot
from vulnassess.cli import main
from vulnassess.errors import ConfigError


@pytest.fixture(scope="module")
def synthetic_snapshot(tmp_path_factory):
    directory = tmp_path_factory.mktemp("synthetic_score_binding")
    with prepared_store(str(directory)) as store:
        return assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")


def synthetic_rehash(payload):
    core = {key: value for key, value in payload.items() if key != "snapshot_hash"}
    payload["snapshot_hash"] = assessment_snapshot._digest(core)
    return payload


def synthetic_scored_row(payload):
    return next(row for row in payload["scores"] if row.get("cvss_version_used") == "3.1")


def synthetic_change(payload, case):
    row = synthetic_scored_row(payload)
    if case == "unknown_cve":
        row["cve_id"] = "CVE-1999-99999"
    elif case == "different_finding_cve":
        other = next(key for key in payload["enrichments"] if key != row["finding_id"])
        selected = deepcopy(payload["enrichments"][row["finding_id"]][0])
        selected.update(finding_id=other, cve_id="CVE-1999-99999", match_method="cpe_range")
        payload["enrichments"][other] = [selected]
        row["cve_id"] = selected["cve_id"]
    elif case == "kev":
        row["kev"] = not row["kev"]
    elif case == "epss_percentile":
        row["epss_percentile"] = 0.123456
    elif case == "missing_percentile":
        row["epss_percentile"] = None
    elif case == "base_vector":
        row["base_vector"] = row["base_vector"].replace("AV:N", "AV:L")
    elif case == "missing_base_vector":
        row["base_vector"] = None
    elif case == "unsupported_version":
        row["cvss_version_used"] = "5.0"
    elif case == "wrong_selected_version":
        row["cvss_version_used"] = "4.0"
    elif case == "role":
        row["inputs"]["role"]["value"] = "workstation"
    elif case == "role_source":
        row["inputs"]["role"]["source"] = "manual"
    elif case == "boolean_confidence":
        row["inputs"]["role"]["confidence"] = True
        profile = next(item for item in payload["profiles"] if item["host_ip"] == row["host_ip"])
        profile["role"]["confidence"] = 1.0
    elif case == "missing_profile":
        payload["profiles"] = [
            profile for profile in payload["profiles"] if profile["host_ip"] != row["host_ip"]
        ]
    elif case == "exposure":
        value = row["inputs"]["exposure"]["value"]
        row["inputs"]["exposure"]["value"] = (
            "internal" if value == "internet_facing" else "internet_facing"
        )
    elif case == "exposure_evidence":
        row["inputs"]["exposure"]["evidence"] = "SYNTHETIC unrelated evidence"
    elif case == "observed_controls":
        row["inputs"]["observed_controls"] = {}
    elif case == "manual":
        row["inputs"]["manual"] = {
            "criticality": {
                "value": 5,
                "confidence": 1.0,
                "source": "manual",
                "evidence": "SYNTHETIC unrelated metadata",
            }
        }
    elif case == "explicit_match":
        match = next(
            item
            for item in payload["enrichments"][row["finding_id"]]
            if item["match_method"] == "explicit"
        )
        match["cve_id"] = "CVE-1999-99999"
    else:
        raise AssertionError(case)
    return synthetic_rehash(payload)


CASES = [
    "unknown_cve",
    "different_finding_cve",
    "kev",
    "epss_percentile",
    "missing_percentile",
    "base_vector",
    "missing_base_vector",
    "unsupported_version",
    "wrong_selected_version",
    "role",
    "role_source",
    "boolean_confidence",
    "missing_profile",
    "exposure",
    "exposure_evidence",
    "observed_controls",
    "manual",
    "explicit_match",
]


@pytest.mark.parametrize("case", CASES)
def test_rehashed_contradictory_score_cannot_claim_snapshot_consistency(synthetic_snapshot, case):
    payload = synthetic_change(deepcopy(synthetic_snapshot), case)
    assert payload != synthetic_snapshot, "mutation must exercise a real difference"
    original = deepcopy(payload)
    with pytest.raises(ConfigError, match="assessment snapshot"):
        assessment_snapshot.validate_snapshot(payload)
    assert payload == original


@pytest.mark.parametrize("case", ["unknown_cve", "kev", "role", "explicit_match"])
def test_snapshot_cli_never_prints_verified_for_cross_record_contradiction(
    tmp_path, synthetic_snapshot, case
):
    payload = synthetic_change(deepcopy(synthetic_snapshot), case)
    path = tmp_path / "synthetic_contradictory_snapshot.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    before = path.read_bytes()
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        code = main(
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
    assert code == 2
    assert output.getvalue() == ""
    assert "assessment snapshot" in errors.getvalue()
    assert "Traceback" not in errors.getvalue()
    assert path.read_bytes() == before


def test_valid_score_and_profile_links_are_not_rewritten(synthetic_snapshot):
    payload = deepcopy(synthetic_snapshot)
    before = deepcopy(payload)
    assert assessment_snapshot.validate_snapshot(payload) is payload
    assert payload == before


def test_range_derived_cve_does_not_have_to_be_a_scanner_named_id(synthetic_snapshot):
    payload = deepcopy(synthetic_snapshot)
    row = synthetic_scored_row(payload)
    match = next(
        item
        for item in payload["enrichments"][row["finding_id"]]
        if item["cve_id"] == row["cve_id"]
    )
    match["match_method"] = "cpe_range"
    finding = next(item for item in payload["findings"] if item["id"] == row["finding_id"])
    finding["cve_ids"] = [cve for cve in finding["cve_ids"] if cve != row["cve_id"]]
    synthetic_rehash(payload)
    before = deepcopy(payload)
    assert assessment_snapshot.validate_snapshot(payload) is payload
    assert payload == before


@pytest.mark.parametrize("omit", [False, True])
def test_sparse_legacy_score_inputs_stay_unknown_without_new_metadata(synthetic_snapshot, omit):
    payload = deepcopy(synthetic_snapshot)
    row = synthetic_scored_row(payload)
    row["inputs"] = {}
    if omit:
        row.pop("inputs")
    synthetic_rehash(payload)
    before = deepcopy(payload)
    assert assessment_snapshot.validate_snapshot(payload) is payload
    assert payload == before


def test_numeric_confidence_representations_are_compatible_but_not_changed(synthetic_snapshot):
    payload = deepcopy(synthetic_snapshot)
    row = synthetic_scored_row(payload)
    profile = next(item for item in payload["profiles"] if item["host_ip"] == row["host_ip"])
    profile["role"]["confidence"] = 1.0
    row["inputs"]["role"]["confidence"] = 1
    synthetic_rehash(payload)
    before = deepcopy(payload)
    assert assessment_snapshot.validate_snapshot(payload) is payload
    assert payload == before


@pytest.mark.parametrize("case", ["role", "kev", "unknown_cve"])
def test_export_rejects_stale_or_contradictory_score_without_overwriting_rows(tmp_path, case):
    with prepared_store(str(tmp_path)) as store:
        payload = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        synthetic_change(payload, case)
        row = synthetic_scored_row(payload)
        result = store.connection.execute(
            "UPDATE scores SET json=? WHERE run_id=? AND finding_id=?",
            (json.dumps(row), "snapshot", row["finding_id"]),
        )
        assert result.rowcount == 1
        store.connection.commit()
        before = tuple(store.connection.iterdump())
        with pytest.raises(ConfigError, match="assessment snapshot"):
            assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        assert tuple(store.connection.iterdump()) == before
