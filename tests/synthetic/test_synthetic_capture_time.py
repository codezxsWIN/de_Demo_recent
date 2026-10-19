"""Copied filesystem times cannot masquerade as recorded scanner-capture chronology."""

import json
import os
from datetime import datetime

import pytest

from tests.synthetic.test_synthetic_saved_case_discovery import (
    ADDRESS,
    SCOPE,
    TARGET,
    write_capture,
)
from vulnassess import capture_history
from vulnassess.errors import ConfigError
from vulnassess.saved_cve_case import load_saved_cve_case


def timestamp(directory, value):
    path = directory / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["captured_at"] = value
    path.write_text(json.dumps(manifest))


def receipt(directory):
    return capture_history.save(
        directory,
        {
            "target": TARGET,
            "resolved_ip": ADDRESS,
            "scan_status": "complete",
            "ai_status": "not_attempted",
            "analyst": None,
            "ai_attempts": [],
            "assessment_summary": {},
        },
        config_hash="SYNTHETIC config",
    )


def load(root):
    return load_saved_cve_case(root, TARGET, SCOPE)


def test_undated_legacy_capture_stays_unknown_after_files_are_copied(tmp_path):
    directory = write_capture(tmp_path, "assessment-synthetic-legacy", 1700000000)
    result = load(tmp_path)
    assert result["captured_at"] is None
    assert result["capture_time_source"] == "unknown"
    assert "not recorded" in result["capture_time_warning"]
    os.utime(directory / "manifest.json", (1900000000, 1900000000))
    os.utime(directory, (1900000000, 1900000000))
    assert load(tmp_path)["captured_at"] is None


def test_explicit_manifest_capture_time_is_not_replaced_by_mtime(tmp_path):
    directory = write_capture(tmp_path, "assessment-synthetic-dated", 1900000000)
    timestamp(directory, "2020-01-01T12:00:00+00:00")
    os.utime(directory / "manifest.json", (1900000000, 1900000000))
    result = load(tmp_path)
    assert result["captured_at"] == "2020-01-01T12:00:00+00:00"
    assert result["capture_time_source"] == "manifest"


def test_hash_bound_receipt_time_survives_a_copy(tmp_path):
    directory = write_capture(tmp_path, "assessment-synthetic-receipt", 1700000000)
    record = receipt(directory)
    os.utime(directory / "manifest.json", (1900000000, 1900000000))
    os.utime(directory, (1900000000, 1900000000))
    result = load(tmp_path)
    assert result["captured_at"] == record["captured_at"]
    assert result["capture_time_source"] == "review_receipt"


def test_selection_uses_recorded_chronology_not_copy_order(tmp_path):
    older = write_capture(tmp_path, "assessment-synthetic-old", 1900000000)
    newer = write_capture(tmp_path, "assessment-synthetic-new", 1600000000)
    timestamp(older, "2020-01-01T00:00:00Z")
    timestamp(newer, "2022-01-01T00:00:00Z")
    os.utime(older, (1900000000, 1900000000))
    os.utime(newer, (1600000000, 1600000000))
    assert load(tmp_path)["evidence_directory"] == str(newer)


def test_ambiguous_undated_captures_do_not_claim_a_newest_capture(tmp_path):
    write_capture(tmp_path, "assessment-synthetic-one", 1700000000)
    write_capture(tmp_path, "assessment-synthetic-two", 1900000000)
    with pytest.raises(ConfigError, match="unknown|ambiguous|recorded capture time"):
        load(tmp_path)


@pytest.mark.parametrize("value", ["not-a-date", "2020-01-01T00:00:00", True, {"bad": "date"}])
def test_malformed_declared_capture_time_cannot_be_silently_replaced(tmp_path, value):
    directory = write_capture(tmp_path, "assessment-synthetic-invalid-time", 1900000000)
    timestamp(directory, value)
    with pytest.raises(ConfigError, match="time|timestamp"):
        load(tmp_path)


def test_corrupt_newest_recorded_capture_does_not_fall_back_to_an_older_copy(tmp_path):
    older = write_capture(tmp_path, "assessment-synthetic-old-valid", 1900000000)
    newer = write_capture(tmp_path, "assessment-synthetic-new-corrupt", 1600000000)
    timestamp(older, "2020-01-01T00:00:00Z")
    timestamp(newer, "2022-01-01T00:00:00Z")
    (newer / "case.json").write_text("{}")
    os.utime(older, (1900000000, 1900000000))
    os.utime(newer, (1600000000, 1600000000))
    with pytest.raises(ConfigError, match="hash"):
        load(tmp_path)


def test_conflicting_manifest_and_receipt_times_fail_closed(tmp_path):
    directory = write_capture(tmp_path, "assessment-synthetic-conflict", 1700000000)
    timestamp(directory, "2020-01-01T00:00:00Z")
    record = receipt(directory)
    record["captured_at"] = "2021-01-01T00:00:00+00:00"
    core = {key: value for key, value in record.items() if key != "snapshot_hash"}
    record["snapshot_hash"] = capture_history._hash(core)
    (directory / "review-evidence.json").write_text(json.dumps(record))
    with pytest.raises(ConfigError, match="time|timestamp"):
        load(tmp_path)


def test_new_receipt_preserves_the_manifest_collection_time(tmp_path):
    directory = write_capture(tmp_path, "assessment-synthetic-publication", 1700000000)
    timestamp(directory, "2020-01-01T00:00:00Z")
    record = receipt(directory)
    assert datetime.fromisoformat(record["captured_at"]) == datetime.fromisoformat(
        "2020-01-01T00:00:00+00:00"
    )


def test_known_chronology_discloses_undated_matching_captures(tmp_path):
    dated = write_capture(tmp_path, "assessment-synthetic-dated", 1600000000)
    timestamp(dated, "2022-01-01T00:00:00Z")
    write_capture(tmp_path, "assessment-synthetic-undated", 1900000000)
    result = load(tmp_path)
    assert result["evidence_directory"] == str(dated)
    assert (
        "undated matching captures cannot be chronologically compared"
        in result["capture_time_warning"]
    )


def test_matching_equal_timestamps_disclose_the_tie(tmp_path):
    for name in ("assessment-synthetic-one", "assessment-synthetic-two"):
        timestamp(write_capture(tmp_path, name, 1700000000), "2022-01-01T00:00:00Z")
    assert "not collection chronology" in load(tmp_path)["capture_time_warning"]


def test_discovery_budget_refuses_instead_of_silently_excluding_captures(tmp_path):
    for number in range(101):
        (tmp_path / f"assessment-synthetic-{number}").mkdir()
    with pytest.raises(ConfigError, match="100 directories"):
        load(tmp_path)


@pytest.mark.parametrize("with_receipt", [False, True])
def test_parsed_case_uses_the_exact_verified_bytes_not_a_second_read(
    tmp_path, monkeypatch, with_receipt
):
    from vulnassess import saved_cve_case

    directory = write_capture(tmp_path, "assessment-synthetic-changing", 1700000000)
    if with_receipt:
        receipt(directory)
    module = capture_history if with_receipt else saved_cve_case
    method = "_bytes" if with_receipt else "_capture_bytes"
    original = getattr(module, method)
    reads = []

    def read(capture_directory, name, *args):
        raw = original(capture_directory, name, *args)
        if name == "case.json":
            reads.append(name)
            (directory / "case.json").write_text("{}")
        return raw

    monkeypatch.setattr(module, method, read)
    result = load(tmp_path)
    assert result["payload"]["findings"][0]["cve_ids"] == ["CVE-2022-0543"]
    assert reads == ["case.json"]
    assert (directory / "case.json").read_text() == "{}"


@pytest.mark.parametrize("value", [None, "not-a-date", "2020-01-01T00:00:00", True])
def test_invalid_manifest_time_does_not_publish_a_new_receipt(tmp_path, value):
    directory = write_capture(tmp_path, "assessment-synthetic-invalid-publication", 1700000000)
    timestamp(directory, value)
    with pytest.raises(ConfigError, match="timestamp"):
        receipt(directory)
    assert not (directory / "review-evidence.json").exists()


def test_naive_receipt_timestamp_fails_even_with_recomputed_hash(tmp_path):
    directory = write_capture(tmp_path, "assessment-synthetic-naive", 1700000000)
    record = receipt(directory)
    record["captured_at"] = "2020-01-01T00:00:00"
    core = {key: value for key, value in record.items() if key != "snapshot_hash"}
    record["snapshot_hash"] = capture_history._hash(core)
    (directory / "review-evidence.json").write_text(json.dumps(record))
    with pytest.raises(ConfigError, match="schema or hash mismatch"):
        load(tmp_path)
