"""Invalid review receipts cannot be reopened as successful assessments."""

import json

import pytest

from tests.test_capture_history import capture
from vulnassess import capture_history as history
from vulnassess.errors import ConfigError


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 2),
        ("capture_id", "assessment-other"),
        ("captured_at", "not-a-date"),
        ("result", {"unregistered": True}),
        ("result", {"scan_status": "failed"}),
        ("result", {"scan_status": "complete", "ai_status": "validated", "assessment_summary": []}),
    ],
)
def test_rehashed_invalid_record_is_rejected(tmp_path, field, value):
    directory, result = capture(tmp_path)
    record = history.save(directory, result, config_hash="synthetic")
    record[field] = value
    record["snapshot_hash"] = history._hash(
        {k: v for k, v in record.items() if k != "snapshot_hash"}
    )
    (directory / "review-evidence.json").write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ConfigError, match="schema or hash mismatch"):
        history.load(tmp_path, directory.name)


def test_missing_directory_file_and_invalid_filename(tmp_path):
    with pytest.raises(ConfigError, match="directory is unavailable"):
        history.load(tmp_path, "assessment-missing")
    with pytest.raises(ConfigError, match="Invalid saved assessment filename"):
        history._bytes(tmp_path, "../secret.json")
    with pytest.raises(ConfigError, match="file is unavailable"):
        history._bytes(tmp_path, "missing.json")


@pytest.mark.parametrize("raw", [b"[]", b"{", b"\xff"])
def test_malformed_json_is_not_empty_history(raw):
    with pytest.raises(ConfigError, match="JSON is malformed"):
        history._json(raw)


def test_read_and_write_budgets_are_enforced(tmp_path, monkeypatch):
    directory, result = capture(tmp_path)
    with pytest.raises(ConfigError, match="configuration hash is required"):
        history.save(directory, result)
    monkeypatch.setattr(history, "MAX_BYTES", 1024)
    with pytest.raises(ConfigError, match="result exceeds"):
        history.save(
            directory, {**result, "assessment_summary": {"text": "x" * 2048}}, config_hash="test"
        )
    assert not (directory / "review-evidence.json").exists()
    monkeypatch.setattr(history, "MAX_BYTES", 1)
    with pytest.raises(ConfigError, match="file exceeds"):
        history._bytes(directory, "case.json")
