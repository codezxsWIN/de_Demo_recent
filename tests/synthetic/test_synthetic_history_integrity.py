"""Pure synthetic history-contract checks; no scanner or feed evidence claimed."""

import json
import sqlite3
from hashlib import sha256

import pytest

from vulnassess import run_history
from vulnassess.errors import ConfigError


@pytest.fixture
def history():
    with sqlite3.connect(":memory:") as connection:
        connection.row_factory = sqlite3.Row
        for statement in run_history.DDL:
            connection.execute(statement)
        connection.execute("CREATE TABLE finding_runs (run_id TEXT, finding_id TEXT)")
        yield connection


def write_payload(connection, text):
    digest = sha256(text.encode("utf-8")).hexdigest()
    connection.execute(
        "INSERT INTO run_intelligence VALUES ('synthetic-run', 1, ?, ?)", (digest, text)
    )


@pytest.mark.parametrize("text", ["{", "null", "[]", '"synthetic"', "1"])
def test_hash_valid_but_invalid_json_or_schema_is_rejected(history, text):
    write_payload(history, text)
    with pytest.raises(ConfigError, match="invalid intelligence snapshot|unknown.*schema"):
        run_history.snapshot(history, "synthetic-run")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", 2, "unknown.*schema"),
        ("run_id", "synthetic-other", "run mismatch"),
        ("origin", "untrusted", "invalid.*fields"),
        ("status", "successful", "invalid.*fields"),
        ("feeds", [], "invalid.*fields"),
        ("enrichments", {}, "invalid.*fields"),
        ("enrichments", [None], "invalid.*fields"),
        ("matching", [], "invalid.*fields"),
    ],
)
def test_valid_hash_cannot_bypass_snapshot_contract(history, field, value, message):
    payload = {
        "schema_version": 1,
        "run_id": "synthetic-run",
        "origin": "native",
        "status": "captured",
        "feeds": {},
        "enrichments": [],
        "matching": None,
    }
    payload[field] = value
    write_payload(history, json.dumps(payload))
    with pytest.raises(ConfigError, match=message):
        run_history.snapshot(history, "synthetic-run")


def test_invalid_latest_snapshot_never_falls_back_to_valid_previous_revision(history):
    run_history.append_snapshot(history, "synthetic-run", {}, [])
    original = run_history.snapshot(history, "synthetic-run")
    history.execute("INSERT INTO run_intelligence VALUES ('synthetic-run', 2, 'wrong-hash', '{}')")
    with pytest.raises(ConfigError, match="hash mismatch"):
        run_history.snapshot(history, "synthetic-run")
    row = history.execute("SELECT * FROM run_intelligence WHERE revision = 1").fetchone()
    assert row["snapshot_hash"] == original["snapshot_hash"]


def test_corrupt_latest_snapshot_blocks_append_without_changing_history(history):
    write_payload(history, "{")
    before = history.execute("SELECT * FROM run_intelligence").fetchall()
    with pytest.raises(ConfigError, match="invalid intelligence snapshot"):
        run_history.append_snapshot(history, "synthetic-run", {}, [])
    assert history.execute("SELECT * FROM run_intelligence").fetchall() == before


def test_unenriched_run_exposes_missing_intelligence_without_claiming_legacy(history):
    run_history.append_snapshot(history, "synthetic-run", {}, [], status="not_enriched")
    result = run_history.status(history, "synthetic-run")
    assert result["intelligence_revision"] == 1
    assert result["limitations"] == ["No intelligence snapshot has been captured for this run yet."]


def test_distinct_matching_state_appends_but_key_order_does_not(history):
    run_history.append_snapshot(history, "synthetic-run", {}, [], matching={"a": 1, "b": 2})
    first = run_history.snapshot(history, "synthetic-run")
    run_history.append_snapshot(history, "synthetic-run", {}, [], matching={"b": 2, "a": 1})
    assert run_history.snapshot(history, "synthetic-run") == first
    run_history.append_snapshot(history, "synthetic-run", {}, [], matching={"a": 2, "b": 2})
    second = run_history.snapshot(history, "synthetic-run")
    assert second["revision"] == 2
    assert second["snapshot_hash"] != first["snapshot_hash"]
    assert history.execute("SELECT COUNT(*) FROM run_intelligence").fetchone()[0] == 2
