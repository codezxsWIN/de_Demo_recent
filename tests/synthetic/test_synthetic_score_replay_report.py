"""Synthetic report diagnostics; mocks establish row logic, never score correctness."""

import io
import json
import re
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_assessment_snapshot import ROOT, SETTINGS, prepared_store
from vulnassess import assessment_snapshot, audit, report, unify
from vulnassess.cli import main
from vulnassess.errors import ConfigError
from vulnassess.schema import Rationale
from vulnassess.store import Store


@pytest.fixture
def synthetic_diagnostics(monkeypatch):
    """Isolate report row decisions from the parent-owned arithmetic implementation."""
    frozen = {
        "run": {"run_id": "synthetic-report"},
        "evidence_status": "TESTED WITH MOCKS",
        "snapshot_hash": "a" * 64,
        "model_hash": None,
        "hosts": [],
        "findings": [],
        "scores": [{"synthetic_retained_input": True}],
    }
    # Matching identity does not make this freshly built object the replay input.
    live = {**deepcopy(frozen), "synthetic_live_only": True}
    load = Mock(return_value=frozen)
    build = Mock(return_value=live)
    replay = Mock(return_value={"total": 3, "replayed": 3, "cvss_checked": 2, "unknown": []})
    monkeypatch.setattr(assessment_snapshot, "load_snapshot", load)
    monkeypatch.setattr(assessment_snapshot, "build_snapshot", build)
    # Mock only row logic here; the real helper is exercised by integration cases below.
    monkeypatch.setattr(assessment_snapshot, "_score_arithmetic_summary", replay)
    preview = {"raw_count": 0, "unified_count": 0, "candidates": [], "groups": []}
    monkeypatch.setattr(unify, "unify_run", Mock(return_value=Mock(to_json=lambda: preview)))
    store = Mock()
    store.run_info.return_value = {"run_id": "synthetic-report"}
    store.intelligence_trace.return_value = None
    return SimpleNamespace(
        settings=Mock(),
        store=store,
        frozen=frozen,
        live=live,
        load=load,
        build=build,
        replay=replay,
    )


def synthetic_collect(state, snapshot_path=Path("synthetic_frozen_assessment.json")):
    return audit.collect_report_audit(
        state.settings, state.store, "synthetic-report", snapshot_path=snapshot_path
    )


def synthetic_arithmetic_row(result):
    rows = [row for row in result["rows"] if row["component"] == "score arithmetic"]
    assert len(rows) == 1
    assert set(rows[0]) == {"component", "evidence_status", "artifact_hash", "summary", "path"}
    return rows[0]


@pytest.mark.parametrize("evidence_status", ["VERIFIED", "TESTED WITH MOCKS", "NOT RUN", "MISSING"])
def test_matching_snapshot_replays_loaded_inputs_after_live_match(
    synthetic_diagnostics, evidence_status
):
    state = synthetic_diagnostics
    state.frozen["evidence_status"] = evidence_status
    original = deepcopy(state.frozen)

    def replay(payload):
        state.build.assert_called_once_with(
            state.settings, state.store, "synthetic-report", model_hash=None
        )
        assert payload is state.frozen
        assert payload is not state.live
        return {"total": 3, "replayed": 3, "cvss_checked": 2, "unknown": []}

    state.replay.side_effect = replay
    path = Path("synthetic_retained_assessment.json")
    result = synthetic_collect(state, path)
    row = synthetic_arithmetic_row(result)
    assert row == {
        "component": "score arithmetic",
        "evidence_status": "VERIFIED",
        "artifact_hash": state.frozen["snapshot_hash"],
        "summary": (
            "3/3 scores replayed against retained current policy/weights; reproduction is not "
            "capture authentication or proof method is correct"
        ),
        "path": str(path),
    }
    state.load.assert_called_once_with(path)
    state.replay.assert_called_once_with(state.frozen)
    assert state.frozen == original
    assert result["assessment_evidence_status"] == evidence_status
    assert result["snapshot_hash"] == state.frozen["snapshot_hash"]
    assert result["limitations"] == []
    snapshot_row = next(row for row in result["rows"] if row["component"] == "assessment snapshot")
    assert snapshot_row["evidence_status"] == evidence_status
    assert set(result) == {
        "assessment_evidence_status",
        "snapshot_hash",
        "cohort_hash",
        "rows",
        "intelligence",
        "unification",
        "model_cases",
        "artifacts",
        "limitations",
    }


@pytest.mark.parametrize(
    "replayed,cvss_checked,unknown",
    [
        (0, 0, ["Historical scoring policy is unavailable; retained weights cannot be inferred."]),
        (1, 2, ["Two scores lack retained profile inputs.", "Historical weights are unavailable."]),
        (2, 1, []),
    ],
)
def test_partial_or_unknown_arithmetic_stays_unverified(
    synthetic_diagnostics, replayed, cvss_checked, unknown
):
    state = synthetic_diagnostics
    summary = {"total": 3, "replayed": replayed, "cvss_checked": cvss_checked, "unknown": unknown}
    state.replay.return_value = summary
    original = deepcopy(summary)
    result = synthetic_collect(state)
    row = synthetic_arithmetic_row(result)
    assert row["evidence_status"] == "NOT RUN"
    assert f"{replayed}/3 scores replayed" in row["summary"]
    assert f"{cvss_checked} CVSS scores checked" in row["summary"]
    assert "unverified" in row["summary"]
    assert row["artifact_hash"] == state.frozen["snapshot_hash"]
    assert row["path"] == "synthetic_frozen_assessment.json"
    assert result["limitations"] == unknown
    assert state.replay.return_value == original
    state.replay.assert_called_once_with(state.frozen)


def test_snapshot_without_numeric_scores_is_not_a_vacuous_verification(synthetic_diagnostics):
    state = synthetic_diagnostics
    state.replay.return_value = {"total": 0, "replayed": 0, "cvss_checked": 0, "unknown": []}
    result = synthetic_collect(state)
    row = synthetic_arithmetic_row(result)
    assert row["evidence_status"] == "NOT RUN"
    assert "no numeric scores" in row["summary"].lower()
    assert "0/0" not in row["summary"]
    assert row["artifact_hash"] == state.frozen["snapshot_hash"]
    assert row["path"] == "synthetic_frozen_assessment.json"
    state.replay.assert_called_once_with(state.frozen)


def test_missing_snapshot_does_not_replay_live_scores(synthetic_diagnostics):
    state = synthetic_diagnostics
    result = synthetic_collect(state, None)
    assert synthetic_arithmetic_row(result) == {
        "component": "score arithmetic",
        "evidence_status": "NOT RUN",
        "artifact_hash": "",
        "summary": "No frozen assessment supplied; score arithmetic not replayed",
        "path": "report --snapshot PATH",
    }
    state.replay.assert_not_called()
    state.load.assert_not_called()
    state.build.assert_not_called()
    assert result["assessment_evidence_status"] == "MISSING"
    assert result["snapshot_hash"] is None
    assert result["limitations"] == [
        "The report is not bound to a frozen assessment snapshot; current global feed and "
        "enrichment state may differ from the original run."
    ]
    components = {row["component"]: row for row in result["rows"]}
    assert components["assessment snapshot"]["evidence_status"] == "MISSING"
    assert components["intelligence trace"]["evidence_status"] == "MISSING"
    assert components["ranking"]["evidence_status"] == "MISSING"


@pytest.mark.parametrize(
    "case,message",
    [
        ("run", "belongs to run"),
        ("status", "unsupported evidence_status"),
        ("live", "no longer matches"),
    ],
)
def test_incompatible_snapshot_is_rejected_before_arithmetic(synthetic_diagnostics, case, message):
    state = synthetic_diagnostics
    if case == "run":
        state.frozen["run"]["run_id"] = "synthetic-other-run"
    elif case == "status":
        state.frozen["evidence_status"] = "synthetic-unsupported-status"
    else:
        state.live["snapshot_hash"] = "b" * 64
    with pytest.raises(ConfigError, match=message):
        synthetic_collect(state)
    state.replay.assert_not_called()


def test_arithmetic_contradiction_propagates_without_partial_diagnostics(synthetic_diagnostics):
    state = synthetic_diagnostics
    error = ConfigError("assessment snapshot scores.risk contradicts retained arithmetic")
    state.replay.side_effect = error
    original = deepcopy(state.frozen)
    with pytest.raises(ConfigError) as caught:
        synthetic_collect(state)
    assert caught.value is error
    assert state.frozen == original
    state.store.upsert_score.assert_not_called()
    state.store.upsert_profile.assert_not_called()


def test_unknown_arithmetic_limitations_render_as_escaped_text(synthetic_diagnostics):
    state = synthetic_diagnostics
    reason = "SYNTHETIC missing retained policy <script>untrusted</script> & weights"
    state.replay.return_value = {"total": 3, "replayed": 0, "cvss_checked": 1, "unknown": [reason]}
    result = synthetic_collect(state)
    rendered = report._audit(result)
    assert result["limitations"] == [reason]
    assert "score arithmetic" in rendered
    assert "0/3 scores replayed" in rendered
    assert "1 CVSS scores checked" in rendered
    assert "&lt;script&gt;untrusted&lt;/script&gt; &amp; weights" in rendered
    assert "<script>" not in rendered


def test_report_without_snapshot_renders_not_run_and_preserves_sql(tmp_path):
    """The actual CLI can render the missing-snapshot row without any replay helper."""
    with prepared_store(str(tmp_path)) as store:
        before = tuple(store.connection.iterdump())
        destination = tmp_path / "synthetic_no_snapshot_report.html"
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "--config",
                    str(ROOT / "config"),
                    "--db",
                    str(tmp_path / "assessment.db"),
                    "report",
                    "--run-id",
                    "snapshot",
                    "--out",
                    str(destination),
                    "--json",
                ]
            )
        assert code == 0
        assert stderr.getvalue() == ""
        rendered = destination.read_text(encoding="utf-8")
        row = re.search(r"<tr>\s*<td>score arithmetic</td>(.*?)</tr>", rendered, re.S)
        assert row is not None
        assert "<b>NOT RUN</b>" in row[1]
        assert "No frozen assessment supplied; score arithmetic not replayed" in row[1]
        assert "report --snapshot PATH" in row[1]
        assert tuple(store.connection.iterdump()) == before


def test_live_mismatch_preserves_existing_html_snapshot_and_sql(tmp_path):
    """A stale attachment is rejected before publishing replay diagnostics."""
    with prepared_store(str(tmp_path)) as store:
        payload = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        frozen = assessment_snapshot.save_snapshot(
            payload, tmp_path / "synthetic_stale_report_snapshot.json"
        )
        snapshot_bytes = frozen.read_bytes()
        store.upsert_rationale(
            "snapshot",
            Rationale(store.findings("snapshot")[0].id, "SYNTHETIC later rationale", "template"),
        )
        before = tuple(store.connection.iterdump())
        destination = tmp_path / "synthetic_retained_report.html"
        old_html = b"SYNTHETIC existing report retained on rejection\n"
        destination.write_bytes(old_html)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "--config",
                    str(ROOT / "config"),
                    "--db",
                    str(tmp_path / "assessment.db"),
                    "report",
                    "--run-id",
                    "snapshot",
                    "--out",
                    str(destination),
                    "--snapshot",
                    str(frozen),
                    "--json",
                ]
            )
        assert code == 2
        assert stdout.getvalue() == ""
        assert "live report state no longer matches" in stderr.getvalue()
        assert "Traceback" not in stderr.getvalue()
        assert destination.read_bytes() == old_html
        assert frozen.read_bytes() == snapshot_bytes
        assert tuple(store.connection.iterdump()) == before


def test_actual_current_scores_replay_in_the_report_without_promoting_capture_status(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        payload = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        frozen = assessment_snapshot.save_snapshot(
            payload, tmp_path / "synthetic_current_score_snapshot.json"
        )
        before = tuple(store.connection.iterdump())
        snapshot_bytes = frozen.read_bytes()
        result = audit.collect_report_audit(SETTINGS, store, "snapshot", snapshot_path=frozen)
        total = len(payload["scores"])
        assert total > 0
        assert synthetic_arithmetic_row(result) == {
            "component": "score arithmetic",
            "evidence_status": "VERIFIED",
            "artifact_hash": payload["snapshot_hash"],
            "summary": (
                f"{total}/{total} scores replayed against retained current policy/weights; "
                "reproduction is not capture authentication or proof method is correct"
            ),
            "path": str(frozen),
        }
        assert result["assessment_evidence_status"] == payload["evidence_status"] == "NOT RUN"
        destination = tmp_path / "synthetic_replayed_score_report.html"
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "--config",
                    str(ROOT / "config"),
                    "--db",
                    str(tmp_path / "assessment.db"),
                    "report",
                    "--run-id",
                    "snapshot",
                    "--out",
                    str(destination),
                    "--snapshot",
                    str(frozen),
                    "--json",
                ]
            )
        assert code == 0
        assert stderr.getvalue() == ""
        rendered = destination.read_text(encoding="utf-8")
        row = re.search(r"<tr>\s*<td>score arithmetic</td>(.*?)</tr>", rendered, re.S)
        assert row is not None
        assert "<b>VERIFIED</b>" in row[1]
        assert f"{total}/{total} scores replayed" in row[1]
        assert "reproduction is not capture authentication or proof method is correct" in row[1]
        assert frozen.read_bytes() == snapshot_bytes
        assert tuple(store.connection.iterdump()) == before


@pytest.mark.parametrize("history", ["all_policy", "one_policy", "all_weights", "incomplete"])
def test_actual_unknown_history_keeps_report_arithmetic_unverified(tmp_path, history):
    with prepared_store(str(tmp_path)) as store:
        scores = store.scores("snapshot")
        altered = scores if history.startswith("all_") else scores[:1]
        for score in altered:
            if history == "all_weights":
                retained = replace(score, weights_hash="SYNTHETIC unavailable historical weights")
            else:
                inputs = deepcopy(score.inputs)
                if history == "incomplete":
                    inputs.pop("controls")
                else:
                    inputs["context_policy"] = "SYNTHETIC unsupported historical policy"
                retained = replace(score, inputs=inputs)
            store.upsert_score("snapshot", retained)
        payload = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        frozen = assessment_snapshot.save_snapshot(
            payload, tmp_path / "synthetic_unknown_score_snapshot.json"
        )
        original = deepcopy(payload)
        before = tuple(store.connection.iterdump())
        snapshot_bytes = frozen.read_bytes()
        summary = assessment_snapshot._score_arithmetic_summary(payload)
        assert summary["total"] == len(scores)
        assert summary["replayed"] == len(scores) - len(altered)
        assert summary["cvss_checked"] > 0
        assert len(summary["unknown"]) == len(altered)
        result = audit.collect_report_audit(SETTINGS, store, "snapshot", snapshot_path=frozen)
        row = synthetic_arithmetic_row(result)
        assert row["evidence_status"] == "NOT RUN"
        assert f"{summary['replayed']}/{len(scores)} scores replayed" in row["summary"]
        assert f"{summary['cvss_checked']} CVSS scores checked" in row["summary"]
        assert row["artifact_hash"] == payload["snapshot_hash"]
        assert row["path"] == str(frozen)
        assert result["limitations"] == summary["unknown"]
        assert payload == original
        assert frozen.read_bytes() == snapshot_bytes
        assert tuple(store.connection.iterdump()) == before


def test_actual_empty_snapshot_reports_no_numeric_scores_without_writing_sql(tmp_path):
    with Store(tmp_path / "synthetic_empty_assessment.db") as store:
        store.start_run("synthetic-empty", SETTINGS.config_hash())
        payload = assessment_snapshot.build_snapshot(SETTINGS, store, "synthetic-empty")
        frozen = assessment_snapshot.save_snapshot(
            payload, tmp_path / "synthetic_empty_score_snapshot.json"
        )
        before = tuple(store.connection.iterdump())
        snapshot_bytes = frozen.read_bytes()
        result = audit.collect_report_audit(
            SETTINGS, store, "synthetic-empty", snapshot_path=frozen
        )
        row = synthetic_arithmetic_row(result)
        assert row["evidence_status"] == "NOT RUN"
        assert "no numeric scores" in row["summary"].lower()
        assert "0/0" not in row["summary"]
        assert row["artifact_hash"] == payload["snapshot_hash"]
        assert row["path"] == str(frozen)
        assert result["limitations"] == []
        assert frozen.read_bytes() == snapshot_bytes
        assert tuple(store.connection.iterdump()) == before


@pytest.mark.parametrize("source", ["snapshot", "live"])
def test_actual_arithmetic_rejection_preserves_existing_html_snapshot_and_sql(tmp_path, source):
    with prepared_store(str(tmp_path)) as store:
        payload = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        frozen = assessment_snapshot.save_snapshot(
            payload, tmp_path / "synthetic_contradictory_score_snapshot.json"
        )
        # Preserve a numerically valid range and a consistent band so rejection
        # must expose a replay contradiction rather than a structural violation.
        selected = store.scores("snapshot")[0]
        risk = 1.0 if selected.risk != 1.0 else 2.0
        if source == "live":
            store.upsert_score("snapshot", replace(selected, risk=risk, band="Low"))
        else:
            row = next(row for row in payload["scores"] if row["finding_id"] == selected.finding_id)
            row.update(risk=risk, band="Low")
            core = {key: value for key, value in payload.items() if key != "snapshot_hash"}
            payload["snapshot_hash"] = assessment_snapshot._digest(core)
            frozen.write_text(json.dumps(payload), encoding="utf-8")
        before = tuple(store.connection.iterdump())
        snapshot_bytes = frozen.read_bytes()
        destination = tmp_path / "synthetic_old_arithmetic_report.html"
        old_html = b"SYNTHETIC retained report before arithmetic rejection\n"
        destination.write_bytes(old_html)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "--config",
                    str(ROOT / "config"),
                    "--db",
                    str(tmp_path / "assessment.db"),
                    "report",
                    "--run-id",
                    "snapshot",
                    "--out",
                    str(destination),
                    "--snapshot",
                    str(frozen),
                    "--json",
                ]
            )
        assert code == 2
        assert stdout.getvalue() == ""
        assert "assessment snapshot" in stderr.getvalue()
        assert "replay" in stderr.getvalue()
        assert "Traceback" not in stderr.getvalue()
        assert destination.read_bytes() == old_html
        assert frozen.read_bytes() == snapshot_bytes
        assert tuple(store.connection.iterdump()) == before
