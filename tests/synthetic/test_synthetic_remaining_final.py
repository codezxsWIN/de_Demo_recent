"""Final fallback and corruption contracts use synthetic records and inert boundaries."""

import copy
import json
import time
from dataclasses import replace
from unittest.mock import Mock

import pytest

from tests.synthetic.test_synthetic_governance_edges import promoted as promoted
from tests.synthetic.test_synthetic_ui_final import app as app
from tests.test_all import make_finding
from tests.test_assessment_snapshot import ROOT, SYNTHETIC, prepared_store
from vulnassess import cli, explain, orchestrator, pipeline, self_defence, unify
from vulnassess.errors import ConfigError
from vulnassess.orchestrator import ScannerCommand
from vulnassess.ui.reader import ReadOnlyStore


def test_rationale_validator_rejects_control_characters():
    accepted, validation = explain.validate("Synthetic\x00 sentence.", {})
    assert not accepted
    assert "non-printable or non-ascii characters" in validation["problems"]


def test_absent_network_profile_becomes_a_verification_action():
    actions = self_defence.prioritize({"checks": [], "active_profiles": []})
    assert actions[0]["basis"] == ["active_profiles"]
    assert actions[0]["kind"] == "not verified"


def test_first_device_check_is_a_baseline_without_inventing_changes():
    assert self_defence.compare(None, {"checks": []}) == {"status": "baseline", "changes": []}


@pytest.mark.parametrize("tool", ["zap", "unknown"])
def test_legacy_counting_parses_captures_and_rejects_unknown_tools(tool):
    command = ScannerCommand(tool, (), SYNTHETIC / "synthetic_zap_dvwa.json")
    if tool == "unknown":
        with pytest.raises(ConfigError, match="unknown scanner"):
            orchestrator._finding_count(command, "synthetic", "172.28.0.11")
    else:
        assert orchestrator._finding_count(command, "synthetic", "172.28.0.11") > 0


def test_requested_cve_comparison_uses_only_its_recorded_scores(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        identity = next(score.cve_id for score in store.scores("snapshot") if score.cve_id)
        rendered = pipeline.two_machine_table(store, "snapshot", cve=identity)
        assert identity in rendered


def test_read_only_query_failure_is_actionable_and_leaves_store_unchanged(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        before = [item.to_json() for item in store.scores("snapshot")]
    with ReadOnlyStore(tmp_path / "assessment.db") as store:
        with pytest.raises(ConfigError, match="cannot read stored UI records"):
            store._rows("SELECT * FROM missing_synthetic_table")
    with ReadOnlyStore(tmp_path / "assessment.db") as store:
        assert store.run("snapshot")["scores"] == before


def test_merge_detects_a_projection_that_drops_raw_source_identity(monkeypatch):
    constructor = unify.UnifiedFinding

    def corrupted_projection(**kwargs):
        return replace(constructor(**kwargs), source_finding_ids=("synthetic-wrong-source",))

    monkeypatch.setattr(unify, "UnifiedFinding", corrupted_projection)
    original = make_finding()
    with pytest.raises(ConfigError, match="preserve every source finding exactly once"):
        unify.unify_findings([original])
    assert original.id != "synthetic-wrong-source"


@pytest.mark.parametrize("missing", ["run", "context"])
def test_hybrid_preview_refuses_missing_run_or_context(tmp_path, promoted, capsys, missing):
    _, manifest = promoted
    path = tmp_path / "synthetic_manifest.json"
    path.write_text(json.dumps(manifest.to_json()))
    with prepared_store(str(tmp_path)) as store:
        if missing == "context":
            store.connection.execute("DELETE FROM context_profiles WHERE run_id = ?", ("snapshot",))
            store.connection.commit()
    args = [
        "--config",
        str(ROOT / "config"),
        "--db",
        str(tmp_path / "assessment.db"),
        "model",
        "hybrid-preview",
        "--run-id",
        "synthetic-missing" if missing == "run" else "snapshot",
        "--model",
        str(ROOT / "models/synthetic-role-model.json"),
        "--manifest",
        str(path),
        "--as-of",
        "2026-10-12",
    ]
    assert cli.main(args) == ConfigError.exit_code
    expected = "MISSING: run" if missing == "run" else "MISSING: context profile"
    assert expected in capsys.readouterr().err


def test_plan_history_skips_a_recent_capture_for_another_host(app):
    app._recent_live_cases["172.28.0.10"] = (
        time.monotonic(),
        {"payload": {"hosts": [], "run": {}}},
    )
    context = app.plan_context("172.28.0.10", "snapshot")
    assert context["target_ip"] == "172.28.0.10"
    assert context["probe_options"]


def test_replay_notifies_capture_consumer_without_starting_scanners(app, monkeypatch):
    from vulnassess.ui import server

    with ReadOnlyStore(app.database) as store:
        payload = store.run("snapshot")
    payload = copy.deepcopy(payload)
    payload["hosts"] = [host for host in payload["hosts"] if host["ip"] == "172.28.0.10"]
    payload["findings"] = [
        finding for finding in payload["findings"] if finding["host_ip"] == "172.28.0.10"
    ]
    identities = {finding["id"] for finding in payload["findings"]}
    for section in ("scores", "enrichments"):
        payload[section] = [item for item in payload[section] if item["finding_id"] in identities]
    payload["context"] = [item for item in payload["context"] if item["host_ip"] == "172.28.0.10"]
    payload["scanner_coverage"] = {
        "nmap": "top 100 TCP ports, SYNTHETIC retained test profile",
        "nikto": "not run; SYNTHETIC no web scan requested",
    }
    target = "synthetic-retained"
    monkeypatch.setattr(
        server,
        "load_saved_cve_case",
        Mock(
            return_value={
                "target": target,
                "resolved_ip": "172.28.0.10",
                "captured_at": "2026-10-01T00:00:00Z",
                "payload": payload,
            }
        ),
    )
    monkeypatch.setattr(server, "refresh_saved_case", Mock(return_value=payload))
    monkeypatch.setattr(
        server.analyst,
        "analyze_optional",
        Mock(return_value={"analyst": None, "ai_status": "unavailable", "ai_attempts": []}),
    )
    captures = []
    result = app.live_report(
        target, "ollama", lambda *_: None, on_capture=captures.append, replay_saved=True
    )
    assert len(captures) == 1
    assert captures[0]["assessment_summary"]["historical_capture"] is True
    assert result["scan_status"] == "complete"
    assert result["reused_scan"] is True
    server.live_assessment.run.assert_not_called()
