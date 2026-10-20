"""Offline regressions for the UI's retained-evidence AI path."""

import copy
from threading import Lock
from unittest.mock import Mock

import pytest

from tests.synthetic.test_synthetic_replay_completion import IP, ROOT, TARGET, retained_case
from tests.synthetic.test_synthetic_saved_case_discovery import ADDRESS, SCOPE, write_capture
from vulnassess.errors import ConfigError
from vulnassess.saved_cve_case import load_saved_cve_case, load_saved_target_case
from vulnassess.ui import server


@pytest.fixture
def replay_app(tmp_path, monkeypatch):
    app = object.__new__(server.UiApplication)
    app.config_dir = ROOT / "config"
    app.database = tmp_path / "synthetic.db"
    app._live_lock = Lock()
    app._recent_live_cases = {}
    app._last_live_scan = {}
    monkeypatch.setattr(
        app,
        "target_check",
        Mock(return_value={"status": "ready", "resolved_ips": [IP], "missing": []}),
    )
    scanner = Mock(side_effect=AssertionError("No scanner may launch"))
    monkeypatch.setattr(server.live_assessment, "run", scanner)
    analyze = Mock(return_value={"analyst": None, "ai_status": "unavailable", "ai_attempts": []})
    monkeypatch.setattr(server.analyst, "analyze_optional", analyze)
    loader = Mock(return_value=retained_case())
    monkeypatch.setattr(server, "load_saved_target_case", loader)
    return app, loader, analyze, scanner


def test_expired_memory_evidence_remains_available_without_restarting_cooldown(replay_app):
    app, loader, analyze, scanner = replay_app
    case = retained_case()
    before = copy.deepcopy(case)
    app._recent_live_cases[IP] = (server.time.monotonic() - 601, case)
    result = app.live_report(TARGET, "google", lambda *args: None, reuse_recent=True)
    assert result["reused_scan"] is True
    assert result["assessment_summary"]["historical_capture"] is True
    assert result["assessment_summary"]["captured_at"] == case["captured_at"]
    assert case == before
    assert app._last_live_scan == {}
    loader.assert_not_called()
    scanner.assert_not_called()
    assert analyze.call_args.args[2] == "google"
    assert analyze.call_args.kwargs["allow_fallback"] is False


def test_restart_loads_verified_exact_target_without_scanner_or_refresh(replay_app, monkeypatch):
    app, loader, analyze, scanner = replay_app
    refresh = Mock(side_effect=AssertionError("No publisher refresh"))
    monkeypatch.setattr(server, "refresh_saved_case", refresh)
    events = []
    result = app.live_report(TARGET, "google", lambda *args: events.append(args), reuse_recent=True)
    assert result["finding_count"] == 0
    assert result["assessment_summary"]["historical_capture"] is True
    assert all(
        stage in {e[0] for e in events}
        for stage in ("nvd", "epss", "kev", "score", "queue", "rationale")
    )
    assert loader.call_args.args[1] == TARGET
    assert app._recent_live_cases == {} and app._last_live_scan == {}
    scanner.assert_not_called()
    refresh.assert_not_called()
    analyze.assert_called_once()


@pytest.mark.parametrize("failure", ["hash mismatch", "No recent scan or verified saved capture"])
def test_failed_retained_verification_never_calls_model_or_scanner(replay_app, failure):
    app, loader, analyze, scanner = replay_app
    loader.side_effect = ConfigError(failure)
    with pytest.raises(ConfigError, match=failure):
        app.live_report(TARGET, "google", lambda *args: None, reuse_recent=True)
    analyze.assert_not_called()
    scanner.assert_not_called()
    assert app._last_live_scan == {}


def test_changed_address_refuses_model_call(replay_app):
    app, loader, analyze, scanner = replay_app
    loader.return_value = {**retained_case(), "resolved_ip": "192.0.2.55"}
    with pytest.raises(ConfigError, match="address changed"):
        app.live_report(TARGET, "google", lambda *args: None, reuse_recent=True)
    analyze.assert_not_called()
    scanner.assert_not_called()


def test_same_ip_different_endpoint_does_not_reuse_memory_case(replay_app):
    app, loader, _, scanner = replay_app
    app._recent_live_cases[IP] = (
        server.time.monotonic(),
        {**retained_case(), "target": "http://127.0.0.1:9000/"},
    )
    app.live_report(TARGET, "google", lambda *args: None, reuse_recent=True)
    loader.assert_called_once()
    scanner.assert_not_called()


def test_zero_finding_saved_case_can_be_analyzed_but_cannot_trigger_cve_refresh(tmp_path):
    target = "http://synthetic.example:6379/"
    write_capture(
        tmp_path,
        "assessment-synthetic-observations",
        1700000000,
        payload={"hosts": [{"ip": ADDRESS}], "findings": []},
        recorded_at="2026-10-01T00:00:00Z",
    )
    loaded = load_saved_target_case(tmp_path, target, SCOPE)
    assert loaded["payload"]["findings"] == []
    assert loaded["historical_capture"] is True
    with pytest.raises(ConfigError, match="No verified saved CVE capture"):
        load_saved_cve_case(tmp_path, target, SCOPE)
