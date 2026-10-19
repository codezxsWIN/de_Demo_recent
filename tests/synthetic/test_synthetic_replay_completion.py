"""Retained synthetic captures cannot manufacture completed scans during replay."""

from copy import deepcopy
from pathlib import Path
from threading import Lock
from unittest.mock import Mock

import pytest

from vulnassess.errors import ConfigError
from vulnassess.schema import ContextProfile, Feature, Host, Service
from vulnassess.ui import server

IP = "127.0.0.1"
TARGET = "http://127.0.0.1:8080/"
ROOT = Path(__file__).resolve().parents[2]


def retained_case():
    host = Host(ip=IP, services=(Service(port=8080, protocol="tcp", name="http"),))
    profile = ContextProfile(
        host_ip=IP,
        role=Feature("web_frontend", 0.9, "rule", "SYNTHETIC http service"),
        exposure=Feature("internal", 0.9, "rule", "SYNTHETIC loopback"),
    )
    payload = {
        "hosts": [host.to_json()],
        "context": [profile.to_json()],
        "findings": [],
        "scores": [],
        "enrichments": [],
        "scan_status": "complete",
        "scanner_coverage": {
            "nmap": "top 100 TCP ports; explicit TCP/8080 check complete",
            "nikto": "complete: bounded checks on http endpoint, 0 findings",
        },
    }
    return {
        "target": TARGET,
        "resolved_ip": IP,
        "captured_at": "2026-10-01T00:00:00Z",
        "services": host.to_json()["services"],
        "finding_count": 0,
        "scan_status": "complete",
        "payload": payload,
        "stage_events": [
            ("context", "complete", "SYNTHETIC historical context"),
            ("report", "complete", "SYNTHETIC historical report"),
        ],
    }


@pytest.fixture
def replay(tmp_path, monkeypatch):
    app = object.__new__(server.UiApplication)
    app.config_dir = ROOT / "config"
    app.database = tmp_path / "synthetic-replay.db"
    app._live_lock = Lock()
    app._recent_live_cases = {}
    app._last_live_scan = {}
    monkeypatch.setattr(
        app,
        "target_check",
        Mock(return_value={"status": "ready", "resolved_ips": [IP], "missing": []}),
    )
    scanner = Mock(side_effect=AssertionError("Replay must never start a new scanner"))
    monkeypatch.setattr(server.live_assessment, "run", scanner)
    monkeypatch.setattr(server.live_assessment.subprocess, "run", scanner)
    monkeypatch.setattr(
        server,
        "resolve_addresses",
        Mock(side_effect=AssertionError("Replay must not resolve a new address")),
    )
    refresh = Mock(side_effect=lambda payload, *_args: deepcopy(payload))
    monkeypatch.setattr(server, "refresh_saved_case", refresh)
    analyze = Mock(return_value={"analyst": None, "ai_status": "unavailable", "ai_attempts": []})
    monkeypatch.setattr(server.analyst, "analyze_optional", analyze)
    events, captures = [], []

    def run(case, mode):
        if mode == "saved":
            monkeypatch.setattr(server, "load_saved_cve_case", Mock(return_value=case))
        else:
            app._recent_live_cases[IP] = (server.time.monotonic(), case)
        return app.live_report(
            case["target"],
            "ollama",
            lambda *event: events.append(event),
            captures.append,
            replay_saved=mode == "saved",
            reuse_recent=mode == "recent",
        )

    return run, events, captures, scanner, refresh, analyze


@pytest.mark.parametrize("mode", ["saved", "recent"])
@pytest.mark.parametrize("damage", ["missing-context", "wrong-context", "invalid-context"])
def test_context_prerequisites_fail_before_any_retained_completion(replay, mode, damage):
    run, events, captures, scanner, refresh, analyze = replay
    case = retained_case()
    if damage == "missing-context":
        case["payload"]["context"] = []
    elif damage == "wrong-context":
        case["payload"]["context"][0]["host_ip"] = "192.0.2.1"
    else:
        del case["payload"]["context"][0]["role"]

    with pytest.raises(ConfigError, match="context"):
        run(case, mode)

    assert any(stage == "context" and state == "error" for stage, state, _ in events)
    assert not any(state == "complete" for _, state, _ in events)
    assert not captures
    scanner.assert_not_called()
    refresh.assert_not_called()
    analyze.assert_not_called()


@pytest.mark.parametrize("mode", ["saved", "recent"])
def test_missing_retained_host_cannot_claim_scanner_or_canonical_completion(replay, mode):
    run, events, captures, scanner, _, analyze = replay
    case = retained_case()
    case["payload"]["hosts"] = []

    with pytest.raises(ConfigError, match="host|target"):
        run(case, mode)

    assert not any(state == "complete" for _, state, _ in events)
    assert not captures
    scanner.assert_not_called()
    analyze.assert_not_called()


@pytest.mark.parametrize("mode", ["saved", "recent"])
@pytest.mark.parametrize(
    "damage", ["scalar-finding", "incomplete-finding", "wrong-host", "duplicate"]
)
def test_canonical_completion_requires_valid_target_bound_findings(replay, mode, damage):
    from tests.test_all import make_finding

    run, events, captures, scanner, refresh, analyze = replay
    case = retained_case()
    finding = make_finding(host_ip=IP).to_json()
    if damage == "scalar-finding":
        case["payload"]["findings"] = [17]
    elif damage == "incomplete-finding":
        case["payload"]["findings"] = [{"id": "SYNTHETIC", "host_ip": IP}]
    elif damage == "wrong-host":
        case["payload"]["findings"] = [{**finding, "host_ip": "192.0.2.1"}]
    else:
        case["payload"]["findings"] = [finding, finding]
    with pytest.raises(ConfigError, match="canonical|finding"):
        run(case, mode)
    assert not any(state == "complete" for _, state, _ in events)
    assert not captures
    refresh.assert_not_called()
    analyze.assert_not_called()
    scanner.assert_not_called()


@pytest.mark.parametrize("mode", ["saved", "recent"])
@pytest.mark.parametrize(
    "coverage,expected_state",
    [
        ("top 100 TCP ports; explicit TCP/8080 check failed", "error"),
        ("top 100 TCP ports; explicit TCP/8080 check redis inspection failed", "error"),
        ("top 100 TCP ports, light service detection", "error"),
        ("top 100 TCP ports; explicit TCP/8080 check closed", "complete"),
    ],
)
def test_endpoint_replay_uses_retained_coverage(replay, mode, coverage, expected_state):
    run, events, _, scanner, _, _ = replay
    case = retained_case()
    case["payload"]["scanner_coverage"] = {"nmap": coverage, "nikto": "skipped: not launched"}
    result = run(case, mode)

    endpoint_events = [
        (state, detail) for stage, state, detail in events if stage == "endpoint_scan"
    ]
    assert endpoint_events
    assert all(state == expected_state for state, _ in endpoint_events)
    assert all(
        "retained" in detail.lower() or "reused" in detail.lower() for _, detail in endpoint_events
    )
    if expected_state == "error":
        assert result["scan_status"] == "partial"
        assert result["assessment_summary"]["scan_status"] == "partial"
        assert any(
            stage == "report" and state == "complete" and "Partial scan" in detail
            for stage, state, detail in events
        )
    scanner.assert_not_called()


@pytest.mark.parametrize("mode", ["saved", "recent"])
@pytest.mark.parametrize(
    "coverage,expected_state",
    [
        ("complete: bounded checks on http endpoint, 0 findings", "complete"),
        ("failed: SYNTHETIC timeout", "error"),
        ("not HTTP: service protocol was not HTTP", "skipped"),
        (None, "skipped"),
    ],
)
def test_nikto_replay_does_not_invent_redis_or_new_scans(replay, mode, coverage, expected_state):
    run, events, _, scanner, _, _ = replay
    case = retained_case()
    if coverage is None:
        del case["payload"]["scanner_coverage"]["nikto"]
    else:
        case["payload"]["scanner_coverage"]["nikto"] = coverage
    result = run(case, mode)

    nikto_events = [(state, detail) for stage, state, detail in events if stage == "nikto"]
    assert nikto_events and all(state == expected_state for state, _ in nikto_events)
    assert all("Redis" not in detail for _, detail in nikto_events)
    if expected_state == "error":
        assert result["scan_status"] == "partial"
    scanner.assert_not_called()


@pytest.mark.parametrize("mode", ["saved", "recent"])
@pytest.mark.parametrize("location", ["case", "payload", "summary"])
def test_partial_source_survives_replay_capture_summary_and_report(replay, mode, location):
    run, events, captures, scanner, _, _ = replay
    case = retained_case()
    if location == "case":
        case["scan_status"] = "partial"
    elif location == "payload":
        case["payload"]["scan_status"] = "partial"
    else:
        case["assessment_summary"] = {"scan_status": "partial"}
    original = deepcopy(case)

    result = run(case, mode)

    assert result["scan_status"] == "partial"
    assert result["assessment_summary"]["scan_status"] == "partial"
    assert captures[-1]["scan_status"] == "partial"
    assert captures[-1]["assessment_summary"]["scan_status"] == "partial"
    assert any(
        stage == "report" and state == "complete" and "Partial scan" in detail
        for stage, state, detail in events
    )
    assert all(
        state in {"pending", "running", "complete", "skipped", "error"} for _, state, _ in events
    )
    assert all("Scan complete" not in detail for _, _, detail in events)
    assert case == original
    scanner.assert_not_called()


@pytest.mark.parametrize("mode", ["saved", "recent"])
@pytest.mark.parametrize("location", ["case", "payload", "summary"])
@pytest.mark.parametrize("invalid_status", ["failed", True, [], "", "COMPLETE", 1])
def test_invalid_retained_scan_status_cannot_be_inferred_complete(
    replay, mode, location, invalid_status
):
    run, events, captures, scanner, refresh, analyze = replay
    case = retained_case()
    if location == "case":
        case["scan_status"] = invalid_status
    elif location == "payload":
        case["payload"]["scan_status"] = invalid_status
    else:
        case["assessment_summary"] = {"scan_status": invalid_status}

    with pytest.raises(ConfigError, match="scan_status"):
        run(case, mode)

    assert not any(state == "complete" for _, state, _ in events)
    assert not captures
    refresh.assert_not_called()
    analyze.assert_not_called()
    scanner.assert_not_called()


@pytest.mark.parametrize("mode", ["saved", "recent"])
@pytest.mark.parametrize("baseline_retained", [False, True])
def test_legacy_missing_status_needs_retained_baseline_evidence(replay, mode, baseline_retained):
    run, events, _, scanner, _, _ = replay
    case = retained_case()
    del case["scan_status"]
    del case["payload"]["scan_status"]
    case["target"] = IP
    case["payload"]["scanner_coverage"]["nmap"] = "top 100 TCP ports, light service detection"
    case["payload"]["scanner_coverage"]["nikto"] = "not run; no explicit URL"
    if not baseline_retained:
        case["payload"]["scanner_coverage"] = {}

    result = run(case, mode)

    expected = "complete" if baseline_retained else "partial"
    assert result["scan_status"] == expected
    assert result["assessment_summary"]["scan_status"] == expected
    if not baseline_retained:
        assert not any(stage == "scanner" and state == "complete" for stage, state, _ in events)
    scanner.assert_not_called()
