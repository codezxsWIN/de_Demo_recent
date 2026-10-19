"""Synthetic lifecycle checks with scanner/provider I/O replaced at the boundary."""

import copy
import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.test_all import make_finding
from vulnassess import analyst, capture_history, live_assessment
from vulnassess.errors import ConfigError, ProviderUnavailable
from vulnassess.schema import Host, Service
from vulnassess.store import Store

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    config = tmp_path / "config"
    shutil.copytree(ROOT / "config", config)
    host = Host(ip="127.0.0.1", services=(Service(port=80, protocol="tcp", name="http"),))
    findings = [make_finding(host_ip=host.ip)]
    events, cases = [], []

    def scanner(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text("SYNTHETIC scanner boundary")
        return subprocess.CompletedProcess(command, 0, "", "")

    client = Mock(model="synthetic", source="synthetic", key="")
    client.available.return_value = True
    client.generate_structured.side_effect = ProviderUnavailable("SYNTHETIC provider offline")
    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "synthetic-nmap")
    monkeypatch.setattr(live_assessment.subprocess, "run", scanner)
    monkeypatch.setattr(live_assessment, "parse_nmap_xml", lambda *_: ([host], findings.copy()))
    monkeypatch.setattr(analyst, "provider_client", lambda *_: client)
    monkeypatch.setattr(analyst, "AUDIT_PATH", tmp_path / "synthetic-audit.jsonl")
    monkeypatch.setattr(
        live_assessment.intel_online,
        "sync_cves",
        Mock(side_effect=AssertionError("No publisher fetch is permitted in this test")),
    )

    def run(database=None):
        return live_assessment.run(
            host.ip,
            {"status": "ready", "resolved_ips": [host.ip]},
            config,
            provider="ollama",
            database=database,
            on_progress=lambda *event: events.append(event),
            on_case=cases.append,
        )

    return run, findings, events, cases, client


@pytest.mark.parametrize("budget,limit", [("MAX_PROMPT_CHARS", 100), ("MAX_EVIDENCE", 1)])
def test_ai_prompt_budget_cannot_prevent_completed_scan_from_being_saved(
    scenario, monkeypatch, budget, limit
):
    run, findings, events, cases, client = scenario
    monkeypatch.setattr(analyst, budget, limit)
    result = run()
    assert result["scan_status"] == "complete"
    assert result["ai_status"] == "needs_review"
    assert result["analyst"] is None
    assert len(result["decision_frame"]["priorities"]) == len(findings)
    assert len(result["assessment_summary"]["priorities"]) == len(findings)
    assert cases[0]["payload"]["findings"][0]["id"] == findings[0].id
    assert any(stage == "report" and state == "complete" for stage, state, _ in events)
    client.generate_structured.assert_not_called()
    directory = Path(result["evidence_directory"])
    saved = capture_history.load(directory.parent, directory.name)
    assert saved["result"]["ai_status"] == "needs_review"
    assert saved["payload"]["findings"] == cases[0]["payload"]["findings"]


def test_live_priority_frame_keeps_every_finding_when_model_case_is_truncated(scenario):
    run, findings, _, cases, _ = scenario
    findings[:] = [
        make_finding(host_ip="127.0.0.1", tool_native_id=f"synthetic-{index}")
        for index in range(30)
    ]
    result = run()
    frame = result["decision_frame"]
    assert len(frame["priorities"]) == len(findings)
    assert frame["case_coverage"]["findings_omitted"] == 0
    assert result["scan_status"] == "complete"
    payload = cases[0]["payload"]
    original = copy.deepcopy(payload)
    model_case, evidence, aliases = analyst.build_case(payload, "127.0.0.1")
    assert model_case["coverage"]["findings_omitted"] > 0
    assert len(analyst.build_prompt(model_case, evidence, len(aliases))) <= analyst.MAX_PROMPT_CHARS
    assert payload == original
    assert sorted(item["risk"] for item in frame["priorities"]) == sorted(
        item["risk"] for item in payload["scores"]
    )
    assert [item["finding_id"] for item in frame["priorities"]] == [
        item["finding_id"] for item in payload["scores"]
    ]
    assert [item["rank"] for item in frame["priorities"]] == list(range(1, 31))
    evidence_ids = {item["id"] for item in frame["evidence"]}
    assert len(evidence_ids) == len(frame["evidence"])
    assert all(
        item["score_evidence_id"] in evidence_ids and item["finding_evidence_id"] in evidence_ids
        for item in frame["priorities"]
    )


def test_evidence_only_assessment_displays_all_observed_services(scenario, monkeypatch):
    run, findings, _, cases, _ = scenario
    findings.clear()
    services = tuple(Service(port=port, protocol="tcp", name="http") for port in range(80, 105))
    host = Host(ip="127.0.0.1", services=services)
    monkeypatch.setattr(live_assessment, "parse_nmap_xml", lambda *_: ([host], []))
    result = run()
    frame = result["decision_frame"]
    assert frame["mode"] == "verification_only"
    assert frame["priorities"] == []
    assert len(frame["verification_candidates"]) == len(services)
    assert frame["case_coverage"]["services_omitted"] == 0
    model_case, _, _ = analyst.build_case(cases[0]["payload"], host.ip)
    assert len(model_case["services"]) == analyst.MAX_SERVICES
    assert model_case["coverage"]["services_omitted"] == len(services) - analyst.MAX_SERVICES


def test_corrupt_intelligence_json_preserves_findings_scores_and_saved_evidence(scenario, tmp_path):
    run, findings, events, cases, _ = scenario
    cache = tmp_path / "intel-cache.db"
    with Store(cache) as store:
        for feed in ("nvd", "epss", "kev"):
            store.put_feed_meta(feed, f"local-cache/{feed}", "synthetic", "2026-10-11", 1)
        store.connection.execute(
            "INSERT INTO cve (id, json) VALUES (?, ?)", (findings[0].cve_ids[0], "{")
        )
        store.connection.commit()
    result = run(tmp_path / "assessment.db")
    assert result["scan_status"] == "complete"
    assert len(result["assessment_summary"]["priorities"]) == 1
    assert result["assessment_summary"]["intelligence"]["mode"] == "unavailable"
    assert cases[0]["payload"]["enrichments"] == []
    assert cases[0]["payload"]["feed_status"] == []
    assert all(
        any(stage == feed and state == "error" for stage, state, _ in events)
        for feed in ("nvd", "epss", "kev", "intel")
    )
    directory = Path(result["evidence_directory"])
    payload = json.loads((directory / "case.json").read_text())
    assert payload["findings"][0]["id"] == findings[0].id
    assert result["saved_assessment"]["status"] == "saved"


@pytest.mark.parametrize("error_type", [OSError, ConfigError])
def test_final_review_save_failure_keeps_reopenable_evidence_checkpoint(
    scenario, monkeypatch, error_type
):
    run, findings, _, _, _ = scenario
    save = capture_history.save

    def fail_final(directory, result, *, final=False, **kwargs):
        if final:
            raise error_type("synthetic final save failure")
        return save(directory, result, final=final, **kwargs)

    monkeypatch.setattr(capture_history, "save", fail_final)
    result = run()
    assert result["scan_status"] == "complete"
    assert "evidence checkpoint is retained" in result["assessment_summary"]["persistence_warning"]
    directory = Path(result["evidence_directory"])
    checkpoint = capture_history.load(directory.parent, directory.name)
    assert checkpoint["payload"]["findings"][0]["id"] == findings[0].id


@pytest.mark.parametrize("failure", ["timeout", "exit", "missing", "wrong-host", "duplicate"])
def test_failed_primary_discovery_cannot_be_reported_as_completed(scenario, monkeypatch, failure):
    run, _, events, cases, client = scenario
    if failure == "timeout":
        monkeypatch.setattr(
            live_assessment.subprocess,
            "run",
            Mock(side_effect=subprocess.TimeoutExpired("synthetic-nmap", 180)),
        )
    elif failure in {"exit", "missing"}:
        monkeypatch.setattr(
            live_assessment.subprocess,
            "run",
            Mock(
                return_value=subprocess.CompletedProcess([], 1 if failure == "exit" else 0, "", "")
            ),
        )
    else:
        host = Host(ip="192.0.2.1" if failure == "wrong-host" else "127.0.0.1")
        monkeypatch.setattr(
            live_assessment,
            "parse_nmap_xml",
            lambda *_: ([host] if failure == "wrong-host" else [host, host], []),
        )
    with pytest.raises(ConfigError, match="Light Nmap|exactly the pinned target"):
        run()
    assert not cases
    client.generate_structured.assert_not_called()
    assert not any(stage == "report" and state == "complete" for stage, state, _ in events)
