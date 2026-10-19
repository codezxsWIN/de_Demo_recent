"""Missing severity is an unscored finding, not evidence of a low priority."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.test_all import SETTINGS, WEIGHTS, make_enrichment, make_finding, make_profile
from vulnassess import analyst, live_assessment, pipeline, report, scoring
from vulnassess.errors import ConfigError, IntelUnavailable
from vulnassess.schema import Host, Service
from vulnassess.score_facts import missing_severity_basis
from vulnassess.store import Store


@pytest.mark.parametrize("fallback", [None, {}])
@pytest.mark.parametrize("kev", [False, True])
def test_missing_severity_cannot_create_zero_or_threat_only_priority(fallback, kev):
    finding = make_finding(tool="redis-check")
    enrichment = replace(
        make_enrichment(finding_id=finding.id), cvss31_vector=None, cvss31_base=None, kev=kev
    )
    original = enrichment.to_json()
    with pytest.raises(IntelUnavailable, match="severity|CVSS|fallback"):
        scoring.score(
            finding, enrichment, make_profile(), (), {**WEIGHTS, "native_fallback": fallback}
        )
    assert enrichment.to_json() == original


@pytest.mark.parametrize("severity", [None, "unrecognized"])
def test_unknown_native_severity_is_not_assigned_the_lowest_table_entry(severity):
    finding = make_finding(tool="nessus", native_severity=severity, cve_ids=[])
    with pytest.raises(IntelUnavailable, match="severity|fallback"):
        scoring.score(finding, None, make_profile(), (), WEIGHTS)


def test_a_real_zero_vector_remains_a_valid_zero_not_missing_data():
    finding = make_finding()
    enrichment = replace(
        make_enrichment(finding_id=finding.id),
        cvss31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        cvss31_base=0.0,
        kev=False,
    )
    result = scoring.score(finding, enrichment, make_profile(), (), WEIGHTS)
    assert result.risk == 0 and result.band == "Low"
    assert result.base_score == 0.0 and result.env_score == 0.0


def test_saved_refresh_keeps_unsupported_findings_unscored_and_raw_evidence_unchanged(
    tmp_path, monkeypatch
):
    from vulnassess.saved_cve_case import refresh_saved_case

    host = Host("172.28.0.10", services=(Service(6379, "tcp", name="redis"),))
    finding = make_finding(host_ip=host.ip, tool="redis-check", port=6379)
    payload = {
        "hosts": [host.to_json()],
        "context": [replace(make_profile(), host_ip=host.ip).to_json()],
        "findings": [finding.to_json()],
        "scores": [],
        "enrichments": [],
    }
    before = deepcopy(payload)
    monkeypatch.setattr(
        "vulnassess.saved_cve_case.intel_online.sync_cves",
        Mock(side_effect=IntelUnavailable("SYNTHETIC publisher unavailable")),
    )
    events = []
    result = refresh_saved_case(
        payload, host.ip, SETTINGS, tmp_path / "synthetic.db", lambda *event: events.append(event)
    )
    assert payload == before
    assert result["findings"] == payload["findings"]
    assert result["scores"] == []
    assert result["unscored_findings"][0]["finding_id"] == finding.id
    assert "severity" in result["unscored_findings"][0]["reason"].lower()
    assert any(stage == "score" and state == "error" for stage, state, _ in events)
    frame = analyst.build_evidence_frame(result, host.ip)
    assert frame["mode"] == "unscored_findings" and frame["priorities"] == []
    assert frame["unscored_findings"][0]["finding_id"] == finding.id


def test_live_missing_severity_preserves_evidence_without_a_low_score(tmp_path, monkeypatch):
    import shutil
    import subprocess

    config = tmp_path / "config"
    shutil.copytree(SETTINGS.config_dir, config)
    host = Host("127.0.0.1", services=(Service(6379, "tcp", name="redis"),))
    finding = make_finding(host_ip=host.ip, tool="redis-check", port=6379)
    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "synthetic-nmap")
    monkeypatch.setattr(live_assessment, "parse_nmap_xml", lambda *_: ([host], [finding]))

    def scan(argv, **kwargs):
        Path(argv[argv.index("-oX") + 1]).write_text("SYNTHETIC scanner; parser injected")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(live_assessment.subprocess, "run", scan)
    monkeypatch.setattr(
        live_assessment.analyst,
        "analyze_optional",
        lambda *_, **__: {"analyst": None, "ai_status": "unavailable", "ai_attempts": []},
    )
    events, cases = [], []
    result = live_assessment.run(
        host.ip,
        {"status": "ready", "resolved_ips": [host.ip]},
        config,
        provider="ollama",
        on_progress=lambda *event: events.append(event),
        on_case=cases.append,
    )
    assert result["scan_status"] == "complete"
    assert result["finding_count"] == 1
    assert result["assessment_summary"]["priorities"] == []
    assert result["assessment_summary"]["unscored_finding_count"] == 1
    assert result["assessment_summary"]["unscored_findings"][0]["finding_id"] == finding.id
    assert cases[0]["payload"]["findings"] == [finding.to_json()]
    assert cases[0]["payload"]["scores"] == []
    assert result["saved_assessment"]["status"] == "saved"
    assert any(stage == "score" and state == "error" for stage, state, _ in events)
    import json

    directory = (
        Path(result["saved_assessment"]["evidence_directory"])
        if "evidence_directory" in result["saved_assessment"]
        else next((config.parent / "data/live/raw").glob("assessment-*"))
    )
    manifest = json.loads((directory / "manifest.json").read_text())
    from vulnassess import capture_history

    stored = capture_history.load(directory.parent, directory.name)
    assert manifest["captured_at"] == stored["captured_at"]


def test_mixed_supported_and_unscored_findings_keep_all_original_evidence():
    supported = make_finding(tool="nikto", tool_native_id="SYNTHETIC-supported", cve_ids=[])
    unsupported = make_finding(tool="redis-check", tool_native_id="SYNTHETIC-unscored")
    findings = [unsupported, supported]
    before = [item.to_json() for item in findings]
    scores, unscored = scoring.score_available(findings, [], make_profile(), (), WEIGHTS)
    assert [item.finding_id for item in scores] == [supported.id]
    assert unscored[0]["finding_id"] == unsupported.id
    assert [item.to_json() for item in findings] == before
    payload = {
        "hosts": [Host(supported.host_ip).to_json()],
        "context": [make_profile().to_json()],
        "findings": before,
        "scores": [item.to_json() for item in scores],
        "unscored_findings": unscored,
        "enrichments": [],
    }
    summary = live_assessment.assessment_summary("SYNTHETIC", supported.host_ip, [], payload)
    assert summary["scored_finding_count"] == summary["unscored_finding_count"] == 1
    frame = analyst.build_evidence_frame(payload, supported.host_ip)
    assert frame["unscored_findings"][0]["finding_id"] == unsupported.id
    assert frame["priorities"][0]["finding_id"] == supported.id


def test_strict_recorded_ranking_publishes_no_partial_replacement(tmp_path, monkeypatch):
    supported = make_finding(tool="nikto", tool_native_id="SYNTHETIC-supported", cve_ids=[])
    unsupported = make_finding(tool="redis-check", tool_native_id="SYNTHETIC-unscored")
    with Store(tmp_path / "synthetic.db") as store:
        store.start_run("synthetic-missing-severity", "synthetic config")
        store.upsert_host("synthetic-missing-severity", Host(supported.host_ip))
        store.upsert_profile("synthetic-missing-severity", make_profile())
        store.upsert_findings("synthetic-missing-severity", [supported, unsupported])
        prior = scoring.score(supported, None, make_profile(), (), WEIGHTS)
        store.upsert_score("synthetic-missing-severity", prior)
        before = [item.to_json() for item in store.scores("synthetic-missing-severity")]
        monkeypatch.setattr(store, "findings", lambda *_: [supported, unsupported])
        write = Mock(wraps=store.upsert_score)
        monkeypatch.setattr(store, "upsert_score", write)
        with pytest.raises(IntelUnavailable, match=unsupported.id):
            pipeline.do_rank(SETTINGS, store, "synthetic-missing-severity")
        write.assert_not_called()
        assert [item.to_json() for item in store.scores("synthetic-missing-severity")] == before


@pytest.mark.parametrize(
    "records",
    [
        None,
        {},
        [None],
        [{"finding_id": "outside", "reason": "SYNTHETIC"}],
        [{"finding_id": "inside", "reason": ""}],
        [{"finding_id": "inside", "reason": None}],
        [{"finding_id": "inside"}],
        [{"finding_id": "inside", "reason": "SYNTHETIC"}],
    ],
)
def test_unscored_annotations_cannot_rebind_or_contradict_findings(records):
    payload = {
        "findings": [{"id": "inside"}],
        "scores": [{"finding_id": "inside", "risk": 25, "band": "Low"}],
        "enrichments": [],
        "unscored_findings": records,
    }
    with pytest.raises(ConfigError, match="Unscored"):
        live_assessment.assessment_summary("SYNTHETIC", "172.28.0.10", [], payload)


def test_duplicate_unscored_annotations_fail_closed():
    record = {"finding_id": "inside", "reason": "SYNTHETIC no severity"}
    payload = {
        "findings": [{"id": "inside"}],
        "scores": [],
        "enrichments": [],
        "unscored_findings": [record, record],
    }
    with pytest.raises(ConfigError, match="duplicated"):
        live_assessment.assessment_summary("SYNTHETIC", "172.28.0.10", [], payload)


def test_legacy_missing_basis_is_visible_but_stored_value_is_not_rewritten():
    finding = make_finding()
    valid = scoring.score(
        finding, make_enrichment(finding_id=finding.id), make_profile(), (), WEIGHTS
    )
    legacy = replace(
        valid,
        base_score=None,
        env_score=None,
        base_vector=None,
        env_vector=None,
        native_fallback=None,
        risk=0.0,
        band="Low",
    )
    before = legacy.to_json()
    assert missing_severity_basis(legacy)
    assert not missing_severity_basis(valid)
    assert not missing_severity_basis({"risk": 0, "band": "Low"})
    document = report.render(
        {"run_id": "synthetic"}, [legacy], [finding], [make_profile()], {}, WEIGHTS, "SYNTHETIC"
    )
    assert "historical stored priority has no severity basis" in document
    assert "not established Low risk" in document
    assert legacy.to_json() == before


def test_printable_report_keeps_unscored_findings_visible_and_escaped():
    finding = make_finding(title="SYNTHETIC <script>not executed</script>")
    document = report.render(
        {"run_id": "synthetic"}, [], [finding], [make_profile()], {}, WEIGHTS, "SYNTHETIC"
    )
    assert "Unscored findings" in document
    assert "not Low risk by default" in document
    assert "&lt;script&gt;not executed&lt;/script&gt;" in document
    assert "<script>not executed</script>" not in document


def test_saved_review_and_stored_workbench_warn_without_rewriting_history():
    from vulnassess.ui import capture_review, presentation

    finding = make_finding(tool_native_id="SYNTHETIC-legacy")
    unsupported = make_finding(tool="redis-check", tool_native_id="SYNTHETIC-unscored")
    valid = scoring.score(
        finding, make_enrichment(finding_id=finding.id), make_profile(), (), WEIGHTS
    )
    legacy = replace(
        valid,
        base_score=None,
        env_score=None,
        base_vector=None,
        env_vector=None,
        native_fallback=None,
        risk=0.0,
        band="Low",
    )
    payload = {"findings": [finding.to_json(), unsupported.to_json()], "scores": [legacy.to_json()]}
    before = deepcopy(payload)
    notice = presentation._severity_notice(payload)
    assert "1 unscored findings; 1 historical priorities" in notice
    assert "not established Low risk" in notice
    record = {
        "captured_at": None,
        "intelligence_recorded_at": "SYNTHETIC time",
        "analysis_attempted_at": None,
        "capture_id": "assessment-synthetic-render",
        "configuration_hash": "synthetic",
        "evidence_hash": "synthetic",
        "intelligence_hash": "synthetic",
        "snapshot_hash": "synthetic",
        "result": {
            "target": "SYNTHETIC target",
            "ai_status": "not_attempted",
            "assessment_summary": {},
        },
        "payload": payload,
    }
    markup = capture_review.review(record)
    assert "<dd>Capture time not recorded</dd>" in markup
    assert "Unscored findings" in markup
    assert "historical stored number has no severity basis" in markup
    assert "Low · 0.0 / 100" in markup
    assert payload == before
    assert (
        presentation._severity_notice(
            {"findings": [finding.to_json()], "scores": [valid.to_json()]}
        )
        == ""
    )
