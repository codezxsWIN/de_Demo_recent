"""The live path uses one authorised IP and a bounded scanner command."""

import hashlib
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnassess import intel, intel_online, live_assessment
from vulnassess.errors import AdapterError, ConfigError, LLMUnavailable, NeedsReview
from vulnassess.store import Store
from vulnassess.ui.server import UiApplication

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "coverage",
    [
        None,
        {},
        False,
        "pretend",
        {"findings_included": -1},
        {"findings_included": True},
        {"findings_included": 1},
    ],
)
def test_batch_summary_rejects_missing_or_fabricated_coverage(coverage: object) -> None:
    payload = {"findings": [], "scores": [], "enrichments": [], "context": []}
    result = {"batches": [{"SYNTHETIC": "invalid coverage"}], "batch_coverage": coverage}
    with pytest.raises(NeedsReview, match="batch coverage"):
        live_assessment.assessment_summary("synthetic.invalid", "172.28.0.10", [], payload, result)


def test_endpoint_validation_rejects_null_host_without_attribute_error() -> None:
    with pytest.raises(ConfigError, match="endpoint metadata"):
        live_assessment._validated_endpoint(
            {"endpoint": {"host": None, "scheme": "https", "port": 443, "path": "/"}}
        )


@pytest.fixture(autouse=True)
def isolate_retained_scanner_files(tmp_path, monkeypatch):
    make_directory = live_assessment.mkdtemp
    monkeypatch.setattr(
        live_assessment,
        "mkdtemp",
        lambda *, prefix, dir: make_directory(prefix=prefix, dir=tmp_path),
    )


def test_live_scan_uses_pinned_ip_and_sends_fresh_services_to_analyst():
    check = {"status": "needs-pinning", "resolved_ips": ["45.33.32.156"]}
    events = []
    captures = []

    def fake_nmap(command, **kwargs):
        assert command[-1] == "45.33.32.156"
        assert command[1:4] == ["-n", "-Pn", "-sT"]
        assert command[command.index("--top-ports") + 1] == "100"
        assert "--script" not in command
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun start="1"><host><status state="up"/>'
            '<address addr="45.33.32.156" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="ssh" product="OpenSSH" version="6.6"/></port></ports>'
            "</host></nmaprun>",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_analyst(payload, host_ip, **kwargs):
        assert host_ip == "45.33.32.156"
        assert payload["hosts"][0]["services"][0]["port"] == 22
        assert payload["findings"] == []
        assert payload["scores"] == []
        assert payload["scanner_coverage"] == {
            "nmap": "top 100 TCP ports, light service detection",
            "nikto": "not run; separate authorized web scan required",
            "nessus": "no .nessus report imported; no Nessus scan claimed",
        }
        assert kwargs["provider"] == "openrouter"
        return {"host_ip": host_ip, "analysis": {"summary": "SSH observed."}}

    with (
        patch.object(live_assessment, "nmap_binary", return_value="nmap.exe"),
        patch.object(live_assessment.subprocess, "run", side_effect=fake_nmap),
        patch.object(live_assessment.analyst, "analyze_target", side_effect=fake_analyst),
    ):
        result = live_assessment.run(
            "scanme.nmap.org",
            check,
            ROOT / "config",
            provider="openrouter",
            on_progress=lambda *event: events.append(event),
            on_capture=captures.append,
        )
    assert result["resolved_ip"] == "45.33.32.156"
    assert result["services"][0]["port"] == 22
    assert captures[0]["finding_count"] == 0
    assert captures[-1]["decision_frame"]["mode"] == "verification_only"
    assert captures[-1]["assessment_summary"]["finding_count"] == 0
    assert captures[-1]["assessment_summary"]["validated_ai_summary"] is None
    assert captures[-1]["decision_frame"]["context"]["exposure"]["value"] == "internet_facing"
    assert captures[-1]["decision_frame"]["priorities"] == []
    assert result["decision_frame"] == captures[-1]["decision_frame"]
    assert ("scanner", "complete") in [(stage, state) for stage, state, _ in events]
    assert ("canonical", "complete") in [(stage, state) for stage, state, _ in events]
    assert ("intel", "skipped") in [(stage, state) for stage, state, _ in events]
    assert ("score", "skipped") in [(stage, state) for stage, state, _ in events]
    assert ("report", "complete") in [(stage, state) for stage, state, _ in events]
    assert result["assessment_summary"]["finding_count"] == 0
    assert "No vulnerability findings" in result["assessment_summary"]["conclusion"]
    assert result["assessment_summary"]["context"]["exposure"] == "internet_facing"
    saved = Path(result["evidence_directory"])
    assert (saved / "nmap.xml").is_file()
    assert json.loads((saved / "case.json").read_text())["hosts"][0]["services"][0]["port"] == 22
    manifest = json.loads((saved / "manifest.json").read_text())
    assert manifest["resolved_ip"] == "45.33.32.156"
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((saved / name).read_bytes()).hexdigest() == digest


def test_live_web_run_scans_requested_port_and_runs_bounded_nikto():
    check = {
        "status": "ready",
        "resolved_ips": ["127.0.0.1"],
        "endpoint": {
            "scheme": "https",
            "host": "agent.example.test",
            "port": 7001,
            "path": "/console/login/LoginForm.jsp",
        },
    }
    events = []
    analyst_payloads = []
    calls = []

    def fake_process(command, **kwargs):
        calls.append(command)
        if "-oX" in command:
            requested = "-p" in command
            port = 7001 if requested else 80
            name = "https" if requested else "http"
            Path(command[command.index("-oX") + 1]).write_text(
                f'<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
                f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>'
                f'<service name="{name}"/></port></ports></host></nmaprun>',
                encoding="utf-8",
            )
        else:
            assert kwargs["stderr"] == subprocess.STDOUT
            assert kwargs["stdout"].writable()
            assert "capture_output" not in kwargs
            output = Path(command[command.index("-output") + 1])
            output.write_text(
                json.dumps(
                    {
                        "ip": "127.0.0.1",
                        "host": "127.0.0.1",
                        "port": "7001",
                        "vulnerabilities": [
                            {
                                "id": "999001",
                                "url": "https://agent.example.test:7001/console/login/LoginForm.jsp",
                                "msg": "Synthetic missing security header",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_analyst(payload, host_ip, **kwargs):
        analyst_payloads.append(payload)
        return {"analysis": {"summary": "Nikto evidence was included."}}

    with (
        patch.object(live_assessment, "nmap_binary", return_value="nmap.exe"),
        patch.object(live_assessment.subprocess, "run", side_effect=fake_process),
        patch.object(live_assessment.analyst, "analyze_target", side_effect=fake_analyst),
        patch.object(live_assessment.orchestrator, "scanner_argv", return_value=("nikto.pl",)),
        patch.object(
            live_assessment.orchestrator,
            "scanner_status",
            return_value={"status": "available", "detail": "test Nikto"},
        ),
    ):
        result = live_assessment.run(
            "https://agent.example.test:7001/console/login/LoginForm.jsp",
            check,
            ROOT / "config",
            provider="ollama",
            on_progress=lambda *event: events.append(event),
        )

    requested_port_command = next(command for command in calls if "-p" in command)
    assert requested_port_command[requested_port_command.index("-p") + 1] == "7001"
    nikto_command = next(command for command in calls if "-output" in command)
    assert nikto_command[nikto_command.index("-Tuning") + 1] == "123b"
    assert nikto_command[nikto_command.index("-timeout") + 1] == "5"
    assert nikto_command[nikto_command.index("-maxtime") + 1] == "90s"
    assert "-nolookup" in nikto_command
    assert "Host: agent.example.test:7001" in nikto_command
    assert [service["port"] for service in result["services"]] == [80, 7001]
    assert result["finding_count"] == 1
    assert analyst_payloads[0]["findings"][0]["tool"] == "nikto"
    assert result["assessment_summary"]["scanner_coverage"]["nikto"].startswith("complete:")
    assert any(stage == "nikto" and state == "complete" for stage, state, _ in events)


def test_finalized_nikto_report_retains_evidence_but_excludes_ip_pinning_artifact(tmp_path):
    report = tmp_path / "nikto.json"
    report.write_text(json.dumps([{
        "ip": "192.0.2.10", "host": "192.0.2.10", "port": 4280,
        "end_time": "2026-10-21 12:00:00 +0000",
        "ssl_info": {"altnames": "lab.example.test"},
        "vulnerabilities": [
            {"id": "013587", "url": "/", "msg": "Suggested security header missing: referrer-policy."},
            {"id": "999993", "url": "/", "msg": "Hostname '192.0.2.10' does not match certificate names (SAN: lab.example.test)."},
        ],
    }]), encoding="utf-8")
    endpoint = {"scheme": "https", "host": "lab.example.test", "port": 4280}
    findings, excluded = live_assessment._parse_pinned_nikto(
        report, "192.0.2.10", endpoint, require_finalized=True
    )
    assert len(findings) == 1
    assert findings[0].tool_native_id == "013587"
    assert excluded == 1

    endpoint["port"] = 4281
    with pytest.raises(AdapterError, match="target, port"):
        live_assessment._parse_pinned_nikto(report, "192.0.2.10", endpoint, require_finalized=True)
    endpoint["port"] = 4280
    payload = json.loads(report.read_text(encoding="utf-8"))
    del payload[0]["end_time"]
    report.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(AdapterError, match="completion marker"):
        live_assessment._parse_pinned_nikto(report, "192.0.2.10", endpoint, require_finalized=True)


def test_public_scope_exception_without_test_asset_tag_never_launches_nikto():
    events = []
    check = {
        "status": "needs-pinning",
        "resolved_ips": ["45.33.32.156"],
        "endpoint": {
            "scheme": "http",
            "host": "scanme.nmap.org",
            "port": 80,
            "path": "/",
        },
    }

    def fake_nmap(command, **kwargs):
        port = 80 if "-p" in command else 22
        Path(command[command.index("-oX") + 1]).write_text(
            f'<nmaprun><host><status state="up"/><address addr="45.33.32.156" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>'
            f'<service name="http"/></port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch.object(live_assessment, "nmap_binary", return_value="nmap.exe"),
        patch.object(live_assessment.subprocess, "run", side_effect=fake_nmap),
        patch.object(
            live_assessment.analyst,
            "analyze_target",
            return_value={"analysis": {"summary": "Observed."}},
        ),
        patch.object(live_assessment.orchestrator, "scanner_status") as nikto_status,
    ):
        result = live_assessment.run(
            "http://scanme.nmap.org/",
            check,
            ROOT / "config",
            provider="ollama",
            on_progress=lambda *event: events.append(event),
        )

    nikto_status.assert_not_called()
    assert result["scan_status"] == "complete"
    assert ("nikto", "skipped") in [(stage, state) for stage, state, _ in events]
    assert "Nikto is limited" in next(
        detail for stage, state, detail in events if stage == "nikto" and state == "skipped"
    )


def test_live_scan_refuses_out_of_scope_ip_before_launch():
    with patch.object(
        live_assessment.subprocess, "run", side_effect=AssertionError("scanner launched")
    ):
        with pytest.raises(ConfigError, match="outside the authorised scope"):
            live_assessment.run(
                "8.8.8.8",
                {"status": "ready", "resolved_ips": ["8.8.8.8"]},
                ROOT / "config",
                provider="openrouter",
                on_progress=lambda *_: None,
            )


def test_failed_model_completes_evidence_only_report():
    captures = []
    events = []

    def fake_nmap(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http"/></port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch.object(live_assessment, "nmap_binary", return_value="nmap.exe"),
        patch.object(live_assessment.subprocess, "run", side_effect=fake_nmap),
        patch.object(
            live_assessment.analyst, "analyze_target", side_effect=LLMUnavailable("timed out")
        ),
    ):
        result = live_assessment.run(
            "127.0.0.1",
            {"status": "ready", "resolved_ips": ["127.0.0.1"]},
            ROOT / "config",
            provider="ollama",
            on_progress=lambda *event: events.append(event),
            on_capture=captures.append,
        )
    assert captures[-1]["assessment_summary"]["validated_ai_summary"] is None
    assert captures[-1]["assessment_summary"]["finding_count"] == 0
    assert result["scan_status"] == "complete"
    assert result["analyst"] is None
    assert result["ai_status"] == "unavailable"
    assert any(stage == "report" and state == "complete" for stage, state, _ in events)


def test_live_findings_use_loaded_intelligence_and_deterministic_scores(tmp_path):
    database = tmp_path / "assessment.sqlite"
    feeds = tmp_path / "operational-feeds"
    shutil.copytree(ROOT / "tests" / "fixtures" / "intel", feeds)
    with Store(tmp_path / "intel-cache.db") as store:
        intel.load_feeds(feeds, store)
    events = []
    payloads = []

    def fake_nmap(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun start="1"><host><status state="up"/>'
            '<address addr="172.28.0.10" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http" product="Apache" version="2.4"/>'
            '<script id="test" output="CVE-2021-44228 observed"/>'
            "</port></ports></host></nmaprun>",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_analyst(payload, host_ip, **kwargs):
        payloads.append(payload)
        return {"analysis": {"summary": "One scanner finding requires verification."}}

    with (
        patch.object(live_assessment, "nmap_binary", return_value="nmap.exe"),
        patch.object(live_assessment.subprocess, "run", side_effect=fake_nmap),
        patch.object(live_assessment.analyst, "analyze_target", side_effect=fake_analyst),
    ):
        live_assessment.run(
            "172.28.0.10",
            {"status": "ready", "resolved_ips": ["172.28.0.10"]},
            ROOT / "config",
            database=database,
            provider="ollama",
            on_progress=lambda *event: events.append(event),
        )
    assert payloads[0]["enrichments"]
    assert payloads[0]["scores"]
    assert payloads[0]["scores"][0]["finding_id"] == payloads[0]["findings"][0]["id"]
    assert ("nvd", "complete") in [(stage, state) for stage, state, _ in events]
    assert ("score", "complete") in [(stage, state) for stage, state, _ in events]


def test_live_scan_does_not_use_synthetic_feed_rows_as_real_intelligence(tmp_path):
    database = tmp_path / "assessment.sqlite"
    with Store(tmp_path / "intel-cache.db") as store:
        intel.load_feeds(ROOT / "tests" / "synthetic" / "feeds", store)
    events = []
    payloads = []

    def fake_nmap(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun><host><status state="up"/>'
            '<address addr="172.28.0.10" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http" product="Synthetic" version="1"/>'
            '<script id="test" output="CVE-1999-9001 observed"/>'
            "</port></ports></host></nmaprun>",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_analyst(payload, host_ip, **kwargs):
        payloads.append(payload)
        return {"analysis": {"summary": "Fixture feed not used."}}

    with (
        patch.object(live_assessment, "nmap_binary", return_value="nmap.exe"),
        patch.object(live_assessment.subprocess, "run", side_effect=fake_nmap),
        patch.object(live_assessment.analyst, "analyze_target", side_effect=fake_analyst),
    ):
        live_assessment.run(
            "172.28.0.10",
            {"status": "ready", "resolved_ips": ["172.28.0.10"]},
            ROOT / "config",
            database=database,
            provider="ollama",
            on_progress=lambda *event: events.append(event),
        )
    assert payloads[0]["enrichments"] == []
    assert payloads[0]["feed_status"] == []
    assert any(
        stage == "nvd" and state == "error" and "test fixture" in detail
        for stage, state, detail in events
    )


@pytest.mark.parametrize("lookup_fails", [False, True])
def test_live_scan_looks_up_only_scanner_named_cve_in_separate_cache(tmp_path, lookup_fails):
    database = tmp_path / "assessment.sqlite"
    events = []
    payloads = []
    cve_id = "CVE-2021-44228"
    real_sync = intel_online.sync_cves

    def fake_nmap(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun><host><status state="up"/>'
            '<address addr="172.28.0.10" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http" product="Apache" version="2.4"/>'
            '<script id="test" output="CVE-2021-44228 observed"/>'
            "</port></ports></host></nmaprun>",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    def fake_fetch(url, limit):
        if "nvd.nist.gov" in url:
            return {"vulnerabilities": [{"cve": {"id": cve_id, "metrics": {}}}]}
        if "api.first.org" in url:
            return {
                "status": "OK",
                "data": [
                    {"cve": cve_id, "epss": "0.9", "percentile": "0.99", "date": "2026-09-26"}
                ],
            }
        return {
            "count": 1,
            "dateReleased": "2026-09-26T00:00:00Z",
            "vulnerabilities": [{"cveID": cve_id}],
        }

    def sync(ids, store, **kwargs):
        assert ids == [cve_id]
        if lookup_fails:
            raise OSError("Intelligence service unavailable")
        return real_sync(ids, store, fetch_json=fake_fetch, **kwargs)

    with (
        patch.object(live_assessment, "nmap_binary", return_value="nmap.exe"),
        patch.object(live_assessment.subprocess, "run", side_effect=fake_nmap),
        patch.object(
            live_assessment.analyst,
            "analyze_target",
            side_effect=lambda payload, *_args, **_kwargs: (
                payloads.append(payload) or {"analysis": {"summary": "Observed."}}
            ),
        ),
        patch.object(live_assessment.intel_online, "sync_cves", side_effect=sync),
    ):
        result = live_assessment.run(
            "172.28.0.10",
            {"status": "ready", "resolved_ips": ["172.28.0.10"]},
            ROOT / "config",
            database=database,
            provider="ollama",
            on_progress=lambda *event: events.append(event),
        )
    assert (tmp_path / "intel-cache.db").is_file()
    assert not database.exists()
    assert result["scan_status"] == "complete"
    assert all(
        (stage, "complete") in [(stage, state) for stage, state, _ in events]
        for stage in ("score", "queue", "rationale", "report")
    )
    if lookup_fails:
        assert payloads[0]["enrichments"] == []
        assert result["assessment_summary"]["intelligence"]["mode"] == "unavailable"
        assert all(
            (stage, "error") in [(stage, state) for stage, state, _ in events]
            for stage in ("nvd", "epss", "kev", "intel")
        )
        return
    assert ("intel", "complete") in [(stage, state) for stage, state, _ in events]
    assert payloads[0]["enrichments"][0]["cve_id"] == cve_id
    assert payloads[0]["enrichments"][0]["kev"] is True
    assert result["assessment_summary"]["intelligence"]["checked_cves"] == [cve_id]
    assert result["assessment_summary"]["intelligence"]["matched_findings"] == 1
    assert all(
        (feed, "complete") in [(stage, state) for stage, state, _ in events]
        for feed in ("nvd", "epss", "kev")
    )


def test_feed_store_used_by_live_run_is_read_only(tmp_path):
    database = tmp_path / "feeds.sqlite"
    with Store(database) as store:
        store.start_run("recorded", "config")
    with Store(database, read_only=True) as store:
        assert store.run_info("recorded")["run_id"] == "recorded"
        with pytest.raises(sqlite3.OperationalError):
            store.start_run("should-not-write", "config")
    with Store(database) as store:
        assert store.run_info("should-not-write") is None


def test_live_scan_with_legacy_database_without_feed_tables_degrades_explicitly(tmp_path):
    database = tmp_path / "legacy.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE runs (run_id TEXT PRIMARY KEY)")
    events = []

    def fake_nmap(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
            "</host></nmaprun>",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch.object(live_assessment, "nmap_binary", return_value="nmap.exe"),
        patch.object(live_assessment.subprocess, "run", side_effect=fake_nmap),
        patch.object(
            live_assessment.analyst,
            "analyze_target",
            return_value={"analysis": {"summary": "No findings."}},
        ),
    ):
        result = live_assessment.run(
            "127.0.0.1",
            {"status": "ready", "resolved_ips": ["127.0.0.1"]},
            ROOT / "config",
            database=database,
            provider="ollama",
            on_progress=lambda *event: events.append(event),
        )
    assert result["assessment_summary"]["finding_count"] == 0
    assert any(
        stage == "nvd" and state == "skipped" and "No scanner-named CVE IDs" in detail
        for stage, state, detail in events
    )


def test_nmap_probe_uses_registered_windows_install_when_path_is_missing(monkeypatch):
    monkeypatch.delenv("VULNASSESS_NMAP_BIN", raising=False)
    with (
        patch.object(live_assessment, "_nmap_data_error", return_value=None),
        patch.object(live_assessment.shutil, "which", return_value=None),
        patch.object(
            live_assessment.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, "Nmap version 7.991", ""),
        ),
        patch.object(
            live_assessment,
            "_registered_nmap_binary",
            return_value=r"C:\Nmap\nmap.exe",
        ),
    ):
        binary, detail = live_assessment.nmap_probe()
    assert binary == r"C:\Nmap\nmap.exe"
    assert "Windows install" in detail


def test_nmap_probe_explains_broken_explicit_path_without_fallback(monkeypatch):
    monkeypatch.setenv("VULNASSESS_NMAP_BIN", r"C:\Missing\nmap.exe")
    with (
        patch.object(live_assessment.shutil, "which", return_value=None),
        patch.object(live_assessment, "_registered_nmap_binary") as registry,
    ):
        binary, detail = live_assessment.nmap_probe()
    assert binary is None
    assert "VULNASSESS_NMAP_BIN" in detail
    registry.assert_not_called()


def test_nmap_probe_reports_executable_launch_failure(monkeypatch):
    monkeypatch.setenv("VULNASSESS_NMAP_BIN", r"C:\Nmap\nmap.exe")
    with (
        patch.object(live_assessment.shutil, "which", return_value=r"C:\Nmap\nmap.exe"),
        patch.object(live_assessment.subprocess, "run", side_effect=OSError("cannot start")),
    ):
        binary, detail = live_assessment.nmap_probe()
    assert binary is None
    assert "could not start" in detail


def test_nmap_probe_prefers_server_path_and_checks_version(monkeypatch):
    monkeypatch.delenv("VULNASSESS_NMAP_BIN", raising=False)
    with (
        patch.object(live_assessment, "_nmap_data_error", return_value=None),
        patch.object(live_assessment.shutil, "which", return_value=r"C:\Nmap\nmap.exe"),
        patch.object(
            live_assessment.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, "Nmap version 7", ""),
        ) as version,
        patch.object(live_assessment, "_registered_nmap_binary") as registry,
    ):
        binary, detail = live_assessment.nmap_probe()
    assert binary == r"C:\Nmap\nmap.exe"
    assert "server PATH" in detail
    assert version.call_args.args[0] == [binary, "-V"]
    registry.assert_not_called()


def test_nmap_probe_reports_version_timeout_and_failure(monkeypatch):
    monkeypatch.setenv("VULNASSESS_NMAP_BIN", r"C:\Nmap\nmap.exe")
    with patch.object(live_assessment.shutil, "which", return_value=r"C:\Nmap\nmap.exe"):
        with patch.object(
            live_assessment.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["nmap", "-V"], 10),
        ):
            assert "timed out" in live_assessment.nmap_probe()[1]
        with patch.object(
            live_assessment.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 3, "", "failure"),
        ):
            binary, detail = live_assessment.nmap_probe()
    assert binary is None
    assert "exited 3" in detail


def test_live_run_reports_nmap_preflight_cause_before_scanner_launch():
    app = UiApplication(ROOT / "data" / "vulnassess.db", ROOT / "config")
    with (
        patch("vulnassess.ui.server.resolve_addresses", return_value=["45.33.32.156"]),
        patch.object(
            live_assessment,
            "nmap_probe",
            return_value=(None, "Nmap was found but could not start: missing DLL"),
        ),
        patch.object(live_assessment.subprocess, "run") as scanner,
    ):
        with pytest.raises(ConfigError, match="missing DLL"):
            app.live_report("scanme.nmap.org", "ollama", lambda *_: None)
    scanner.assert_not_called()


def test_model_retry_reuses_recent_scan_without_starting_nmap(tmp_path):
    from vulnassess.schema import ContextProfile, Feature, Host, Service

    database = tmp_path / "vulnassess.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE runs (run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
            "config_hash TEXT NOT NULL, summary_json TEXT NOT NULL DEFAULT '{}')"
        )
    app = UiApplication(database, ROOT / "config")
    check = {"status": "ready", "resolved_ips": ["45.33.32.156"], "missing": []}
    events = []
    captures = []
    retained_host = Host(
        ip="45.33.32.156", services=(Service(port=22, protocol="tcp", name="ssh"),)
    )
    retained_profile = ContextProfile(
        host_ip=retained_host.ip,
        role=Feature("unknown", 0.1, "rule", "SYNTHETIC retained context"),
        exposure=Feature("internet_facing", 1.0, "rule", "SYNTHETIC public IP"),
    )
    case = {
        "target": "scanme.nmap.org",
        "resolved_ip": "45.33.32.156",
        "scan_profile": "light",
        "services": retained_host.to_json()["services"],
        "finding_count": 0,
        "stage_events": [
            ("canonical", "complete", "Parsed one service"),
            ("score", "skipped", "No vulnerability findings"),
        ],
        "payload": {
            "hosts": [retained_host.to_json()],
            "findings": [],
            "scores": [],
            "enrichments": [],
            "context": [retained_profile.to_json()],
            "scanner_coverage": {
                "nmap": "top 100 TCP ports, SYNTHETIC retained test profile",
                "nikto": "not run; SYNTHETIC no web scan requested",
            },
        },
    }

    calls = 0

    def scanner_run(*args, **kwargs):
        nonlocal calls
        calls += 1
        kwargs["on_case"](case)
        if calls == 1:
            raise RuntimeError("model unavailable")
        return {
            "services": case["services"],
            "scan_status": "complete",
            "reused_scan": False,
            "assessment_summary": {"finding_count": 0},
        }

    with (
        patch.object(app, "target_check", return_value=check),
        patch("vulnassess.ui.server.time.monotonic", return_value=100),
        patch("vulnassess.ui.server.live_assessment.run", side_effect=scanner_run) as scanner,
        patch(
            "vulnassess.ui.server.analyst.analyze_target",
            return_value={"analysis": {"summary": "SSH observed"}},
        ),
    ):
        with pytest.raises(RuntimeError, match="model unavailable"):
            app.live_report(
                "scanme.nmap.org",
                "openrouter",
                lambda *event: events.append(event),
                captures.append,
            )
        fresh = app.live_report(
            "scanme.nmap.org",
            "openrouter",
            lambda *event: events.append(event),
            captures.append,
        )
        result = app.live_report(
            "scanme.nmap.org",
            "openrouter",
            lambda *event: events.append(event),
            captures.append,
            reuse_recent=True,
        )

    assert scanner.call_count == 2
    assert fresh["reused_scan"] is False
    assert result["reused_scan"] is True
    assert result["services"] == case["services"]
    assert captures[-1]["services"] == case["services"]
    assert result["scan_status"] == "complete"
    assert any(stage == "scanner" and "Reused" in detail for stage, _, detail in events)
    assert any(stage == "canonical" and "Reused" in detail for stage, _, detail in events)
    assert result["assessment_summary"]["finding_count"] == 0
    assert app._last_live_scan == {}
