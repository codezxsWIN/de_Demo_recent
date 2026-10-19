"""Synthetic execution outcomes; every scanner, probe and provider boundary is inert."""

import json
import shutil
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.adversarial.test_scan_plans import answer, context
from tests.test_all import SETTINGS, make_finding
from vulnassess import capture_history, live_assessment, orchestrator, runner, scan_plans
from vulnassess.ai_boundary import digest
from vulnassess.errors import AdapterError, ConfigError, ScopeError
from vulnassess.schema import Host, Service


@pytest.fixture(autouse=True)
def inert_execution_boundaries(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", Mock(side_effect=AssertionError("Unstubbed process is forbidden"))
    )
    monkeypatch.setattr(
        live_assessment.redis_probe,
        "run",
        Mock(side_effect=AssertionError("Unstubbed Redis transport is forbidden")),
    )
    monkeypatch.setattr(
        live_assessment.intel_online,
        "sync_cves",
        Mock(side_effect=AssertionError("Publisher access is forbidden")),
    )
    monkeypatch.setattr(
        live_assessment.analyst,
        "provider_client",
        Mock(side_effect=AssertionError("Provider access is forbidden")),
    )


@pytest.mark.parametrize("configured", [True, False])
def test_nikto_path_resolution_uses_discovered_executable_without_starting_it(
    monkeypatch, configured
):
    monkeypatch.delenv("VULNASSESS_NIKTO_BIN", raising=False)
    if configured:
        monkeypatch.setenv("VULNASSESS_NIKTO_BIN", "synthetic-nikto")
    monkeypatch.setattr(orchestrator.shutil, "which", lambda _: "synthetic-nikto.exe")
    assert orchestrator.scanner_argv("nikto") == ("synthetic-nikto.exe",)
    subprocess.run.assert_not_called()


@pytest.mark.parametrize("entry_point", ["plan", "missing_binaries"])
def test_unknown_scanner_is_rejected_before_discovery(tmp_path, monkeypatch, entry_point):
    discovery = Mock(side_effect=AssertionError("Invalid tool must not reach discovery"))
    monkeypatch.setattr(orchestrator, "scanner_argv", discovery)
    with pytest.raises(ConfigError, match="unknown scanner 'synthetic-unknown'"):
        if entry_point == "plan":
            orchestrator.plan(SETTINGS, "127.0.0.1", tmp_path, ["synthetic-unknown"])
        else:
            orchestrator.missing_binaries(["synthetic-unknown"])
    discovery.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_public_light_scan_exception_does_not_authorize_aggressive_orchestration(tmp_path):
    assert SETTINGS.scope.contains("45.33.32.156")
    with pytest.raises(ScopeError, match="public target.*separate light-scan path"):
        orchestrator.plan(SETTINGS, "45.33.32.156", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_unreadable_canary_log_cannot_be_treated_as_empty(tmp_path, monkeypatch):
    log = tmp_path / "synthetic_canary.log"
    log.write_text("", encoding="utf-8")
    read_text = Path.read_text

    def inaccessible(path, *args, **kwargs):
        if path == log:
            raise PermissionError("synthetic access denied")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", inaccessible)
    with pytest.raises(ConfigError, match="cannot read canary access log") as error:
        orchestrator.plan(SETTINGS, "127.0.0.1", tmp_path, canary_log=log)
    assert isinstance(error.value.__cause__, PermissionError)
    subprocess.run.assert_not_called()


def test_web_plan_rejects_a_discovery_host_from_another_target(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator, "scanner_argv", lambda _: ("synthetic-scanner",))
    plan = orchestrator.plan(SETTINGS, "127.0.0.1", tmp_path)
    with pytest.raises(AdapterError, match="expected target 127.0.0.1"):
        orchestrator.web_plan(plan, Host(ip="172.28.0.10"))
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("failure", ["start", "missing-output", "malformed-output"])
def test_discovery_failure_is_retained_and_web_tools_never_execute(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(orchestrator, "scanner_argv", lambda _: ("synthetic-scanner",))
    plan = orchestrator.plan(SETTINGS, "127.0.0.1", tmp_path)

    def execute(command):
        if failure == "start":
            raise OSError("synthetic executable disappeared")
        if failure == "malformed-output":
            command.output.write_text("SYNTHETIC incomplete XML", encoding="utf-8")
        return orchestrator.Execution(0, "2026-10-11T00:00:00Z", "2026-10-11T00:00:01Z")

    executor = Mock(side_effect=execute)
    result = orchestrator.orchestrate(plan, "synthetic-final", executor)
    assert result["complete"] is False
    assert result["failed_tools"] == 1
    assert result["successful_tools"] == 0
    assert result["endpoints"] == []
    discovery, web = result["outcomes"]
    assert discovery["status"] == "failed"
    assert discovery["raw_path"] == str(plan.discovery.output)
    assert discovery["finding_count"] == 0
    assert discovery["failure"]
    if failure == "start":
        assert "executor raised OSError" in discovery["failure"]
        assert discovery["exit_code"] is None
    else:
        assert discovery["exit_code"] == 0
    assert web["status"] == "skipped" and "Nmap discovery failed" in web["skip_reason"]
    assert executor.call_count == 1


def test_runner_missing_binary_cannot_create_capture_directory_or_start_process(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    output = tmp_path / "synthetic-capture"
    with pytest.raises(ConfigError, match="MISSING scanner binary"):
        runner.run_scan(SETTINGS, "127.0.0.1", ["nmap"], output, execute=True)
    assert not output.exists()
    subprocess.run.assert_not_called()


@pytest.mark.parametrize("launchable", [True, False])
def test_nmap_binary_exposes_only_a_successful_preflight(monkeypatch, launchable):
    # Isolate executable preflight; startup-data validation has its own tests.
    monkeypatch.setattr(live_assessment, "_nmap_data_error", lambda _: None)
    monkeypatch.setenv("VULNASSESS_NMAP_BIN", "synthetic-nmap")
    monkeypatch.setattr(live_assessment.shutil, "which", lambda _: "synthetic-nmap")
    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 0 if launchable else 1, "", "")),
    )
    assert live_assessment.nmap_binary() == ("synthetic-nmap" if launchable else None)
    assert subprocess.run.call_args.args[0] == ["synthetic-nmap", "-V"]


def test_registry_entries_without_existing_binary_do_not_claim_readiness(tmp_path, monkeypatch):
    registry = SimpleNamespace(
        KEY_WOW64_32KEY=32,
        KEY_WOW64_64KEY=64,
        KEY_READ=1,
        HKEY_LOCAL_MACHINE=2,
        OpenKey=lambda *_: nullcontext("synthetic-key"),
        QueryValueEx=Mock(side_effect=[(str(tmp_path), 1), (None, 1)]),
    )
    monkeypatch.setattr(live_assessment, "os", SimpleNamespace(name="nt"))
    monkeypatch.setitem(sys.modules, "winreg", registry)
    assert live_assessment._registered_nmap_binary() is None
    subprocess.run.assert_not_called()


@pytest.fixture
def observed_endpoint(tmp_path, monkeypatch):
    original = Host(ip="127.0.0.1", services=(Service(port=22, protocol="tcp", name="ssh"),))
    observed = Host(ip=original.ip, services=(Service(port=8080, protocol="tcp", name="http"),))
    findings = [make_finding(host_ip=original.ip)]
    extra = make_finding(host_ip=original.ip, port=8080, tool_native_id="synthetic-endpoint")
    monkeypatch.setattr(live_assessment, "parse_nmap_xml", lambda *_: ([observed], [extra]))
    monkeypatch.setattr(orchestrator, "scanner_status", lambda _: {"status": "available"})
    monkeypatch.setattr(orchestrator, "scanner_argv", lambda _: ("synthetic-nikto",))
    events = []
    endpoint = {"host": "synthetic.invalid", "scheme": "http", "port": 8080, "path": "/"}
    return original, findings, extra, endpoint, events


@pytest.mark.parametrize("failure", ["exit", "missing-output"])
def test_nikto_unsuccessful_result_preserves_confirmed_services_and_findings(
    tmp_path, monkeypatch, observed_endpoint, failure
):
    original, findings, extra, endpoint, events = observed_endpoint

    def scanner(command, **kwargs):
        if "-oX" in command:
            Path(command[command.index("-oX") + 1]).write_text("SYNTHETIC boundary")
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 7 if failure == "exit" else 0, "", "")

    monkeypatch.setattr(subprocess, "run", scanner)
    host, retained, status, nikto = live_assessment._scan_requested_endpoint(
        "synthetic-nmap",
        original.ip,
        endpoint,
        SETTINGS,
        tmp_path,
        original,
        findings,
        lambda *event: events.append(event),
    )
    assert [service.port for service in host.services] == [22, 8080]
    assert retained[-1] == extra and len(retained) == 2
    assert (status, nikto) == ("complete", "failed")
    assert events[-1] == ("nikto", "error", f"Nikto exited {7 if failure == 'exit' else 0}")


def test_nmap_only_approval_cannot_launch_followup_probe(tmp_path, monkeypatch, observed_endpoint):
    original, findings, extra, endpoint, events = observed_endpoint
    source = context()
    source.update(target_ip=original.ip, scope_hash=digest(SETTINGS.raw["scope.yaml"]))
    proposal = answer() | {"target_ip": original.ip}
    plans = scan_plans.PlanRegistry(tmp_path / "synthetic_audit.jsonl", clock=lambda: 10.0)
    draft = plans.create(proposal, source)
    plans.approve(draft["plan_id"], draft["plan_hash"])
    execution = plans.claim(draft["plan_id"], draft["plan_hash"], source)
    execution.before("nmap", original.ip, source["scope_hash"])

    def scanner(command, **kwargs):
        assert "-oX" in command
        Path(command[command.index("-oX") + 1]).write_text("SYNTHETIC boundary")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", scanner)
    host, retained, status, nikto = live_assessment._scan_requested_endpoint(
        "synthetic-nmap",
        original.ip,
        endpoint,
        SETTINGS,
        tmp_path,
        original,
        findings,
        lambda *event: events.append(event),
        execution,
    )
    assert [service.port for service in host.services] == [22, 8080]
    assert retained[-1] == extra
    assert (status, nikto) == ("complete", "not in approved plan")
    assert "no web or Redis probe launched" in events[-1][2]
    assert execution.finish()["state"] == "completed"
    live_assessment.redis_probe.run.assert_not_called()


def test_retained_redis_observation_is_hashed_and_reopens_with_its_coverage(tmp_path, monkeypatch):
    config = tmp_path / "config"
    shutil.copytree(SETTINGS.config_dir, config)
    host = Host(ip="127.0.0.1", services=(Service(port=6379, protocol="tcp", name="redis"),))
    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "synthetic-nmap")
    monkeypatch.setattr(live_assessment, "parse_nmap_xml", lambda *_: ([host], []))

    def scanner(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text("SYNTHETIC boundary")
        return subprocess.CompletedProcess(command, 0, "", "")

    def redis_transport(scope, ip, port, directory):
        (directory / "redis-lua-check.json").write_text(
            json.dumps({"synthetic": True, "observation": "configuration not established"})
        )
        return None

    monkeypatch.setattr(subprocess, "run", scanner)
    monkeypatch.setattr(live_assessment.redis_probe, "run", redis_transport)
    monkeypatch.setattr(
        live_assessment.analyst,
        "analyze_optional",
        lambda *_args, **_kwargs: {"analyst": None, "ai_status": "unavailable", "ai_attempts": []},
    )
    cases = []
    result = live_assessment.run(
        "http://127.0.0.1:6379/",
        {
            "status": "ready",
            "resolved_ips": [host.ip],
            "endpoint": {
                "host": host.ip,
                "scheme": "http",
                "port": 6379,
                "path": "/",
            },
        },
        config,
        provider="ollama",
        on_progress=lambda *_: None,
        on_case=cases.append,
    )
    directory = Path(result["evidence_directory"])
    saved = capture_history.load(directory.parent, directory.name)
    assert result["scan_status"] == "complete" and result["finding_count"] == 0
    coverage = saved["payload"]["scanner_coverage"]
    assert "did not establish" in coverage["redis-check"]
    assert "not HTTP" in coverage["nikto"]
    assert coverage == cases[0]["payload"]["scanner_coverage"]
    manifest = json.loads((directory / "manifest.json").read_text())
    assert "redis-lua-check.json" in manifest["files"]
    assert saved["payload"]["scores"] == []
