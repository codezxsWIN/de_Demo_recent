"""Optional scanner failures must preserve the completed discovery evidence."""

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.test_all import SETTINGS, make_finding
from vulnassess import live_assessment
from vulnassess.errors import AdapterError
from vulnassess.schema import Host, Service


@pytest.fixture
def endpoint_run(tmp_path, monkeypatch):
    host = Host(ip="127.0.0.1", services=(Service(port=22, protocol="tcp", name="ssh"),))
    findings = [make_finding(host_ip=host.ip)]
    endpoint = {"host": "synthetic.invalid", "scheme": "http", "port": 8080, "path": "/"}
    observed = replace(host, services=(Service(port=8080, protocol="tcp", name="http"),))
    parser = Mock(return_value=([observed], []))
    events = []

    def scanner(command, **kwargs):
        flag = "-oX" if "-oX" in command else "-output"
        Path(command[command.index(flag) + 1]).write_text(
            "SYNTHETIC scanner boundary"
            if flag == "-oX"
            else json.dumps(
                {
                    "ip": host.ip,
                    "port": endpoint["port"],
                    "vulnerabilities": [],
                    "end_time": "SYNTHETIC completed report",
                }
            )
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    transport = Mock(side_effect=scanner)
    monkeypatch.setattr(live_assessment.subprocess, "run", transport)
    monkeypatch.setattr(live_assessment, "parse_nmap_xml", parser)
    monkeypatch.setattr(live_assessment, "parse_nikto_json", Mock(return_value=[]))
    monkeypatch.setattr(
        live_assessment.orchestrator, "scanner_status", lambda _: {"status": "available"}
    )
    monkeypatch.setattr(live_assessment.orchestrator, "scanner_argv", lambda _: ["synthetic-nikto"])
    redis = Mock(side_effect=AssertionError("No Redis probe expected"))
    monkeypatch.setattr(live_assessment.redis_probe, "run", redis)

    def run():
        return live_assessment._scan_requested_endpoint(
            "synthetic-nmap",
            host.ip,
            endpoint,
            SETTINGS,
            tmp_path,
            host,
            findings,
            lambda *event: events.append(event),
        )

    return run, host, findings, endpoint, observed, parser, transport, redis, events


@pytest.mark.parametrize(
    "failure", ["exit", "missing", "os", "timeout", "parse", "wrong-host", "duplicate"]
)
def test_requested_port_failure_never_discards_discovery_or_launches_web_probe(
    endpoint_run, failure
):
    run, host, findings, _, observed, parser, transport, redis, events = endpoint_run
    if failure in {"exit", "missing"}:
        transport.side_effect = None
        transport.return_value = subprocess.CompletedProcess(
            [], 1 if failure == "exit" else 0, "", ""
        )
    elif failure == "os":
        transport.side_effect = OSError("synthetic executable disappeared")
    elif failure == "timeout":
        transport.side_effect = subprocess.TimeoutExpired("synthetic-nmap", 90)
    elif failure == "parse":
        parser.side_effect = AdapterError("synthetic malformed capture")
    else:
        parser.return_value = (
            [replace(observed, ip="192.0.2.1")]
            if failure == "wrong-host"
            else [observed, observed],
            [],
        )
    result = run()
    assert result == (host, findings, "failed", "skipped")
    assert len(findings) == 1
    assert transport.call_count == 1
    redis.assert_not_called()
    assert any(stage == "endpoint_scan" and state == "error" for stage, state, _ in events)
    assert events[-1][:2] == ("nikto", "skipped")


def test_closed_requested_port_keeps_original_services_and_does_not_launch_nikto(endpoint_run):
    run, host, findings, _, observed, parser, transport, redis, events = endpoint_run
    parser.return_value = ([replace(observed, services=())], [])
    assert run() == (host, findings, "closed", "skipped")
    assert transport.call_count == 1
    redis.assert_not_called()
    assert "not open" in events[-1][2]


@pytest.mark.parametrize("name", ["http", "http-alt", "http-proxy", "ssl/http-alt", "https-alt"])
def test_supported_web_labels_share_the_cli_eligibility_rule(endpoint_run, name):
    run, _, _, _, observed, parser, transport, redis, _ = endpoint_run
    parser.return_value = (
        [replace(observed, services=(Service(8080, "tcp", name=name),))],
        [],
    )
    assert run()[2:] == ("complete", "complete")
    assert transport.call_count == 2
    redis.assert_not_called()


def test_udp_redis_label_cannot_redirect_a_confirmed_tcp_http_check(endpoint_run):
    run, _, _, _, observed, parser, transport, redis, _ = endpoint_run
    parser.return_value = (
        [
            replace(
                observed,
                services=(Service(8080, "tcp", name="http"), Service(8080, "udp", name="redis")),
            )
        ],
        [],
    )
    assert run()[2:] == ("complete", "complete")
    assert transport.call_count == 2
    redis.assert_not_called()


@pytest.mark.parametrize("failure", ["dependency", "disappeared", "os", "timeout", "parse"])
def test_nikto_failure_retains_confirmed_endpoint_and_findings(endpoint_run, monkeypatch, failure):
    run, host, findings, _, observed, parser, transport, _, events = endpoint_run
    extra = make_finding(host_ip=host.ip, tool_native_id="synthetic-endpoint", port=8080)
    parser.return_value = ([observed], [extra])
    if failure == "dependency":
        monkeypatch.setattr(
            live_assessment.orchestrator,
            "scanner_status",
            lambda _: {"status": "dependency-error", "detail": "Missing synthetic module"},
        )
    elif failure == "disappeared":
        monkeypatch.setattr(live_assessment.orchestrator, "scanner_argv", lambda _: None)
    elif failure == "parse":
        monkeypatch.setattr(
            live_assessment,
            "parse_nikto_json",
            Mock(side_effect=AdapterError("synthetic invalid JSON")),
        )
    else:
        scanner = transport.side_effect

        def fail_web(command, **kwargs):
            if "-oX" in command:
                return scanner(command, **kwargs)
            if failure == "os":
                raise OSError("synthetic executable failure")
            raise subprocess.TimeoutExpired("synthetic-nikto", 150)

        transport.side_effect = fail_web
    merged_host, merged_findings, endpoint_status, nikto_status = run()
    assert [service.port for service in merged_host.services] == [22, 8080]
    assert merged_findings == findings and extra in merged_findings
    assert (endpoint_status, nikto_status) == ("complete", "failed")
    assert transport.call_count == (1 if failure in {"dependency", "disappeared"} else 2)
    assert events[-1][:2] == ("nikto", "error")


@pytest.mark.parametrize("failure", ["tls", "os", "timeout"])
def test_unavailable_redis_inspection_never_claims_a_vulnerability(endpoint_run, failure):
    run, _, findings, endpoint, observed, parser, transport, redis, events = endpoint_run
    parser.return_value = (
        [replace(observed, services=(Service(port=8080, protocol="tcp", name="redis"),))],
        [],
    )
    if failure == "tls":
        endpoint["scheme"] = "https"
    else:
        redis.side_effect = (
            OSError("synthetic unavailable")
            if failure == "os"
            else TimeoutError("synthetic timeout")
        )
    _, result_findings, endpoint_status, nikto_status = run()
    assert result_findings == findings and len(findings) == 1
    assert endpoint_status == (
        "redis not inspected" if failure == "tls" else "redis inspection failed"
    )
    assert nikto_status == "skipped"
    assert transport.call_count == 1
    assert redis.call_count == (0 if failure == "tls" else 1)
    assert not any(stage == "nikto" and state == "running" for stage, state, _ in events)
