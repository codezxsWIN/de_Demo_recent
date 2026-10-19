import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vulnassess import live_assessment
from vulnassess.errors import AdapterError
from vulnassess.readers.nikto_json import parse_nikto_json
from vulnassess.schema import Host


@pytest.mark.parametrize("service_name", ["tcpwrapped", "unknown", "ssh"])
def test_url_scheme_does_not_authorize_nikto_for_non_http_service(tmp_path, service_name):
    def nmap(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun><host><status state="up"/>'
            '<address addr="127.0.0.1" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="6379"><state state="open"/>'
            f'<service name="{service_name}"/></port></ports></host></nmaprun>',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    events = []
    settings = SimpleNamespace(scope=SimpleNamespace(tags=lambda ip: {"environment": "test"}))
    with (
        patch.object(live_assessment.subprocess, "run", side_effect=nmap) as process,
        patch.object(live_assessment.orchestrator, "scanner_status") as readiness,
        patch.object(live_assessment.redis_probe, "run") as redis,
    ):
        host, findings, endpoint_status, nikto_status = live_assessment._scan_requested_endpoint(
            "nmap",
            "127.0.0.1",
            {"scheme": "http", "host": "lab.example", "port": 6379, "path": "/"},
            settings,
            tmp_path,
            Host(ip="127.0.0.1"),
            [],
            lambda *event: events.append(event),
        )
    assert endpoint_status == "complete"
    assert nikto_status == "not HTTP"
    assert findings == []
    assert host.services[0].name == service_name
    process.assert_called_once()
    readiness.assert_not_called()
    redis.assert_not_called()
    assert any(
        stage == "nikto" and state == "skipped" and "HTTP" in detail
        for stage, state, detail in events
    )


@pytest.mark.parametrize("include_valid_finding", [False, True])
def test_nikto_fail_record_rejects_report_instead_of_creating_findings(
    tmp_path, include_valid_finding
):
    entries = [{"id": "FAIL", "msg": "Unable to connect to 127.0.0.1:6379.", "url": "/"}]
    if include_valid_finding:
        entries.insert(0, {"id": "013587", "msg": "Missing security header", "url": "/"})
    capture = tmp_path / "nikto.json"
    capture.write_text(
        json.dumps(
            [
                {
                    "ip": "127.0.0.1",
                    "port": 6379,
                    "vulnerabilities": entries,
                }
            ]
        ),
        encoding="utf-8",
    )
    original = capture.read_bytes()
    with pytest.raises(AdapterError, match="scan failure"):
        parse_nikto_json(capture, "unit")
    assert capture.read_bytes() == original


def test_zero_exit_nikto_failure_is_failed_coverage_with_no_scored_finding(tmp_path):
    def process(command, **kwargs):
        if "-oX" in command:
            Path(command[command.index("-oX") + 1]).write_text(
                '<nmaprun><host><status state="up"/>'
                '<address addr="127.0.0.1" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="7001"><state state="open"/>'
                '<service name="http"/></port></ports></host></nmaprun>',
                encoding="utf-8",
            )
        else:
            Path(command[command.index("-output") + 1]).write_text(
                json.dumps(
                    [
                        {
                            "ip": "127.0.0.1",
                            "port": 7001,
                            "vulnerabilities": [
                                {"id": "FAIL", "msg": "Unable to connect.", "url": "/"}
                            ],
                        }
                    ]
                ),
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    events = []
    settings = SimpleNamespace(scope=SimpleNamespace(tags=lambda ip: {"environment": "test"}))
    with (
        patch.object(live_assessment.subprocess, "run", side_effect=process),
        patch.object(
            live_assessment.orchestrator, "scanner_status", return_value={"status": "available"}
        ),
        patch.object(live_assessment.orchestrator, "scanner_argv", return_value=("nikto.pl",)),
    ):
        host, findings, endpoint_status, nikto_status = live_assessment._scan_requested_endpoint(
            "nmap",
            "127.0.0.1",
            {"scheme": "http", "host": "lab.example", "port": 7001, "path": "/"},
            settings,
            tmp_path,
            Host(ip="127.0.0.1"),
            [],
            lambda *event: events.append(event),
        )
    assert host.services[0].name == "http"
    assert endpoint_status == "complete"
    assert nikto_status == "failed"
    assert findings == []
    assert (tmp_path / "nikto.json").is_file()
    assert any(stage == "nikto" and state == "error" for stage, state, detail in events)
