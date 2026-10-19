import json
from unittest.mock import patch

import pytest

from vulnassess import redis_probe
from vulnassess.errors import ScopeError


class Scope:
    def contains(self, ip):
        return ip == "178.79.134.182"

    def is_canary(self, ip):
        return False

    def tags(self, ip):
        return {"environment": "test"}


class Connection:
    def __init__(self, reply):
        self.reply = reply
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, value):
        pass

    def recv(self, limit):
        reply, self.reply = self.reply, b""
        return reply


def test_scope_refusal_precedes_network(tmp_path):
    with patch("socket.create_connection") as connect:
        with pytest.raises(ScopeError):
            redis_probe.run(Scope(), "192.0.2.4", 6379, tmp_path)
    connect.assert_not_called()


@pytest.mark.parametrize(
    "tags,canary", [({"environment": "prod"}, False), ({"environment": "test"}, True)]
)
def test_production_and_canary_refused(tmp_path, tags, canary):
    scope = Scope()
    scope.tags = lambda _: tags
    scope.is_canary = lambda _: canary
    with patch("socket.create_connection") as connect:
        with pytest.raises(ScopeError):
            redis_probe.run(scope, "178.79.134.182", 6379, tmp_path)
    connect.assert_not_called()


def test_live_endpoint_routes_redis_to_fixed_check_not_nikto(tmp_path):
    import subprocess
    from pathlib import Path
    from types import SimpleNamespace

    from vulnassess import live_assessment
    from vulnassess.schema import Host

    def nmap(command, **kwargs):
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun><host><status state="up"/><address addr="178.79.134.182" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="6379"><state state="open"/>'
            '<service name="redis"/></port></ports></host></nmaprun>'
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    events = []
    with (
        patch.object(live_assessment.subprocess, "run", side_effect=nmap),
        patch("socket.create_connection", return_value=Connection(redis_probe.POSITIVE)),
        patch.object(live_assessment.orchestrator, "scanner_status") as nikto,
    ):
        _, findings, status, nikto_status = live_assessment._scan_requested_endpoint(
            "nmap",
            "178.79.134.182",
            {"scheme": "http", "host": "pentest-ground.com", "port": 6379, "path": "/"},
            SimpleNamespace(scope=Scope()),
            tmp_path,
            Host(ip="178.79.134.182"),
            [],
            lambda *event: events.append(event),
        )
    assert findings[0].cve_ids == ("CVE-2022-0543",)
    assert "RCE not attempted" in status
    assert nikto_status == "not HTTP"
    nikto.assert_not_called()


@pytest.mark.parametrize(
    "reply,positive",
    [
        (b"$14\r\ntable:function\r\n", True),
        (b"-ERR unknown global package\r\n", False),
        (b"-NOAUTH Authentication required\r\n", False),
        (b"$3\r\nnil\r\n", False),
    ],
)
def test_only_exact_vulnerable_configuration_creates_finding(tmp_path, reply, positive):
    connection = Connection(reply)
    with patch("socket.create_connection", return_value=connection) as connect:
        result = redis_probe.run(Scope(), "178.79.134.182", 6379, tmp_path)
    connect.assert_called_once_with(("178.79.134.182", 6379), timeout=5)
    assert len(connection.sent) == 1
    assert b"loadlib(" not in connection.sent[0]
    assert b"redis.call" not in connection.sent[0]
    assert b"os." not in connection.sent[0]
    assert bool(result) is positive
    if positive:
        assert result.cve_ids == ("CVE-2022-0543",)
        assert "OS command execution was not attempted" in result.description
    assert (
        json.loads((tmp_path / "redis-lua-check.json").read_text())["target_ip"] == "178.79.134.182"
    )
