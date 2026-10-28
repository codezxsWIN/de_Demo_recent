"""Offline contracts for Redis alongside the Office and IoT policy checks."""
import json
import subprocess
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from labs.service_networks.catalog import ENVIRONMENTS
from vulnassess import cve_discovery, live_assessment, network_service_checks, network_service_policy
from vulnassess.schema import Host, Service
from vulnassess.settings import Settings
from vulnassess.store import Store

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"


@pytest.mark.parametrize("ip,other_ports", [
    ("127.0.0.2", {2121, 2122, 1445, 1446, 2222, 2223}),
    ("127.0.0.3", {1883, 1884, 8883}),
])
def test_live_scan_scope_contains_redis_and_existing_ports(ip, other_ports, monkeypatch):
    settings = Settings(CONFIG)
    policy = network_service_policy.load(CONFIG, settings.scope, ip)
    ports = {entry["port"] for entry in policy["endpoints"] if entry["transport"] == "tcp"}
    assert ports == other_ports | {6379}
    assert set(ENVIRONMENTS[ip]["tcp"]) == ports
    entry = next(entry for entry in policy["endpoints"] if entry["port"] == 6379)
    assert entry == {"port": 6379, "transport": "tcp", "service": "redis"}
    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "nmap")

    def inspect(command, **kwargs):
        assert command[-1] == ip
        assert set(map(int, command[command.index("-p") + 1].split(","))) == ports
        raise subprocess.TimeoutExpired(command, 180)

    monkeypatch.setattr(live_assessment.subprocess, "run", inspect)
    with pytest.raises(Exception, match="timed out"):
        live_assessment.run(ip, {"status": "ready", "resolved_ips": [ip]}, CONFIG,
                            provider="openrouter", on_progress=lambda *args: None,
                            on_capture=lambda *args: None)


@pytest.mark.parametrize("ip", ["127.0.0.2", "127.0.0.3"])
def test_redis_identity_reaches_nvd_as_candidate(ip, tmp_path, monkeypatch):
    settings = Settings(CONFIG)
    policy = network_service_policy.load(CONFIG, settings.scope, ip)
    body = b"# Server\r\nredis_version:7.0.5\r\n"

    class Wire:
        def __init__(self):
            self.data = b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n"
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def settimeout(self, timeout): pass
        def sendall(self, request):
            assert request == b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"
        def recv(self, count):
            data, self.data = self.data[:count], self.data[count:]
            return data

    connect = Mock(return_value=Wire())
    monkeypatch.setattr("vulnassess.redis_identity.socket.create_connection", connect)
    findings, services, _ = network_service_checks.run(
        settings.scope, ip, policy, [Service(6379, "tcp", name="redis")], tmp_path)
    connect.assert_called_once_with((ip, 6379), timeout=4)
    assert not findings
    redis = next(s for s in services if s.port == 6379)
    assert redis.version == "7.0.5"
    assert redis.cpe == "cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*"
    record = {"cve": {"id": "CVE-2026-12345", "descriptions": [{"lang": "en", "value": "Synthetic"}],
              "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True,
              "criteria": "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*", "versionEndExcluding": "7.0.6"}]}]}]}}
    fetch = Mock(return_value={"startIndex": 0, "totalResults": 1, "vulnerabilities": [record]})
    with Store(tmp_path / "intel.db") as store:
        candidates, receipt = cve_discovery.discover(Host(ip, services=(redis,)), tmp_path, store,
                                                     fetch=fetch, sleep=lambda *_: None,
                                                     progress=lambda *_: None)
    assert parse_qs(urlsplit(fetch.call_args.args[0]).query)["cpeName"] == [redis.cpe]
    assert len(candidates) == 1
    assert cve_discovery.candidate_facts(candidates[0], redis)["notice"] == cve_discovery.NOTICE
    assert candidates[0].native_confidence == "medium"
    assert receipt["findings_created"] == 1
    saved = json.loads((tmp_path / "network-service-observations.json").read_text())
    assert next(row for row in saved["observations"] if row["port"] == 6379)["violations"] == []
