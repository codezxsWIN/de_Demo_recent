"""Synthetic protocol facts test classification, not a real scanner or TLS handshake."""

from pathlib import Path

import pytest

from tests.test_all import SETTINGS
from vulnassess import context, orchestrator
from vulnassess.readers import parse_nmap_xml
from vulnassess.schema import Host, Service


@pytest.mark.parametrize("port", [80, 443, 3000, 8000, 8080, 8443])
@pytest.mark.parametrize("name", [None, "unknown", "tcpwrapped", "ssh", "redis", "smtp"])
def test_a_common_web_port_is_not_observed_http(port, name):
    host = Host("172.28.0.10", services=(Service(port, "tcp", name=name),))
    assert orchestrator.derive_endpoints(host) == []


@pytest.mark.parametrize("protocol", ["udp", "sctp", "unknown"])
@pytest.mark.parametrize("name", ["http", "https", "ssl/http", "http-proxy"])
def test_a_non_tcp_service_is_not_a_tcp_web_endpoint(protocol, name):
    host = Host("172.28.0.10", services=(Service(443, protocol, name=name, tls=True),))
    assert orchestrator.derive_endpoints(host) == []


@pytest.mark.parametrize(
    "name", ["prefix/http", "http-database", "http-proxy-exploit", "https_unknown"]
)
def test_an_http_substring_is_not_a_supported_service_identity(name):
    host = Host("172.28.0.10", services=(Service(49152, "tcp", name=name),))
    assert orchestrator.derive_endpoints(host) == []


@pytest.mark.parametrize(
    "name,port,tls,url",
    [
        ("http", 443, False, "http://172.28.0.10:443"),
        ("http", 8443, False, "http://172.28.0.10:8443"),
        ("http", 49152, False, "http://172.28.0.10:49152"),
        ("http-alt", 8080, False, "http://172.28.0.10:8080"),
        ("http-proxy", 3128, False, "http://172.28.0.10:3128"),
        ("https", 80, False, "https://172.28.0.10:80"),
        ("https-alt", 49152, False, "https://172.28.0.10:49152"),
        ("ssl/http", 49152, False, "https://172.28.0.10:49152"),
        ("ssl/http-alt", 49152, False, "https://172.28.0.10:49152"),
        ("http", 443, True, "https://172.28.0.10"),
    ],
)
def test_explicit_service_and_tls_evidence_select_the_scheme(name, port, tls, url):
    host = Host("172.28.0.10", services=(Service(port, "tcp", name=name, tls=tls),))
    endpoints = orchestrator.derive_endpoints(host)
    assert len(endpoints) == 1 and endpoints[0].url == url


@pytest.mark.parametrize("port", [80, 443, 8443, 49152])
@pytest.mark.parametrize("name", [None, "http", "ssh"])
def test_port_number_cannot_create_a_tls_control_observation(tmp_path, port, name):
    attribute = f' name="{name}"' if name else ""
    capture = tmp_path / "synthetic_plain_service.xml"
    capture.write_text(
        "<!-- SYNTHETIC parser input; no scanner or handshake -->"
        '<nmaprun><host><address addr="172.28.0.10" addrtype="ipv4"/><ports>'
        f'<port protocol="tcp" portid="{port}"><state state="open"/>'
        f"<service{attribute}/></port></ports></host></nmaprun>"
    )
    hosts, findings = parse_nmap_xml(capture, "synthetic-protocol")
    assert hosts[0].services[0].tls is False
    controls = context.detect_controls(hosts[0], findings, {})
    assert controls["tls"].value is None
    assert controls["tls"].evidence == "none observed"


@pytest.mark.parametrize(
    "name,tunnel", [("http", "ssl"), ("redis", "ssl"), ("https", None), ("ssl/http", None)]
)
def test_explicit_tls_classification_is_not_lost(tmp_path, name, tunnel):
    attribute = f' tunnel="{tunnel}"' if tunnel else ""
    capture = tmp_path / "synthetic_tls_service.xml"
    capture.write_text(
        "<!-- SYNTHETIC scanner classification; not a real TLS verification -->"
        '<nmaprun><host><address addr="172.28.0.10" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="49152"><state state="open"/>'
        f'<service name="{name}"{attribute}/></port></ports></host></nmaprun>'
    )
    hosts, _ = parse_nmap_xml(capture, "synthetic-protocol")
    assert hosts[0].services[0].tls is True


def test_a_port_table_https_guess_is_not_a_tls_observation(tmp_path):
    capture = tmp_path / "synthetic_table_guess.xml"
    capture.write_text(
        "<!-- SYNTHETIC port-table label, no TLS probe -->"
        '<nmaprun><host><address addr="172.28.0.10" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="443"><state state="open"/>'
        '<service name="https" method="table" conf="3"/></port></ports></host></nmaprun>'
    )
    hosts, _ = parse_nmap_xml(capture, "synthetic-protocol")
    assert hosts[0].services[0].tls is False
    assert context.detect_controls(hosts[0], [], {})["tls"].value is None


@pytest.mark.parametrize("tls", ["false", "true", 0, 1, None, [], {}])
def test_retained_service_cannot_coerce_untrusted_tls_values_to_a_fact(tls):
    with pytest.raises(ValueError, match="tls"):
        Service.from_json({"port": 443, "protocol": "tcp", "tls": tls})


def test_orchestration_never_launches_nikto_for_ssh_on_port_80(tmp_path, monkeypatch):
    host = Host("172.28.0.10", services=(Service(80, "tcp", name="ssh"),))
    monkeypatch.setattr(orchestrator, "scanner_argv", lambda tool: (f"synthetic-{tool}",))
    monkeypatch.setattr(orchestrator, "parse_nmap_xml", lambda *_: ([host], []))
    monkeypatch.setattr(orchestrator, "parse_nikto_json", lambda *_, **__: [])
    calls = []

    def executor(command):
        calls.append(command.tool)
        Path(command.output).write_text("SYNTHETIC transport output; parser is injected")
        return orchestrator.Execution(0, "2026-10-17T00:00:00Z", "2026-10-17T00:00:01Z")

    plan = orchestrator.plan(SETTINGS, host.ip, tmp_path / "synthetic-output")
    result = orchestrator.orchestrate(plan, "synthetic-protocol", executor)
    assert calls == ["nmap"]
    assert result["endpoints"] == []
    assert result["outcomes"][1]["status"] == "skipped"
    assert "no HTTP service" in result["outcomes"][1]["skip_reason"]
