"""Reject malformed capture/context inputs before they can become trusted facts."""

import json
from pathlib import Path
from unittest.mock import Mock
from xml.etree.ElementTree import Element, SubElement

import pytest

from tests.test_all import SETTINGS
from tests.test_redis_probe import Connection
from vulnassess import redis_probe
from vulnassess.errors import AdapterError, ScopeError
from vulnassess.readers import _input, parse_nmap_xml
from vulnassess.schema import Feature, Finding


@pytest.mark.parametrize(
    "field,value",
    [
        ("confidence", True),
        ("confidence", "1"),
        ("confidence", -0.1),
        ("confidence", 1.1),
        ("confidence", float("nan")),
        ("source", "untrusted"),
        ("evidence", " "),
    ],
)
def test_invalid_context_fact_is_rejected(field, value):
    fields = {
        "value": "web_frontend",
        "confidence": 0.8,
        "source": "rule",
        "evidence": "synthetic banner",
    }
    fields[field] = value
    with pytest.raises(ValueError, match="Feature\\."):
        Feature(**fields)


def test_blank_finding_cannot_enter_canonical_evidence():
    from tests.test_all import make_finding

    data = make_finding().to_json()
    data["evidence"] = " "
    with pytest.raises(ValueError, match="evidence must not be empty"):
        Finding.from_json(data)


def test_capture_read_permission_failure_is_an_adapter_error(tmp_path, monkeypatch):
    path = tmp_path / "synthetic_unreadable.json"
    path.write_text("{}")
    monkeypatch.setattr(Path, "open", Mock(side_effect=PermissionError("synthetic denied")))
    with pytest.raises(AdapterError, match="unreadable") as error:
        _input.read_capture(path, "nikto")
    assert isinstance(error.value.__cause__, PermissionError)


def test_xml_node_budget_rejects_shallow_but_wide_capture(tmp_path, monkeypatch):
    root = Element("nmaprun")
    for _ in range(3):
        SubElement(root, "host")
    monkeypatch.setattr(_input, "MAX_NODES", 3)
    with pytest.raises(AdapterError, match="exceeds 3 elements"):
        _input.validate_tree(root, tmp_path / "synthetic_wide.xml", "nmap")


def test_xml_tree_depth_budget_rejects_deep_tree(tmp_path, monkeypatch):
    root = Element("nmaprun")
    SubElement(SubElement(root, "host"), "ports")
    monkeypatch.setattr(_input, "MAX_DEPTH", 2)
    with pytest.raises(AdapterError, match="exceeds depth 2"):
        _input.validate_tree(root, tmp_path / "synthetic_deep.xml", "nmap")


def test_json_node_budget_rejects_shallow_but_wide_capture(tmp_path, monkeypatch):
    path = tmp_path / "synthetic_wide.json"
    path.write_text("[1,2,3]")
    monkeypatch.setattr(_input, "MAX_NODES", 3)
    with pytest.raises(AdapterError, match="exceeds 3 values"):
        _input.load_json_capture(path, "nikto")


@pytest.mark.parametrize("timestamp", ["invalid", "9999999999999999999999999"])
def test_invalid_nmap_timestamps_preserve_evidence_without_inventing_dates(tmp_path, timestamp):
    path = tmp_path / "synthetic_invalid_time.xml"
    path.write_text(
        f'<nmaprun start="{timestamp}"><host starttime="{timestamp}"><address addr="127.0.0.1" addrtype="ipv4"/><ports><port portid="80"><state state="open"/><script id="synthetic" output="CVE-1999-9001 synthetic evidence"/></port></ports></host></nmaprun>'
    )
    hosts, findings = parse_nmap_xml(path, "synthetic")
    assert hosts[0].ip == "127.0.0.1"
    assert len(findings) == 1
    assert findings[0].first_seen == findings[0].last_seen == ""
    assert findings[0].evidence == "CVE-1999-9001 synthetic evidence"


def test_nmap_host_without_ipv4_is_not_assigned_a_fabricated_target(tmp_path):
    path = tmp_path / "synthetic_no_target.xml"
    path.write_text(
        '<nmaprun><host><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/></host></nmaprun>'
    )
    assert parse_nmap_xml(path, "synthetic") == ([], [])


@pytest.mark.parametrize("port", [0, 65536, True, "6379"])
def test_invalid_redis_ports_never_reach_transport(tmp_path, monkeypatch, port):
    connect = Mock(side_effect=AssertionError("connection forbidden"))
    monkeypatch.setattr(redis_probe.socket, "create_connection", connect)
    with pytest.raises(ScopeError, match="port is invalid"):
        redis_probe.run(SETTINGS.scope, "127.0.0.1", port, tmp_path)
    connect.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_redis_deadline_does_not_publish_partial_evidence(tmp_path, monkeypatch):
    connection = Connection(b"")
    monkeypatch.setattr(
        redis_probe.socket, "create_connection", lambda *_args, **_kwargs: connection
    )
    monkeypatch.setattr(redis_probe.time, "monotonic", Mock(side_effect=[0, 11]))
    with pytest.raises(TimeoutError, match="deadline exceeded"):
        redis_probe.run(SETTINGS.scope, "127.0.0.1", 6379, tmp_path)
    assert connection.sent == [redis_probe.REQUEST]
    assert list(tmp_path.iterdir()) == []


def test_redis_eof_is_recorded_but_does_not_prove_a_vulnerability(tmp_path, monkeypatch):
    connection = Connection(b"$14\r\ntable:")
    monkeypatch.setattr(
        redis_probe.socket, "create_connection", lambda *_args, **_kwargs: connection
    )
    assert redis_probe.run(SETTINGS.scope, "127.0.0.1", 6379, tmp_path) is None
    record = json.loads((tmp_path / "redis-lua-check.json").read_text())
    assert record["response"] == "$14\r\ntable:"
    assert connection.sent == [redis_probe.REQUEST]
