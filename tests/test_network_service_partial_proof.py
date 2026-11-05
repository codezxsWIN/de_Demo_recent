"""Preserve completed protocol evidence without crediting unfinished policy checks."""

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from vulnassess import network_service_checks as checks
from vulnassess.schema import Service
from vulnassess.settings import Scope

IP = "127.0.0.1"


@pytest.fixture
def offline_coroutines(monkeypatch):
    # These async doubles finish immediately; no event-loop sockets are needed.
    def finish(coroutine):
        try:
            coroutine.send(None)
        except StopIteration as completed:
            return completed.value
        finally:
            coroutine.close()
        pytest.fail("A protocol double unexpectedly awaited external IO")

    monkeypatch.setattr(checks.asyncio, "run", finish)


def assess(entry, directory):
    policy = {"target_ip": IP, "policy_sha256": "a" * 64, "endpoints": [entry]}
    discovered = [Service(entry["port"], "tcp")] if entry["transport"] == "tcp" else []
    findings, services, coverage = checks.run(
        Scope({"allowed_hosts": [IP]}, Path("synthetic-scope.yaml")),
        IP,
        policy,
        discovered,
        directory,
    )
    row = json.loads((directory / "network-service-observations.json").read_text())["observations"][
        0
    ]
    return findings, services, coverage, row


@pytest.mark.parametrize("stage", ["suback", "publication", "disconnect"])
def test_mqtt_late_timeout_preserves_authentication_finding(tmp_path, monkeypatch, stage):
    wire = MagicMock()
    monkeypatch.setattr(checks.socket, "create_connection", lambda *a, **kw: wire)
    marker = "owned-nonce"
    topic = b"owner/assessment"
    expected = len(topic).to_bytes(2, "big") + topic + marker.encode()
    packets = [(0x20, b"\x00\x00")]
    if stage != "suback":
        packets.append((0x90, b"\x00\x01\x00"))
    if stage == "disconnect":
        packets.append((0x30, expected))
    else:
        packets.append(TimeoutError("untrusted response must not be persisted"))
    monkeypatch.setattr(checks, "_packet", Mock(side_effect=packets))
    monkeypatch.setattr(checks, "uuid4", lambda: SimpleNamespace(hex=marker))

    def send(_connection, header, _payload):
        if stage == "disconnect" and header == 0xE0:
            raise TimeoutError("untrusted response must not be persisted")

    monkeypatch.setattr(checks, "_send", send)
    findings, services, coverage, row = assess(
        {
            "service": "mqtt",
            "port": 49171,
            "transport": "tcp",
            "require_auth": True,
            "publish_topic": topic.decode(),
        },
        tmp_path,
    )
    proof = row["proof"]
    assert proof["protocol_confirmed"] is proof["anonymous_accepted"] is True
    assert proof["message_exchange_confirmed"] is (stage == "disconnect")
    assert proof["topic"] == topic.decode()
    assert proof["post_connect_error"] == "TimeoutError"
    assert proof["inconclusive"] is True
    assert row["status"] == "inconclusive"
    assert row["violations"] == ["authentication"]
    assert len(findings) == len(services) == 1
    assert json.loads(findings[0].evidence)["observed"] == proof
    assert "untrusted response" not in json.dumps(row)
    assert coverage.startswith("partial:")


def test_mqtt_timeout_before_connack_does_not_invent_acceptance(tmp_path, monkeypatch):
    monkeypatch.setattr(checks.socket, "create_connection", lambda *a, **kw: MagicMock())
    monkeypatch.setattr(checks, "_send", lambda *_: None)
    monkeypatch.setattr(checks, "_packet", Mock(side_effect=TimeoutError()))
    findings, services, coverage, row = assess(
        {"service": "mqtt", "port": 49171, "transport": "tcp", "require_auth": True},
        tmp_path,
    )
    assert findings == services == []
    assert row["status"] == "error" and "proof" not in row
    assert coverage.startswith("partial:")


@pytest.mark.parametrize("methods", [[], ["password"]])
@pytest.mark.parametrize("require_auth", [True, False, None])
def test_ssh_method_discovery_does_not_complete_required_auth_check(
    tmp_path, monkeypatch, offline_coroutines, methods, require_auth
):
    async def advertised(ip, port, **options):
        assert (ip, port) == (IP, 49171)
        assert options["username"] == "assessment"
        return methods

    def connect(*_args, **_kwargs):
        pytest.fail("No designated credential was supplied; no login is authorised")

    monkeypatch.setitem(
        sys.modules,
        "asyncssh",
        SimpleNamespace(get_server_auth_methods=advertised, connect=connect),
    )
    entry = {"service": "ssh", "port": 49171, "transport": "tcp"}
    if require_auth is not None:
        entry["require_auth"] = require_auth
    findings, services, coverage, row = assess(entry, tmp_path)
    proof = row["proof"]
    assert proof["protocol_confirmed"] is True
    assert proof["advertised_auth_methods"] == methods
    assert proof["login_attempted"] is False
    assert "anonymous_accepted" not in proof and "test_credential_accepted" not in proof
    assert findings == [] and len(services) == 1
    if require_auth is True:
        assert proof["inconclusive"] is True
        assert "no designated credential" in proof["authentication_check_error"]
        assert row["status"] == "inconclusive" and coverage.startswith("partial:")
    else:
        assert "inconclusive" not in proof
        assert row["status"] == "observed" and coverage.startswith("complete:")


@pytest.mark.parametrize(
    "value_kind", ["NoSuchObject", "NoSuchInstance", "EndOfMibView", "empty", "value"]
)
def test_snmp_monitoring_needs_a_real_management_value(
    tmp_path, monkeypatch, offline_coroutines, value_kind
):
    exceptions = {
        name: type(name, (), {}) for name in ("NoSuchObject", "NoSuchInstance", "EndOfMibView")
    }
    value = "independently configured device" if value_kind == "value" else None
    if value_kind in exceptions:
        value = exceptions[value_kind]()
    bindings = [] if value_kind == "empty" else [("1.3.6.1.2.1.1.1.0", value)]
    responses = iter([("timeout", 0, 0, []), (None, 0, 0, bindings)])
    communities = []
    engine = SimpleNamespace(close_dispatcher=Mock())

    async def target(*args, **kwargs):
        return object()

    async def get_cmd(_engine, community, *_args):
        communities.append(community)
        return next(responses)

    monkeypatch.setitem(
        sys.modules,
        "pysnmp.hlapi.v3arch.asyncio",
        SimpleNamespace(
            SnmpEngine=lambda: engine,
            UdpTransportTarget=SimpleNamespace(create=target),
            get_cmd=get_cmd,
            CommunityData=lambda community, **_: community,
            ContextData=lambda: None,
            ObjectIdentity=lambda *_: None,
            ObjectType=lambda *_: None,
        ),
    )
    monkeypatch.setitem(sys.modules, "pysnmp.proto.rfc1905", SimpleNamespace(**exceptions))
    findings, services, coverage, row = assess(
        {
            "service": "snmp",
            "port": 49172,
            "transport": "udp",
            "require_auth": True,
            "monitoring_community": "approved-test-only",
        },
        tmp_path,
    )
    assert communities == ["public", "approved-test-only"]
    engine.close_dispatcher.assert_called_once_with()
    assert findings == [] and len(services) == 1
    assert row["proof"]["protocol_confirmed"] is True
    assert "approved-test-only" not in json.dumps(row)
    if value_kind == "value":
        assert row["proof"]["approved_monitoring_read"] is True
        assert row["proof"]["public_community_read"] is None
        assert row["proof"]["inconclusive"] is True
        assert row["proof"]["oid"] == "1.3.6.1.2.1.1.1.0"
        assert row["proof"]["response_length"] == len(value.encode())
        assert row["proof"]["response_sha256"] == hashlib.sha256(value.encode()).hexdigest()
        assert "silence does not establish public-community rejection" in row["proof"]["reason"]
        assert row["status"] == "inconclusive" and coverage.startswith("partial:")
    else:
        assert row["proof"]["inconclusive"] is True
        assert "approved_monitoring_read" not in row["proof"]
        assert "public_community_read" not in row["proof"]
        assert row["status"] == "inconclusive" and coverage.startswith("partial:")
