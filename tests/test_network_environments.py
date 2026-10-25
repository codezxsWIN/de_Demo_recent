import io
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from labs.network_environments import servers, verify
from vulnassess import network_lab_probe
from vulnassess.errors import ScopeError
from vulnassess.settings import Settings


def exercise(protocol, request, protected=False):
    activity = servers.Activity()
    handler = SimpleNamespace(
        connection=SimpleNamespace(settimeout=Mock()),
        rfile=io.BytesIO(request),
        wfile=io.BytesIO(),
        server=SimpleNamespace(
            protocol=protocol,
            protected=protected,
            server_address=(servers.HOST, 1234),
            activity=activity,
        ),
    )
    servers.ProtocolHandler.handle(handler)
    return handler.wfile.getvalue(), activity.snapshot()


@pytest.mark.parametrize(
    "protocol,command",
    [
        ("smtp", b"VRFY training@example.invalid\r\n"),
        ("memcached", b"get fixture:shipment\r\n"),
        ("modbus", bytes.fromhex("000100000006010300000002")),
    ],
)
def test_wire_protocol_conditions_and_access_denied_comparisons(protocol, command):
    for protected in (False, True):
        response, activity = exercise(protocol, command, protected)
        if protocol == "smtp":
            response = response.split(b"\r\n", 1)[1]
        assert verify.observed(protocol, {"response_hex": response.hex()}, protected)
        assert activity["counts"][protocol] == 1
        assert activity["events"][0]["request_hex"] == command.hex()


@pytest.mark.parametrize(
    "protocol,command",
    [
        ("smtp", b"MAIL FROM:<person@example.invalid>\r\n"),
        ("memcached", b"set arbitrary 0 0 4\r\ndata\r\n"),
        ("modbus", bytes.fromhex("000100000006010600000001")),
    ],
)
def test_no_relay_arbitrary_cache_writes_or_register_writes(protocol, command):
    response, _ = exercise(protocol, command)
    assert servers.CACHE_VALUE not in response
    if protocol == "smtp":
        assert b"502 " in response
    elif protocol == "memcached":
        assert response.startswith(b"ERROR")
    else:
        assert response[7:] == b"\x86\x02"


def test_wrong_registry_identity_aborts_before_protocol_connections(monkeypatch):
    context = io.BytesIO(json.dumps({"lab_id": "wrong"}).encode())
    opener = SimpleNamespace(open=lambda *_args, **_kwargs: context)
    monkeypatch.setattr(verify, "build_opener", lambda *_: opener)
    connect = Mock(side_effect=AssertionError("No protocol traffic before identity"))
    monkeypatch.setattr(verify.socket, "create_connection", connect)
    with pytest.raises(ValueError, match="identity mismatch"):
        verify.verify()
    connect.assert_not_called()


def test_adapter_scope_failure_never_probes(tmp_path, monkeypatch):
    monkeypatch.setattr(verify, "verify", Mock(side_effect=AssertionError("Out of scope")))
    scope = SimpleNamespace(contains=lambda _: False, is_canary=lambda _: False)
    endpoint = {"host": "127.0.0.1", "scheme": "http", "port": 8800, "path": "/"}
    with pytest.raises(ScopeError):
        network_lab_probe.run(scope, "127.0.0.1", endpoint, tmp_path)
    assert not network_lab_probe.eligible("192.0.2.1", endpoint)
    assert not network_lab_probe.eligible("127.0.0.1", {**endpoint, "port": 8787})


def test_adapter_preserves_observation_when_comparison_fails(tmp_path, monkeypatch):
    receipt = {
        "lab_id": servers.LAB_ID,
        "target": verify.BASE,
        "checks": [
            {
                "id": "mail",
                "port": 8825,
                "protocol": "smtp",
                "observed": True,
                "control_passed": False,
                "port_evidence": {"response_hex": servers.SMTP_USER.hex()},
                "control_error": "timeout",
            }
        ],
    }
    receipt["checks"].extend(
        [
            {
                "id": key,
                "port": network_lab_probe.METADATA[key][0],
                "protocol": network_lab_probe.METADATA[key][1],
                "observed": False,
                "control_passed": False,
                "port_error": "timeout",
                "control_error": "timeout",
            }
            for key in ("cache", "industrial")
        ]
    )
    monkeypatch.setattr(verify, "verify", lambda: receipt)
    scope = SimpleNamespace(contains=lambda _: True, is_canary=lambda _: False)
    endpoint = {"host": "127.0.0.1", "scheme": "http", "port": 8800, "path": "/"}
    findings, services, coverage = network_lab_probe.run(scope, "127.0.0.1", endpoint, tmp_path)
    assert len(findings) == len(services) == 1
    assert not findings[0].cve_ids
    assert coverage.startswith("partial:")
    assert (tmp_path / "network-environment-checks.json").is_file()
    assert Settings("config").weights["native_fallback"]["network-lab"]["Low"] == 20


def test_activity_is_bounded_and_malformed_modbus_is_refused():
    response, _ = exercise("modbus", bytes.fromhex("00010000ffff01"))
    assert response == b""
    activity = servers.Activity()
    for _ in range(100):
        activity.record("smtp", 8825, b"x", b"y")
    assert len(activity.snapshot()["events"]) == 60
    assert servers.HOST == "127.0.0.1"


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Host": "127.0.0.1:8800", "Origin": "https://other.invalid"},
        {
            "Host": "127.0.0.1:8800",
            "Origin": "http://127.0.0.1:8800",
            "X-VulnAssess-Lab-Action": "verify",
            "Content-Length": "10",
        },
    ],
)
def test_browser_action_rejects_cross_origin_and_arbitrary_payloads(headers):
    handler = SimpleNamespace(path="/verify", headers=headers, send_error=Mock())
    servers.RegistryHandler.do_POST(handler)
    handler.send_error.assert_called_once_with(403)
    assert handler.close_connection
