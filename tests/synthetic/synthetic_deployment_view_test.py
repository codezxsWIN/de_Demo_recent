"""Synthetic receipt integrity/display cases, not proof of Docker isolation."""

import copy
import json

import pytest

from tests.test_assessment_report import setup_report
from vulnassess import capture_history
from vulnassess import service_network_deployment as deployment
from vulnassess.errors import ConfigError


def synthetic_receipt():
    value = {
        "schema_version": 1,
        "project": "vulnassess-service-networks",
        "status": "passed",
        "verified_at": "2026-10-26T10:00:00+00:00",
        "containers": {},
        "gateways": {},
        "client_controls": [],
    }
    for index, name in enumerate(("office", "iot")):
        ip, loopback, port = (
            ("172.30.41.2", "127.0.0.2", 2121)
            if name == "office"
            else ("172.30.42.2", "127.0.0.3", 1883)
        )
        peer, peer_port = ("172.30.42.2", 1883) if name == "office" else ("172.30.41.2", 2121)
        value["containers"][name] = {
            "id": str(index + 1) * 64,
            "private_ip": ip,
            "health": "healthy",
            "read_only_rootfs": True,
            "published_ports": {},
            "runtime": {"network_namespace": 100 + index},
        }
        value["gateways"][name] = {
            "id": str(index + 3) * 64,
            "ip_forward": False,
            "published_ports": {f"{port}/tcp": [{"HostIp": loopback, "HostPort": str(port)}]},
            "runtime": {"network_namespace": 200 + index},
        }
        row = {
            "client_segment": name,
            "positive_control": {"target": ip, "port": port, "protocol_exchange_succeeded": True},
            "cross_segment_control": {"target": peer, "port": peer_port, "tcp_connected": False},
        }
        if name == "iot":
            row["udp_gateway_controls"] = {
                "public_get_returned_value": True,
                "protected_public_get_returned_value": False,
                "protected_authorised_get_returned_value": True,
            }
        value["client_controls"].append(row)
    value["receipt_hash"] = deployment.digest(value)
    return value


def test_dated_deployment_is_separate_from_a_selected_capture_and_never_a_live_claim(tmp_path):
    app, directory = setup_report(tmp_path, ai=False)
    root = app.config_dir.parent / "data/service-networks"
    root.mkdir(parents=True)
    path = root / "container-verification-synthetic.json"
    value = synthetic_receipt()
    path.write_text(json.dumps(value))
    before = copy.deepcopy(value)
    loaded = deployment.load_latest(root)
    assert loaded["filename"] == path.name
    response = app.get(f"/environment?capture={directory.name}")
    assert response.status == 200
    html = response.body.decode()
    assert "Network labs · last verified deployment" in html
    assert "not live status" in html and "selected scan observed the whole topology" in html
    assert "172.30.41.2" in html and "172.30.42.2" in html
    assert "public-community management read succeeded" in html
    assert value == before
    record = capture_history.load(directory.parent, directory.name)
    assert "container" not in record["payload"]


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(status="failed"),
        lambda d: d.update(schema_version=True),
        lambda d: d.update(project="unrelated-project"),
        lambda d: d.update(verified_at="not-a-date"),
        lambda d: d.update(verified_at="2026-10-26T10:00:00"),
        lambda d: d["containers"]["office"].update(private_ip="192.0.2.1"),
        lambda d: d["containers"]["office"]["runtime"].update(network_namespace=True),
        lambda d: d["gateways"]["office"]["runtime"].update(network_namespace=100),
        lambda d: d["gateways"]["office"].update(ip_forward=True),
        lambda d: d["gateways"]["office"]["published_ports"]["2121/tcp"][0].update(
            HostIp="0.0.0.0"
        ),
        lambda d: d["client_controls"][0]["positive_control"].update(
            protocol_exchange_succeeded=False
        ),
        lambda d: d["client_controls"][0]["cross_segment_control"].update(tcp_connected=True),
        lambda d: d["client_controls"][0]["positive_control"].update(target="192.0.2.1"),
        lambda d: d["client_controls"][1]["udp_gateway_controls"].update(
            public_get_returned_value=False
        ),
        lambda d: d["client_controls"][1]["udp_gateway_controls"].update(
            protected_public_get_returned_value=True
        ),
    ],
)
def test_contradictory_receipt_is_rejected_even_after_rehash(change):
    value = synthetic_receipt()
    change(value)
    value["receipt_hash"] = deployment.digest(value)
    with pytest.raises(ConfigError):
        deployment.validate(value)


def test_tamper_missing_oversize_and_duplicate_keys_do_not_display_a_success(tmp_path):
    assert deployment.load_latest(tmp_path) is None
    path = tmp_path / "container-verification-synthetic.json"
    value = synthetic_receipt()
    value["verified_at"] = "2025-01-01T00:00:00+00:00"
    path.write_text(json.dumps(value))
    with pytest.raises(ConfigError):
        deployment.load_latest(tmp_path)
    value = synthetic_receipt()
    path.write_text(
        json.dumps(value).replace('"status": "passed"', '"status": "failed", "status": "passed"')
    )
    with pytest.raises(ConfigError):
        deployment.load_latest(tmp_path)
    path.write_text("x" * 262145)
    with pytest.raises(ConfigError):
        deployment.load_latest(tmp_path)
    path.write_text("{")
    with pytest.raises(ConfigError):
        deployment.load_latest(tmp_path)


def test_corrupt_optional_deployment_does_not_break_verified_scan_page(tmp_path):
    app, directory = setup_report(tmp_path, ai=False)
    root = app.config_dir.parent / "data/service-networks"
    root.mkdir(parents=True)
    (root / "container-verification-synthetic.json").write_text("{}")
    response = app.get(f"/environment?capture={directory.name}")
    assert response.status == 200
    assert b"Container verification could not be checked" in response.body
    assert b"Observed hosts and services" in response.body
    assert b"Network labs" not in response.body
