"""Offline packet fixtures and Docker-boundary tests; no network traffic generated."""

import builtins
import copy
import hashlib
import io
import json
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from labs.service_networks import traffic_capture as capture
from vulnassess import lab_traffic as traffic


def test_runtime_source_receipt_binds_only_the_inspected_backend(monkeypatch, tmp_path):
    from vulnassess.lab_traffic import PROJECT, TrafficMonitor

    monitor = TrafficMonitor(tmp_path)
    node = {
        "service": "office",
        "id": "a" * 64,
        "running": True,
        "project": PROJECT,
        "ips": ["172.30.41.2"],
    }
    monkeypatch.setattr(monitor, "refresh", lambda *_: None)
    monkeypatch.setattr(monitor, "_topology", lambda: {"nodes": [node]})
    calls = []

    def download(identity, kind):
        calls.append((identity, kind))
        return b"independently deployed source"

    monkeypatch.setattr(monitor, "_download", download)
    receipt = monitor.source_receipt("office")
    assert receipt["available"]
    assert receipt["source_sha256"] == hashlib.sha256(b"independently deployed source").hexdigest()
    assert calls == [("a" * 64, "office_source")]
    node["ips"] = ["172.30.42.2"]
    assert not monitor.source_receipt("office")["available"]
    assert len(calls) == 1
    with pytest.raises(ValueError):
        monitor.source_receipt("external")


def frame(
    *,
    source="172.30.41.5",
    destination="172.30.41.3",
    source_port=45000,
    destination_port=2121,
    transport="tcp",
    payload=b"fixture\x00bytes",
    flags=0x18,
):
    if transport == "tcp":
        segment = (
            struct.pack("!HHIIBBHHH", source_port, destination_port, 1, 1, 0x50, flags, 4096, 0, 0)
            + payload
        )
        protocol = 6
    else:
        segment = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
        protocol = 17
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(segment),
        1,
        0x4000,
        64,
        protocol,
        0,
        socket.inet_aton(source),
        socket.inet_aton(destination),
    )
    return b"\x01" * 12 + b"\x08\x00" + header + segment


def document(tmp_path, environment="office", packets=None):
    observer = capture.Capture(environment, tmp_path / environment)
    observer._reset(time.time() - 3)
    observer.running = True
    for packet in packets if packets is not None else [frame()]:
        assert observer.accept(packet, time.time() - 1)
    observer.publish()
    return json.loads((observer.directory / "status.json").read_bytes()), bytes(observer.data)


def archive(name, content, kind=tarfile.REGTYPE, extra=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as bundle:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = "../../secret"
        member.size = len(content) if kind == tarfile.REGTYPE else 0
        bundle.addfile(member, io.BytesIO(content))
        if extra:
            bundle.addfile(tarfile.TarInfo("unexpected"))
    return output.getvalue()


def docker_nodes():
    nodes = []
    for index, environment in enumerate(("office", "iot")):
        base, ingress = (
            ("172.30.41", "172.30.43") if environment == "office" else ("172.30.42", "172.30.44")
        )
        gateway_id = f"{index * 10 + 1:064x}"
        project_network = traffic.PROJECT + "_" + environment
        for offset, service, mode in (
            (1, environment + "-gateway", project_network),
            (2, environment + "-capture", "container:" + gateway_id),
            (3, environment, project_network),
            (4, environment + "-redis", project_network),
            (5, environment + "-client", project_network),
        ):
            networks = (
                {}
                if offset == 2
                else {
                    traffic.PROJECT + "_" + environment: {
                        "IPAddress": base
                        + (
                            ".3"
                            if offset == 1
                            else ".2"
                            if offset == 3
                            else ".4"
                            if offset == 4
                            else ".5"
                        ),
                        "NetworkID": f"{index * 10 + 5:064x}",
                    }
                }
            )
            if offset == 1:
                networks[traffic.PROJECT + "_" + environment + "-ingress"] = {
                    "IPAddress": ingress + ".2",
                    "NetworkID": f"{index * 10 + 6:064x}",
                }
            nodes.append(
                {
                    "Id": f"{index * 10 + offset:064x}",
                    "Name": "/actual-" + service,
                    "Config": {
                        "Labels": {
                            "com.docker.compose.project": traffic.PROJECT,
                            "com.docker.compose.service": service,
                        }
                    },
                    "State": {
                        "Running": True,
                        "Status": "running",
                        "Health": {"Status": "healthy"},
                    },
                    "HostConfig": {
                        "NetworkMode": mode,
                        "CapAdd": ["NET_RAW"] if offset == 2 else [],
                        "CapDrop": ["ALL"],
                        "Privileged": False,
                        "PidMode": "",
                    },
                    "NetworkSettings": {"Networks": networks},
                }
            )
    return nodes


@pytest.fixture
def backend(monkeypatch, tmp_path):
    status, pcap = document(tmp_path)
    nodes = docker_nodes()
    calls = []
    monitor = traffic.TrafficMonitor(tmp_path)
    files = {"status.json": json.dumps(status).encode(), "capture.pcap": pcap}

    def docker(arguments, limit):
        calls.append(arguments)
        if arguments[0] == "ps":
            return "\n".join(row["Id"] for row in nodes).encode()
        if arguments[0] == "inspect":
            assert arguments[1:] == [row["Id"] for row in nodes]
            return json.dumps(nodes).encode()
        if arguments[0] == "cp":
            assert arguments[1].split(":")[0] == nodes[1]["Id"]
            assert arguments[2] == "-"
            name = arguments[1].split("/")[-1]
            return archive(name, files[name])
        pytest.fail("Unexpected Docker command")

    monkeypatch.setattr(monitor, "_docker", docker)
    return monitor, nodes, files, calls, status


def test_tcp_parser_decodes_only_observed_headers_and_bounded_payload():
    packet = capture.decode_packet(
        frame(payload=b"x" * 200, flags=0x12), "office", 1_700_000_000.25
    )
    assert packet["source_ip"] == "172.30.41.5" and packet["destination_port"] == 2121
    assert packet["tcp_flags"] == ["SYN", "ACK"] and packet["transport"] == "tcp"
    assert packet["protocol"] == "FTP" and "not validated" in packet["protocol_basis"]
    assert packet["timestamp"] == "2023-11-14T22:13:20.250000+00:00"
    assert len(packet["payload_hex"]) == 192 and len(packet["payload_summary"]) == 96
    assert packet["payload_truncated"] and packet["payload_length"] == 200
    assert packet["evidence_kind"] == "captured_packet"


def test_reverse_flow_identity_is_stable():
    request = capture.decode_packet(frame(), "office")
    response = capture.decode_packet(
        frame(
            source="172.30.41.3",
            destination="172.30.41.5",
            source_port=2121,
            destination_port=45000,
        ),
        "office",
    )
    assert capture.flow_id("office", request) == capture.flow_id("office", response)
    assert request["payload_summary"] == "fixture.bytes"


@pytest.mark.parametrize("port", [1161, 1162])
def test_udp_snmp_scope_and_ingress(port):
    packet = capture.decode_packet(
        frame(
            source="172.30.44.3", destination="172.30.44.2", destination_port=port, transport="udp"
        ),
        "iot",
    )
    assert packet["network"] == "iot-ingress" and packet["protocol"] == "SNMP"
    assert packet["tcp_flags"] == []


@pytest.mark.parametrize(
    "environment,port",
    [("office", port) for port in sorted(capture.SCOPE["office"]["tcp"])]
    + [("iot", port) for port in sorted(capture.SCOPE["iot"]["tcp"])],
)
def test_every_declared_tcp_service_port(environment, port):
    base = "172.30.41" if environment == "office" else "172.30.42"
    assert capture.decode_packet(
        frame(source=base + ".5", destination=base + ".3", destination_port=port), environment
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"source": "192.0.2.1"},
        {"destination": "127.0.0.2"},
        {"source": "172.30.42.3"},
        {"source": "172.30.41.0"},
        {"source": "172.30.41.7"},
        {"destination_port": 22},
        {"destination_port": 1883},
        {"destination_port": 2121, "transport": "udp"},
        {"destination_port": 1161},
    ],
)
def test_parser_rejects_cross_environment_external_and_wrong_transport_ports(changes):
    assert capture.decode_packet(frame(**changes), "office") is None


def test_all_truncated_frames_and_malformed_header_lengths_fail_closed():
    wire = frame()
    for length in range(len(wire)):
        assert capture.decode_packet(wire[:length], "office") is None
    for offset, replacement in (
        (12, b"\x86\xdd"),
        (14, b"\x65"),
        (14, b"\x44"),
        (20, b"\x20\x00"),
        (20, b"\x00\x01"),
        (20, b"\x80\x00"),
        (23, b"\x01"),
        (46, b"\x40"),
        (46, b"\xf0"),
    ):
        bad = bytearray(wire)
        bad[offset : offset + len(replacement)] = replacement
        assert capture.decode_packet(bytes(bad), "office") is None


def test_vlan_and_udp_length_validation():
    wire = frame()
    tagged = wire[:12] + b"\x81\x00\x00\x01" + wire[12:]
    assert capture.decode_packet(tagged, "office")["destination_port"] == 2121
    udp = bytearray(
        frame(
            source="172.30.42.5", destination="172.30.42.3", destination_port=1161, transport="udp"
        )
    )
    udp[38:40] = b"\x00\x07"
    assert capture.decode_packet(bytes(udp), "iot") is None


def test_worker_ring_counts_and_atomic_publication(tmp_path):
    observer = capture.Capture("office", tmp_path)
    observer.running = True
    for _ in range(405):
        assert observer.accept(frame())
    assert not observer.accept(frame(destination_port=80))
    observer.publish()
    status = traffic.validate_status((tmp_path / "status.json").read_bytes(), "office")
    assert status["captured_packets"] == status["parsed_packets"] == status["pcap_packets"] == 405
    assert len(status["packets"]) == 400 and status["packets"][0]["packet_id"].endswith(":6")
    assert status["flows"][0]["packets"] == 400
    assert traffic.validate_pcap((tmp_path / "capture.pcap").read_bytes(), "office") == 405
    assert not list(tmp_path.glob("*.tmp"))


def test_four_mib_rotation_is_a_new_valid_session(tmp_path):
    observer = capture.Capture("office", tmp_path)
    identity = observer.session_id
    large = frame(payload=b"x" * 64000)
    for _ in range(70):
        assert observer.accept(large)
    assert observer.session_id != identity and observer.rotations == 1
    assert len(observer.data) <= 4 * 1024 * 1024
    assert observer.captured_packets == traffic.validate_pcap(bytes(observer.data), "office")
    assert observer.packets[0]["packet_id"] == observer.session_id + ":1"
    observer.publish()
    assert traffic.validate_status((tmp_path / "status.json").read_bytes(), "office")


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"{}",
        b"\xff",
        b"[]",
        b"null",
        b"{",
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b" " * (traffic.MAX_STATUS_BYTES + 1),
    ],
    ids=[
        "empty",
        "empty-object",
        "encoding",
        "array",
        "null",
        "truncated",
        "duplicate",
        "nonfinite",
        "oversized",
    ],
)
def test_malformed_json_is_rejected(bad):
    with pytest.raises(ValueError):
        traffic.validate_status(bad, "office")


@pytest.mark.parametrize(
    "key,value",
    [
        ("captured_packets", True),
        ("captured_packets", -1),
        ("captured_packets", 99),
        ("pcap_bytes", 4 * 1024 * 1024 + 1),
        ("schema_version", True),
        ("session_id", "../../path"),
        ("running", "yes"),
        ("parsed_packets", 0),
        ("started_at", "2026-01-01"),
        ("project", "harbordesk"),
        ("environment", "iot"),
        ("packets", [{}] * 401),
        ("pcap_sha256", "bad"),
    ],
)
def test_status_rejects_malformed_counts_identity_and_bounds(tmp_path, key, value):
    status, _ = document(tmp_path)
    status[key] = value
    with pytest.raises(ValueError):
        traffic.validate_status(json.dumps(status).encode(), "office")


@pytest.mark.parametrize(
    "key,value",
    [
        ("destination_ip", "192.0.2.1"),
        ("destination_ip", "172.30.42.3"),
        ("network", "iot"),
        ("destination_port", 22),
        ("source_port", True),
        ("tcp_flags", ["INFERRED"]),
        ("payload_hex", "ff" * 97),
        ("payload_summary", "invented assertion"),
        ("packet_id", "other:1"),
        ("flow_id", "generated"),
        ("length", -1),
        ("timestamp", "2020-01-01T00:00:00Z"),
    ],
)
def test_status_revalidates_each_packet_scope_and_payload(tmp_path, key, value):
    status, _ = document(tmp_path)
    status["packets"][0][key] = value
    with pytest.raises(ValueError):
        traffic.validate_status(json.dumps(status).encode(), "office")


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not a capture",
        capture.PCAP_HEADER[:-1],
        capture.PCAP_HEADER + b"x",
        capture.PCAP_HEADER + struct.pack("<IIII", 1, 1_000_000, 54, 54) + b"x" * 54,
        capture.PCAP_HEADER + struct.pack("<IIII", 1, 0, 54, 54) + b"x" * 3,
        capture.PCAP_HEADER + struct.pack("<IIII", 1, 0, 54, 100) + b"x" * 54,
        capture.PCAP_HEADER + b"x" * (4 * 1024 * 1024),
    ],
    ids=[
        "empty",
        "text",
        "short-header",
        "short-record",
        "bad-time",
        "truncated",
        "length",
        "oversized",
    ],
)
def test_malformed_or_unbounded_pcap_is_rejected(data):
    with pytest.raises(ValueError):
        traffic.validate_pcap(data, "office")


def test_valid_empty_and_big_endian_pcap_and_scope_validation(tmp_path):
    assert traffic.validate_pcap(capture.PCAP_HEADER, "office") == 0
    wire = frame()
    big = struct.pack(">IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    big += struct.pack(">IIII", 1_700_000_000, 1, len(wire), len(wire)) + wire
    assert traffic.validate_pcap(big, "office") == 1
    with pytest.raises(ValueError, match="scope"):
        traffic.validate_pcap(big, "iot")


def test_snapshot_pcap_topology_report_inspected_data_and_real_counts(backend):
    monitor, nodes, files, calls, _ = backend
    snapshot = monitor.snapshot("office")
    assert snapshot["available"] and snapshot["error"] is None
    assert snapshot["captured_packets"] == 1 and len(snapshot["packets"]) == 1
    assert monitor.pcap("office") == files["capture.pcap"]
    topology = monitor.topology()
    assert len(topology["nodes"]) == len(nodes)
    gateway = next(node for node in topology["nodes"] if node["service"] == "office-gateway")
    assert gateway["name"] == "actual-office-gateway" and gateway["id"] == nodes[0]["Id"]
    assert gateway["ips"] == ["172.30.41.3", "172.30.43.2"]
    assert (
        gateway["state"] == "running"
        and gateway["health"] == "healthy"
        and gateway["role"] == "gateway"
    )
    assert gateway["environment"] == "office" and gateway["client_status"] is None
    assert all(call[0] in ("ps", "inspect", "cp") for call in calls)
    assert "exec" not in [call[0] for call in calls]


def test_wrong_project_label_is_rejected_even_if_ps_filter_and_name_match(backend):
    monitor, nodes, _, calls, _ = backend
    nodes[1]["Config"]["Labels"]["com.docker.compose.project"] = "harbordesk"
    result = monitor.snapshot("office")
    assert not result["available"] and "wrong Compose project" in result["error"]
    assert result["captured_packets"] is None and result["packets"] == []
    assert not any(call[0] == "cp" for call in calls)


@pytest.mark.parametrize(
    "which,key,value",
    [
        (1, "NetworkMode", "host"),
        (1, "NetworkMode", "container:" + "a" * 64),
        (1, "NetworkMode", "container:" + f"{3:064x}"),
        (1, "CapAdd", ["NET_RAW", "NET_ADMIN"]),
        (1, "CapAdd", []),
        (1, "CapDrop", []),
        (1, "Privileged", True),
        (1, "PidMode", "host"),
        (0, "NetworkMode", "host"),
    ],
)
def test_unsafe_or_backend_namespace_observer_cannot_read_files(backend, which, key, value):
    monitor, nodes, _, calls, _ = backend
    nodes[which]["HostConfig"][key] = value
    assert not monitor.snapshot("office")["available"]
    assert not any(call[0] == "cp" for call in calls)


def test_changed_gateway_network_and_stopped_capture_are_explicit(backend):
    monitor, nodes, _, _, _ = backend
    nodes[0]["NetworkSettings"]["Networks"][traffic.PROJECT + "_office"]["IPAddress"] = (
        "172.30.42.3"
    )
    assert "scope" in monitor.snapshot("office")["error"]
    monitor.refresh()
    nodes[0]["NetworkSettings"]["Networks"][traffic.PROJECT + "_office"]["IPAddress"] = (
        "172.30.41.3"
    )
    nodes[1]["State"]["Running"] = False
    result = monitor.snapshot("office")
    assert not result["available"] and "stopped" in result["error"]


def test_stale_heartbeat_exposes_historical_packets_and_refuses_download(backend):
    monitor, _, files, _, status = backend
    old = datetime.now(UTC) - timedelta(seconds=40)
    status["started_at"] = (old - timedelta(seconds=5)).isoformat()
    status["updated_at"] = old.isoformat()
    status["packets"][0]["timestamp"] = (old - timedelta(seconds=1)).isoformat()
    packet_time = old - timedelta(seconds=1)
    status["packets"][0]["timestamp_ns"] = (
        int(packet_time.timestamp()) * 1_000_000_000 + packet_time.microsecond * 1000
    )
    status["packets"][0]["processed_at"] = old.isoformat()
    files["status.json"] = json.dumps(status).encode()
    result = monitor.snapshot("office")
    assert not result["available"] and result["stale"] and "historical" in result["error"]
    assert result["captured_packets"] == 1
    with pytest.raises(ValueError, match="stale"):
        monitor.pcap("office")


def test_stopped_capture_status_and_malformed_status_never_claim_available(backend):
    monitor, _, files, _, status = backend
    status["running"] = False
    files["status.json"] = json.dumps(status).encode()
    assert "stopped" in monitor.snapshot("office")["error"]
    monitor.refresh()
    files["status.json"] = b'{"schema_version":1,"schema_version":1}'
    result = monitor.snapshot("office")
    assert not result["available"] and result["captured_packets"] is None


def test_cache_is_bounded_refreshable_and_returns_defensive_copies(backend):
    monitor, _, _, calls, _ = backend
    first = monitor.snapshot("office")
    before = len(calls)
    first["packets"].clear()
    assert len(monitor.snapshot("office")["packets"]) == 1 and len(calls) == before
    monitor.snapshot("office", force=True)
    assert len(calls) == before + 1
    monitor.refresh("office")
    monitor.snapshot("office")
    assert len(calls) > before + 1


@pytest.mark.parametrize(
    "environment",
    [
        "../office",
        "office/capture.pcap",
        "office?path=x",
        "office;whoami",
        "harbordesk",
        "OFFICE",
        None,
        [],
        True,
    ],
)
def test_environment_and_download_paths_cannot_expand_scope(backend, environment):
    monitor, _, _, calls, _ = backend
    for method in (monitor.snapshot, monitor.pcap):
        with pytest.raises(ValueError):
            method(environment)
    with pytest.raises(ValueError):
        monitor.correlate(environment, 2121, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z")
    assert calls == []


@pytest.mark.parametrize(
    "name,kind,extra",
    [
        ("../../secret", tarfile.REGTYPE, False),
        ("/capture/status.json", tarfile.REGTYPE, False),
        ("status.json", tarfile.SYMTYPE, False),
        ("status.json", tarfile.LNKTYPE, False),
        ("status.json", tarfile.DIRTYPE, False),
        ("status.json", tarfile.REGTYPE, True),
    ],
)
def test_unsafe_tar_download_members_are_rejected(monkeypatch, tmp_path, name, kind, extra):
    monitor = traffic.TrafficMonitor(tmp_path)
    monkeypatch.setattr(monitor, "_docker", lambda *_: archive(name, b"{}", kind, extra))
    with pytest.raises(ValueError):
        monitor._copy("a" * 64, "status.json")


def test_direct_copy_accepts_no_arbitrary_container_or_filename(backend):
    monitor, _, _, calls, _ = backend
    for identity, name in (
        ("--privileged", "status.json"),
        ("a" * 64, "../secret"),
        ("a" * 64, "/etc/passwd"),
    ):
        with pytest.raises(ValueError):
            monitor._copy(identity, name)
    assert calls == []


def test_pcap_download_accepts_an_independent_atomic_generation(backend):
    monitor, _, files, _, _ = backend
    # Rotation may publish a valid fresh empty file after the status was read.
    # Byte downloads do not claim to be an atomic bundle with that old status.
    files["capture.pcap"] = capture.PCAP_HEADER
    assert monitor.pcap("office") == capture.PCAP_HEADER


def test_pcap_download_still_rejects_out_of_scope_new_generation(backend):
    monitor, _, files, _, _ = backend
    wire = frame(destination="192.0.2.10")
    files["capture.pcap"] = (
        capture.PCAP_HEADER + struct.pack("<IIII", 1, 0, len(wire), len(wire)) + wire
    )
    with pytest.raises(ValueError, match="scope"):
        monitor.pcap("office")


def test_correlation_filters_time_endpoint_port_and_both_directions(backend, tmp_path):
    monitor, _, files, _, _ = backend
    packets = [
        frame(),
        frame(
            source="172.30.41.3",
            destination="172.30.41.5",
            source_port=2121,
            destination_port=45000,
        ),
        frame(destination_port=2222),
        frame(destination="172.30.41.6"),
    ]
    status, pcap = document(tmp_path / "correlate", packets=packets)
    files.update({"status.json": json.dumps(status).encode(), "capture.pcap": pcap})
    result = monitor.correlate("office", 2121, status["started_at"], status["updated_at"])
    assert result["available"] and len(result["packet_ids"]) == 2
    assert result["matched_packets"] == 2 and result["captured_packets"] == 4
    assert result["method"] == "endpoint_and_time_window"
    assert result["correlation_only"] and result["causal_validation"] is False
    assert result["window_published"]
    empty = monitor.correlate("office", 6379, status["started_at"], status["updated_at"])
    assert empty["packet_ids"] == [] and empty["captured_packets"] == 4


def test_correlation_waits_for_publication_ignoring_cached_snapshot(backend, monkeypatch):
    monitor, _, _, _, _ = backend
    old = monitor.snapshot("office")
    finish = datetime.now(UTC)
    before = copy.deepcopy(old)
    before["updated_at"] = (finish - timedelta(seconds=1)).isoformat()
    after = copy.deepcopy(old)
    after["updated_at"] = (finish + timedelta(milliseconds=1)).isoformat()
    replies = iter((before, after))
    forces = []

    def snapshot(environment, force=False):
        forces.append(force)
        return next(replies)

    monkeypatch.setattr(monitor, "snapshot", snapshot)
    result = monitor.correlate("office", 2121, old["started_at"], finish.isoformat())
    assert result["window_published"] and forces == [False, True]


@pytest.mark.parametrize("port", [22, "2121", True, 1161, -1, 65536])
def test_correlation_port_scope_never_dispatches(backend, port):
    monitor, _, _, calls, _ = backend
    with pytest.raises(ValueError):
        monitor.correlate("office", port, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z")
    assert calls == []


def test_correlation_rejects_naive_or_reversed_times_and_unavailable_counts(backend):
    monitor, nodes, _, _, _ = backend
    for start, finish in (
        ("2026-01-01", "2026-01-02"),
        ("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z"),
    ):
        with pytest.raises(ValueError):
            monitor.correlate("office", 2121, start, finish)
    nodes[1]["State"]["Running"] = False
    result = monitor.correlate("office", 2121, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    assert (
        not result["available"]
        and result["captured_packets"] is None
        and result["packet_ids"] == []
    )


def test_docker_command_is_shell_free_bounded_and_has_a_kill_deadline(monkeypatch, tmp_path):
    seen = []

    class Process:
        def __init__(self, argv, **kwargs):
            seen.append((argv, kwargs))
            self.stdout = io.BytesIO(b"x" * 20)
            self.killed = False

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def kill(self):
            self.killed = True

        def wait(self, timeout):
            assert timeout == traffic.DOCKER_TIMEOUT
            return 0

    monkeypatch.setattr(subprocess, "Popen", Process)
    monitor = traffic.TrafficMonitor(tmp_path)
    assert monitor._docker(["ps"], 30) == b"x" * 20
    with pytest.raises(ValueError, match="bounded"):
        monitor._docker(["ps"], 10)
    assert seen[0][0] == ["docker", "ps"]
    assert seen[0][1]["shell"] is False and seen[0][1]["stdin"] == subprocess.DEVNULL


def test_missing_docker_and_empty_project_are_unavailable(monkeypatch, tmp_path):
    monitor = traffic.TrafficMonitor(tmp_path)

    def absent(*_, **__):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(subprocess, "Popen", absent)
    result = monitor.snapshot("office")
    assert not result["available"] and "unavailable" in result["error"]
    monitor.refresh()
    monkeypatch.setattr(monitor, "_docker", lambda *_: b"")
    assert monitor.topology()["nodes"] == []
    assert monitor.snapshot("office")["captured_packets"] is None


def test_worker_opens_only_receive_raw_socket_and_publishes_stop(monkeypatch, tmp_path):
    observer = capture.Capture("office", tmp_path)
    handlers, opened = {}, []

    class Wire:
        reads = 0

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def settimeout(self, seconds):
            assert seconds == 0.25

        def setsockopt(self, level, option, value):
            assert level == socket.SOL_SOCKET and option in (35, 64) and value == 1

        def recvmsg(self, size, control_bytes):
            assert size == capture.SNAPLEN + 1
            assert control_bytes >= 32
            self.reads += 1
            if self.reads == 1:
                seconds, nanos = divmod(time.time_ns(), 1_000_000_000)
                return (
                    frame(),
                    [
                        (
                            socket.SOL_SOCKET,
                            getattr(socket, "SO_TIMESTAMPNS", 35),
                            capture.TIMESPEC.pack(seconds, nanos),
                        )
                    ],
                    0,
                    (),
                )
            handlers[capture.signal.SIGTERM]()
            raise socket.timeout()

    def raw(*arguments):
        opened.append(arguments)
        return Wire()

    monkeypatch.setattr(capture, "Capture", lambda _: observer)
    monkeypatch.setattr(capture, "Path", lambda _: SimpleNamespace(is_file=lambda: True))
    monkeypatch.setattr(capture, "validate_gateway_interfaces", lambda _: None)
    monkeypatch.setattr(capture.sys, "platform", "linux")
    monkeypatch.setattr(capture.platform, "machine", lambda: "x86_64")
    monkeypatch.setenv("VULNASSESS_CONTAINER_LAB", "1")
    monkeypatch.setattr(
        capture.signal, "signal", lambda sig, handler: handlers.update({sig: handler})
    )
    monkeypatch.setattr(capture.socket, "AF_PACKET", 17, raising=False)
    monkeypatch.setattr(capture.socket, "socket", raw)
    assert capture.run("office") == 0
    assert opened == [(17, socket.SOCK_RAW, socket.htons(0x0003))]
    status = traffic.validate_status((tmp_path / "status.json").read_bytes(), "office")
    assert not status["running"] and status["captured_packets"] == 1
    assert status["packets"][0]["timestamp_basis"] == capture.KERNEL_TIMESTAMP
    assert status["timestamp_fallback_packets"] == 0


def test_gateway_interface_guard_refuses_backend_or_extra_network(monkeypatch):
    addresses = ["172.30.41.3", "172.30.43.2"]

    class Control:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def fileno(self):
            return 1

    def ioctl(_, operation, name):
        assert operation == 0x8915
        index = int(name.split(b"\x00")[0][-1:])
        return b"\x00" * 20 + socket.inet_aton(addresses[index])

    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(ioctl=ioctl))
    monkeypatch.setattr(capture.socket, "socket", lambda *_: Control())
    monkeypatch.setattr(
        capture.socket, "if_nameindex", lambda: [(0, "lo"), (1, "eth0"), (2, "eth1")]
    )
    capture.validate_gateway_interfaces("office")
    addresses[0] = "172.30.41.2"
    with pytest.raises(RuntimeError, match="gateway"):
        capture.validate_gateway_interfaces("office")
    addresses[0] = "192.0.2.1"
    with pytest.raises(RuntimeError):
        capture.validate_gateway_interfaces("office")


def test_status_rejects_byte_count_contradictions_and_discards_unvalidated_fields(tmp_path):
    status, _ = document(tmp_path)
    status["packets"][0]["protocol_basis"] = "invented claim"
    status["packets"][0]["asserted_vulnerability"] = "invented claim"
    result = traffic.validate_status(json.dumps(status).encode(), "office")
    assert "asserted_vulnerability" not in result["packets"][0]
    assert "not validated" in result["packets"][0]["protocol_basis"]
    status["pcap_bytes"] += 1
    with pytest.raises(ValueError, match="byte count"):
        traffic.validate_status(json.dumps(status).encode(), "office")


def test_correlation_read_deadline_prevents_new_process(monkeypatch, tmp_path):
    monitor = traffic.TrafficMonitor(tmp_path)
    monitor._timeouts.deadline = time.monotonic() - 1

    def forbidden(*_, **__):
        pytest.fail("Expired publication polling must not start Docker")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises(ValueError, match="deadline"):
        monitor._docker(["ps"], 30)


def client_receipt(service, identity):
    source, destination, port, protocol, operation = {
        "office-workstation": (
            "172.30.41.5",
            "172.30.41.3",
            2121,
            "ftp",
            "FTP RETR network-proof.txt",
        ),
        "iot-sensor": ("172.30.42.5", "172.30.42.3", 1883, "mqtt", "MQTT PUBLISH"),
        "iot-dashboard": ("172.30.42.6", "172.30.42.3", 1883, "mqtt", "MQTT SUBSCRIBE / receive"),
    }[service]
    now = datetime.now(UTC)
    return {
        "role": service,
        "container_id": identity[:12],
        "container_hostname": identity[:12],
        "source_address": source,
        "observed_source_address": source,
        "destination": {"address": destination, "port": port, "protocol": protocol},
        "operation": operation,
        "state": "running",
        "operation_count": 3,
        "last_success": (now - timedelta(seconds=1)).isoformat(),
        "last_failure": None,
        "last_error": None,
        "latest_sensor_data": None,
        "started_at": (now - timedelta(seconds=30)).isoformat(),
        "updated_at": now.isoformat(),
        "heartbeat_at": now.timestamp(),
    }


@pytest.fixture
def client_backend(backend, monkeypatch):
    monitor, nodes, files, calls, capture_status = backend
    nodes[4]["Config"]["Labels"]["com.docker.compose.service"] = "office-workstation"
    nodes[9]["Config"]["Labels"]["com.docker.compose.service"] = "iot-sensor"
    dashboard = copy.deepcopy(nodes[9])
    dashboard["Id"] = "d" * 64
    dashboard["Config"]["Labels"]["com.docker.compose.service"] = "iot-dashboard"
    dashboard["NetworkSettings"]["Networks"][traffic.PROJECT + "_iot"]["IPAddress"] = "172.30.42.6"
    nodes.append(dashboard)
    # Real Docker short IDs must distinguish these services, unlike the simple
    # zero-padded IDs used by the older non-client fixture.
    nodes[4]["Id"], nodes[9]["Id"] = "b" * 64, "c" * 64
    receipts = {
        node["Id"]: json.dumps(
            client_receipt(node["Config"]["Labels"]["com.docker.compose.service"], node["Id"])
        ).encode()
        for node in (nodes[4], nodes[9], nodes[10])
    }

    def docker(arguments, limit):
        calls.append(arguments)
        if arguments[0] == "ps":
            return "\n".join(row["Id"] for row in nodes).encode()
        if arguments[0] == "inspect":
            assert arguments[1:] == [row["Id"] for row in nodes]
            return json.dumps(nodes).encode()
        if arguments[0] == "cp":
            assert arguments[2] == "-"
            identity, path = arguments[1].split(":", 1)
            if path == "/runtime/client-status.json":
                assert identity in receipts
                return archive("client-status.json", receipts[identity])
            assert identity == nodes[1]["Id"] and path in (
                "/capture/status.json",
                "/capture/capture.pcap",
            )
            name = path.rsplit("/", 1)[-1]
            return archive(name, files[name])
        if arguments[0] == "exec":
            assert arguments[:3] == ["exec", "--user", "10001:10001"]
            assert arguments[4:] == ["python", "-c", traffic.CLIENT_RECEIPT_READ_SCRIPT]
            assert arguments[3] in receipts and limit == traffic.MAX_CLIENT_STATUS_BYTES
            return receipts[arguments[3]]
        pytest.fail("Unexpected Docker command")

    monkeypatch.setattr(monitor, "_docker", docker)
    return monitor, nodes, receipts, calls, capture_status


def test_three_inspected_client_receipts_are_separate_from_packet_counts(client_backend):
    monitor, _, _, calls, _ = client_backend
    topology = monitor.topology()
    clients = [node for node in topology["nodes"] if node["service"] in traffic.CLIENT_ENDPOINTS]
    assert len(clients) == 3
    for node in clients:
        status = node["client_status"]
        assert status["available"] and status["error"] is None and not status["stale"]
        assert status["role"] == node["service"] and status["container_id"] == node["id"]
        assert status["source_address"] == status["observed_source_address"] == node["ips"][0]
        assert status["operation_count"] == 3
        assert status["evidence_kind"] == "application_client_receipt"
        assert "not captured packet counts" in status["count_basis"]
    assert (
        sum(call[0] == "cp" and call[1].endswith(":/runtime/client-status.json") for call in calls)
        == 3
    )
    assert all(call[0] in ("ps", "inspect", "cp") for call in calls)
    assert monitor.snapshot("office")["captured_packets"] == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", "iot-sensor"),
        ("container_id", "d" * 12),
        ("container_id", "b" * 11),
        ("container_id", "../secret"),
        ("container_hostname", "named-client"),
        ("source_address", "192.0.2.1"),
        ("observed_source_address", "172.30.42.5"),
        ("destination", {"address": "172.30.41.2", "port": 2121, "protocol": "ftp"}),
        ("destination", {"address": "172.30.41.3", "port": 22, "protocol": "ftp"}),
        ("operation", "arbitrary command"),
        ("operation_count", True),
        ("operation_count", -1),
        ("operation_count", 3.5),
        ("operation_count", 2**63),
        ("operation_count", float("inf")),
        ("heartbeat_at", True),
        ("heartbeat_at", float("nan")),
        ("state", "asserted-success"),
        ("started_at", "2026-01-01"),
        ("last_success", None),
        ("observed_source_address", None),
        ("last_error", "x" * 257),
        ("latest_sensor_data", {"unbounded": "payload"}),
    ],
)
def test_client_identity_scope_counts_and_bounds_fail_without_breaking_capture(
    client_backend, field, value
):
    monitor, nodes, receipts, _, _ = client_backend
    identity = nodes[4]["Id"]
    status = json.loads(receipts[identity])
    status[field] = value
    receipts[identity] = json.dumps(status).encode()
    topology = monitor.topology()
    client = next(node for node in topology["nodes"] if node["service"] == "office-workstation")
    assert not client["client_status"]["available"] and client["client_status"]["error"]
    assert client["client_status"]["operation_count"] is None
    assert topology["environments"]["office"]["available"]
    assert monitor.snapshot("office")["available"]


@pytest.mark.parametrize(
    "raw",
    [b"[]", b"null", b"\xff", b"{", b'{"role":1,"role":2}', b"x" * 8193],
    ids=["array", "null", "encoding", "truncated", "duplicate", "oversized"],
)
def test_malformed_client_json_is_isolated(client_backend, raw):
    monitor, nodes, receipts, _, _ = client_backend
    receipts[nodes[4]["Id"]] = raw
    client = next(
        node for node in monitor.topology()["nodes"] if node["service"] == "office-workstation"
    )
    assert not client["client_status"]["available"] and client["client_status"]["error"]
    assert monitor.snapshot("office")["available"]


@pytest.mark.parametrize("offset", [-60, 60])
def test_stale_or_future_client_receipt_retains_explicit_historical_counts(client_backend, offset):
    monitor, nodes, receipts, _, _ = client_backend
    status = json.loads(receipts[nodes[4]["Id"]])
    for field in ("started_at", "updated_at", "last_success"):
        status[field] = (
            datetime.fromisoformat(status[field]) + timedelta(seconds=offset)
        ).isoformat()
    status["heartbeat_at"] += offset
    receipts[nodes[4]["Id"]] = json.dumps(status).encode()
    client = next(
        node for node in monitor.topology()["nodes"] if node["service"] == "office-workstation"
    )
    result = client["client_status"]
    assert not result["available"] and result["stale"] and "historical" in result["error"]
    assert result["operation_count"] == 3 and monitor.snapshot("office")["available"]


def test_client_initial_source_none_and_policy_blocked_are_honest_receipts(client_backend):
    monitor, nodes, receipts, _, _ = client_backend
    status = json.loads(receipts[nodes[4]["Id"]])
    status.update(
        operation_count=0, last_success=None, observed_source_address=None, state="starting"
    )
    receipts[nodes[4]["Id"]] = json.dumps(status).encode()
    first = next(
        node for node in monitor.topology()["nodes"] if node["service"] == "office-workstation"
    )["client_status"]
    assert (
        first["available"]
        and first["operation_count"] == 0
        and first["observed_source_address"] is None
    )
    status.update(
        state="policy_blocked",
        last_failure=status["updated_at"],
        last_error="PolicyBlocked: FTP denied",
    )
    receipts[nodes[4]["Id"]] = json.dumps(status).encode()
    monitor.refresh("office")
    second = next(
        node for node in monitor.topology()["nodes"] if node["service"] == "office-workstation"
    )["client_status"]
    assert second["available"] and second["state"] == "policy_blocked"
    assert second["last_error"] == "PolicyBlocked: FTP denied" and second["operation_count"] == 0


def test_client_receipt_only_exposes_bounded_sensor_and_file_fields(client_backend):
    monitor, nodes, receipts, _, _ = client_backend
    sensor = json.loads(receipts[nodes[9]["Id"]])
    sensor["latest_sensor_data"] = {
        "device": "training-sensor-01",
        "source": "simulated sensor",
        "sequence": 3,
        "temperature_c": 21.3,
        "humidity_pct": 43,
        "sent_at": sensor["last_success"],
    }
    sensor["arbitrary_payload"] = {"credential": "discard"}
    receipts[nodes[9]["Id"]] = json.dumps(sensor).encode()
    workstation = json.loads(receipts[nodes[4]["Id"]])
    workstation.update(filename="network-proof.txt", bytes_received=32)
    receipts[nodes[4]["Id"]] = json.dumps(workstation).encode()
    topology = monitor.topology()
    output = next(node for node in topology["nodes"] if node["service"] == "iot-sensor")[
        "client_status"
    ]
    assert output["latest_sensor_data"] == sensor["latest_sensor_data"]
    assert "arbitrary_payload" not in output
    file_status = next(
        node for node in topology["nodes"] if node["service"] == "office-workstation"
    )["client_status"]
    assert file_status["filename"] == "network-proof.txt" and file_status["bytes_received"] == 32
    sensor["latest_sensor_data"]["humidity_pct"] = float("inf")
    receipts[nodes[9]["Id"]] = json.dumps(sensor).encode()
    monitor.refresh()
    assert not next(
        node for node in monitor.topology()["nodes"] if node["service"] == "iot-sensor"
    )["client_status"]["available"]


def test_stopped_or_wrong_inspected_client_network_is_explicit(client_backend):
    monitor, nodes, _, calls, _ = client_backend
    nodes[4]["State"]["Running"] = False
    first = next(
        node for node in monitor.topology()["nodes"] if node["service"] == "office-workstation"
    )["client_status"]
    assert not first["available"] and "stopped" in first["error"]
    assert not any(call[0] == "cp" and call[1].startswith(nodes[4]["Id"] + ":") for call in calls)
    nodes[4]["State"]["Running"] = True
    nodes[4]["NetworkSettings"]["Networks"][traffic.PROJECT + "_office"]["IPAddress"] = (
        "172.30.41.6"
    )
    monitor.refresh()
    second = next(
        node for node in monitor.topology()["nodes"] if node["service"] == "office-workstation"
    )["client_status"]
    assert not second["available"] and "source network" in second["error"]
    assert monitor.snapshot("office")["available"]


def test_client_caches_are_refreshable_and_capture_never_reads_them(client_backend):
    monitor, _, _, calls, _ = client_backend
    assert monitor.snapshot("office")["available"]
    assert not any(call[0] == "cp" and "/runtime/" in call[1] for call in calls)
    topology = monitor.topology()
    client = next(node for node in topology["nodes"] if node["service"] == "office-workstation")
    client["client_status"]["operation_count"] = 999
    before = len(calls)
    fresh = next(
        node for node in monitor.topology()["nodes"] if node["service"] == "office-workstation"
    )
    assert fresh["client_status"]["operation_count"] == 3 and len(calls) == before
    monitor.refresh("office")
    monitor.topology()
    reads = [call for call in calls[before:] if call[0] == "cp" and "/runtime/" in call[1]]
    assert len(reads) == 1


def test_client_download_path_cannot_be_expanded_and_links_are_rejected(monkeypatch, tmp_path):
    monitor = traffic.TrafficMonitor(tmp_path)
    calls = []

    def docker(arguments, limit):
        calls.append(arguments)
        assert arguments == ["cp", "a" * 64 + ":/runtime/client-status.json", "-"]
        return archive("client-status.json", b"{}", tarfile.SYMTYPE)

    monkeypatch.setattr(monitor, "_docker", docker)
    for kind in ("/runtime/client-status.json", "../client_status", "client_status;id", None, []):
        with pytest.raises(ValueError):
            monitor._download("a" * 64, kind)
    with pytest.raises(ValueError):
        monitor._copy("a" * 64, "client-status.json")
    assert calls == []
    with pytest.raises(ValueError, match="Unsafe"):
        monitor._download("a" * 64, "client_status")


def test_client_copy_failure_reports_receipt_not_stopped_observer(client_backend, monkeypatch):
    monitor, _, _, _, _ = client_backend
    docker = monitor._docker

    def missing_receipt(arguments, limit):
        if arguments[0] == "cp" and arguments[1].endswith(":/runtime/client-status.json"):
            raise ValueError(
                "Docker inspection or fixed evidence read failed; container or receipt may be unavailable"
            )
        return docker(arguments, limit)

    monkeypatch.setattr(monitor, "_docker", missing_receipt)
    node = next(
        node for node in monitor.topology()["nodes"] if node["service"] == "office-workstation"
    )
    status = node["client_status"]
    assert node["running"] and node["health"] == "healthy"
    assert not status["available"] and status["operation_count"] is None
    assert status["error"].startswith("Client application receipt unavailable:")
    assert "observer" not in status["error"] and "stopped" not in status["error"]
    assert monitor.snapshot("office")["available"]


def test_kernel_ancillary_time_survives_delayed_userspace_and_matches_pcap(
    backend, monkeypatch, tmp_path
):
    monitor, _, files, _, _ = backend
    processed_ns = time.time_ns()
    seconds = processed_ns // 1_000_000_000 - 1
    kernel_ns = seconds * 1_000_000_000 + 123_456_789
    ancillary = [(socket.SOL_SOCKET, 35, capture.TIMESPEC.pack(seconds, 123_456_789))]

    class DelayedWire:
        def recvmsg(self, size, control_bytes):
            assert size == capture.SNAPLEN + 1 and control_bytes >= 32
            return frame(payload=b"230 fixture response"), ancillary, 0, ()

    monkeypatch.setattr(capture.time, "time_ns", lambda: processed_ns)
    wire, stamp, basis, error, processed = capture.receive_packet(DelayedWire(), 35)
    assert stamp == kernel_ns and processed - stamp > 0.5 * 1_000_000_000
    assert basis == capture.KERNEL_TIMESTAMP and error is None
    observer = capture.Capture("office", tmp_path / "kernel")
    observer._reset(seconds - 1)
    observer.running = True
    observer.timestamp_mode, observer.timestamp_error = capture.KERNEL_TIMESTAMP, None
    assert observer.accept(
        wire,
        timestamp_ns=stamp,
        timestamp_basis=basis,
        timestamp_error=error,
        processed_ns=processed,
    )
    observer.publish()
    status_bytes = (observer.directory / "status.json").read_bytes()
    status = traffic.validate_status(status_bytes, "office")
    packet = status["packets"][0]
    assert (
        packet["timestamp_ns"] == kernel_ns
        and packet["timestamp_basis"] == capture.KERNEL_TIMESTAMP
    )
    assert packet["timestamp"] == capture.utc_ns(kernel_ns)
    assert packet["processed_at"] == capture.utc_ns(processed_ns)
    assert status["timestamp_fallback_packets"] == 0
    pcap_seconds, micros, included, original = struct.unpack_from("<IIII", observer.data, 24)
    assert (pcap_seconds, micros) == (seconds, 123_456)
    assert included == original == len(wire)
    assert traffic.validate_pcap(bytes(observer.data), "office") == 1
    files.update({"status.json": status_bytes, "capture.pcap": bytes(observer.data)})
    start, finish = capture.utc_ns(kernel_ns - 50_000_000), capture.utc_ns(kernel_ns + 50_000_000)
    result = monitor.correlate("office", 2121, start, finish)
    assert result["available"] and result["packet_ids"] == [packet["packet_id"]]
    assert packet["processed_at"] > finish


@pytest.mark.parametrize(
    "ancillary,flags",
    [
        ([], 0),
        ([(socket.SOL_SOCKET, 35, b"short")], 0),
        ([(socket.SOL_SOCKET, 35, capture.TIMESPEC.pack(-1, 0))], 0),
        ([(socket.SOL_SOCKET, 35, capture.TIMESPEC.pack(1, -1))], 0),
        ([(socket.SOL_SOCKET, 35, capture.TIMESPEC.pack(1, 1_000_000_000))], 0),
        ([(socket.SOL_SOCKET, 35, capture.TIMESPEC.pack(2**32, 0))], 0),
        ([(socket.SOL_SOCKET, 35, capture.TIMESPEC.pack(1, 0))] * 2, 0),
        ([(socket.SOL_SOCKET, 64, capture.TIMESPEC.pack(1, 0))], 0),
        ([(socket.SOL_SOCKET + 1, 35, capture.TIMESPEC.pack(1, 0))], 0),
        (["malformed"], 0),
        ({"malformed": True}, 0),
        ([(socket.SOL_SOCKET, 35, capture.TIMESPEC.pack(1, 0))], getattr(socket, "MSG_CTRUNC", 8)),
    ],
    ids=[
        "missing",
        "short",
        "negative-seconds",
        "negative-nanos",
        "overflow-nanos",
        "overflow-seconds",
        "duplicate",
        "wrong-type",
        "wrong-level",
        "malformed-message",
        "malformed-list",
        "truncated-control",
    ],
)
def test_invalid_or_missing_kernel_ancillary_falls_back_with_uncertainty(ancillary, flags):
    processed = 1_700_000_000_987_654_321
    stamp, basis, error = capture.ancillary_timestamp(ancillary, flags, 35, processed)
    assert stamp == processed and basis == capture.USERSPACE_TIMESTAMP
    assert error and "userspace" in error


def test_valid_new_timespec_abi_and_unavailable_kernel_timestamp():
    stamp = 1_700_000_000_123_456_789
    ancillary = [(socket.SOL_SOCKET, 64, capture.TIMESPEC.pack(1_700_000_000, 123_456_789))]
    assert capture.ancillary_timestamp(ancillary, 0, 64, stamp + 1_000_000_000) == (
        stamp,
        capture.KERNEL_TIMESTAMP,
        None,
    )
    fallback, basis, error = capture.ancillary_timestamp(ancillary, 0, None, stamp + 1_000_000_000)
    assert fallback == stamp + 1_000_000_000 and basis == capture.USERSPACE_TIMESTAMP
    assert "unavailable" in error and "delay is unknown" in error


def test_linux_amd64_constant_fallback_and_setsockopt_failure_are_explicit(monkeypatch):
    monkeypatch.setattr(capture.sys, "platform", "linux")
    monkeypatch.setattr(capture.platform, "machine", lambda: "x86_64")
    monkeypatch.delattr(capture.socket, "SO_TIMESTAMPNS", raising=False)
    calls = []

    class Wire:
        def setsockopt(self, level, option, value):
            calls.append((level, option, value))

    assert capture.enable_kernel_timestamps(Wire()) == (35, None)
    assert calls == [(socket.SOL_SOCKET, 35, 1)]

    class UnsupportedWire:
        def setsockopt(self, *_):
            raise OSError("unsupported")

    option, error = capture.enable_kernel_timestamps(UnsupportedWire())
    assert option is None and "userspace receive scheduling delay is unknown" in error
    monkeypatch.setattr(capture.platform, "machine", lambda: "unsupported")
    assert capture.enable_kernel_timestamps(Wire())[0] is None


def test_truncated_recvmsg_frame_never_becomes_capture_evidence(tmp_path):
    class Wire:
        def recvmsg(self, *_):
            return frame(), [], getattr(socket, "MSG_TRUNC", 32), ()

    wire, stamp, basis, error, processed = capture.receive_packet(Wire(), None)
    observer = capture.Capture("office", tmp_path)
    assert not observer.accept(
        wire,
        timestamp_ns=stamp,
        timestamp_basis=basis,
        timestamp_error=error,
        processed_ns=processed,
    )
    assert observer.captured_packets == 0 and bytes(observer.data) == capture.PCAP_HEADER


def test_legacy_receipts_do_not_claim_kernel_capture_timestamps(tmp_path):
    status, _ = document(tmp_path)
    for key in (
        "timestamp_mode",
        "timestamp_error",
        "timestamp_fallback_packets",
        "pcap_timestamp_resolution",
    ):
        status.pop(key)
    for packet in status["packets"]:
        for key in ("timestamp_ns", "timestamp_basis", "processed_at", "timestamp_error"):
            packet.pop(key)
    result = traffic.validate_status(json.dumps(status).encode(), "office")
    assert result["timestamp_mode"] == capture.LEGACY_TIMESTAMP
    assert result["timestamp_fallback_packets"] is None
    assert result["packets"][0]["timestamp_basis"] == capture.LEGACY_TIMESTAMP
    assert result["packets"][0]["timestamp_ns"] is None
    assert "unknown" in result["packets"][0]["timestamp_error"]


@pytest.mark.parametrize(
    "key,value",
    [
        ("timestamp_basis", "exact-causal-time"),
        ("timestamp_ns", True),
        ("timestamp_ns", -1),
        ("timestamp_ns", 1_700_000_000_000_000_000),
        ("timestamp_error", "x" * 241),
        ("processed_at", "2020-01-01T00:00:00Z"),
    ],
)
def test_status_rejects_forged_or_malformed_timestamp_provenance(tmp_path, key, value):
    status, _ = document(tmp_path)
    status["packets"][0][key] = value
    with pytest.raises(ValueError):
        traffic.validate_status(json.dumps(status).encode(), "office")


def bundle_generation(tmp_path, *, packets=None, updated_at=None, packet_time=None):
    observer = capture.Capture("office", tmp_path)
    observer._reset(time.time() - 4)
    observer.running = True
    for packet in [frame()] if packets is None else packets:
        instant = time.time() - 1 if packet_time is None else packet_time
        observer.accept(packet, instant, processed_ns=int(instant * 1_000_000_000))
    observer.publish()
    status = json.loads((tmp_path / "status.json").read_bytes())
    pcap = (tmp_path / "capture.pcap").read_bytes()
    if updated_at is not None:
        status["updated_at"] = updated_at
    return status, pcap, capture.evidence_bundle(json.dumps(status).encode(), pcap)


def test_observer_atomic_bundle_contains_its_exact_published_generation(tmp_path):
    status, pcap, _ = bundle_generation(tmp_path)
    bundled_status, bundled_pcap = traffic.validate_evidence_bundle(
        (tmp_path / "evidence.tar").read_bytes(), "office"
    )
    assert bundled_status["session_id"] == status["session_id"]
    assert bundled_status["captured_packets"] == status["captured_packets"] == 1
    assert bundled_pcap == pcap
    assert bundled_status["pcap_sha256"] == traffic.hashlib.sha256(pcap).hexdigest()
    assert not list(tmp_path.glob("*.tmp"))


def test_collect_uses_only_one_fixed_bundle_and_never_separate_snapshot_or_pcap(
    backend, tmp_path, monkeypatch
):
    monitor, _, files, calls, old = backend
    status, pcap, bundle = bundle_generation(
        tmp_path / "paired", packets=[frame(destination_port=2222), frame(destination_port=2222)]
    )
    assert old["session_id"] != status["session_id"]
    files["evidence.tar"] = bundle

    def forbidden(*_, **__):
        pytest.fail("Paired collect must not independently read snapshot, correlate or pcap")

    monkeypatch.setattr(monitor, "snapshot", forbidden)
    monkeypatch.setattr(monitor, "correlate", forbidden)
    monkeypatch.setattr(monitor, "pcap", forbidden)
    result, content = monitor.collect("office", 2222, status["started_at"], status["updated_at"])
    assert content == pcap and result["session_id"] == status["session_id"]
    assert (
        result["paired_evidence"] and result["evidence_pairing"] == "atomic_status_and_pcap_bundle"
    )
    assert result["matched_packets"] == result["captured_packets"] == result["pcap_packets"] == 2
    assert result["association_established"] and not result["causal_validation"]
    assert result["packet_ids"] == [packet["packet_id"] for packet in status["packets"]]
    assert result["pcap_sha256"] == traffic.hashlib.sha256(content).hexdigest()
    copies = [call for call in calls if call[0] == "cp"]
    assert len(copies) == 1 and copies[0][1].endswith(":/capture/evidence.tar")


def test_cross_generation_bundle_with_same_count_and_size_is_rejected(tmp_path):
    first, first_pcap, _ = bundle_generation(
        tmp_path / "first", packets=[frame(payload=b"generation-A")]
    )
    second, second_pcap, _ = bundle_generation(
        tmp_path / "second", packets=[frame(payload=b"generation-B")]
    )
    assert first["captured_packets"] == second["captured_packets"]
    assert len(first_pcap) == len(second_pcap)
    mixed = capture.evidence_bundle(json.dumps(first).encode(), second_pcap)
    with pytest.raises(ValueError, match="different generations"):
        traffic.validate_evidence_bundle(mixed, "office")


def test_bundle_rejects_status_metadata_that_disagrees_with_matching_hash(tmp_path):
    status, pcap, _ = bundle_generation(tmp_path)
    packet = status["packets"][0]
    payload = b"z" * packet["payload_length"]
    packet.update(payload_hex=payload.hex(), payload_summary=payload.decode())
    bundle = capture.evidence_bundle(json.dumps(status).encode(), pcap)
    with pytest.raises(ValueError, match="metadata differs"):
        traffic.validate_evidence_bundle(bundle, "office")


@pytest.mark.parametrize(
    "change", ["hash", "truncated-pcap", "truncated-status", "wrong-environment"]
)
def test_corrupt_bundle_never_returns_evidence(tmp_path, change):
    status, pcap, _ = bundle_generation(tmp_path)
    environment = "office"
    if change == "hash":
        status["pcap_sha256"] = "0" * 64
    elif change == "truncated-pcap":
        pcap = pcap[:-1]
    elif change == "wrong-environment":
        environment = "iot"
    raw = json.dumps(status).encode()
    if change == "truncated-status":
        raw = raw[:-1]
    with pytest.raises(ValueError):
        traffic.validate_evidence_bundle(capture.evidence_bundle(raw, pcap), environment)


def arbitrary_bundle(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as bundle:
        for name, content, kind in entries:
            member = tarfile.TarInfo(name)
            member.type, member.linkname = kind, "../../secret"
            member.size = len(content) if kind == tarfile.REGTYPE else 0
            bundle.addfile(member, io.BytesIO(content))
    return output.getvalue()


@pytest.mark.parametrize(
    "entries",
    [
        [("status.json", b"{}", tarfile.REGTYPE)],
        [("status.json", b"{}", tarfile.REGTYPE), ("status.json", b"{}", tarfile.REGTYPE)],
        [("status.json", b"{}", tarfile.REGTYPE), ("../capture.pcap", b"", tarfile.REGTYPE)],
        [("status.json", b"{}", tarfile.SYMTYPE), ("capture.pcap", b"", tarfile.REGTYPE)],
        [("status.json", b"{}", tarfile.REGTYPE), ("capture.pcap", b"", tarfile.LNKTYPE)],
        [("status.json", b"{}", tarfile.REGTYPE), ("capture.pcap", b"", tarfile.DIRTYPE)],
        [
            ("status.json", b"{}", tarfile.REGTYPE),
            ("capture.pcap", b"", tarfile.REGTYPE),
            ("extra", b"", tarfile.REGTYPE),
        ],
    ],
    ids=["missing", "duplicate", "traversal", "symlink", "hardlink", "directory", "extra"],
)
def test_unsafe_bundle_members_are_rejected(entries):
    with pytest.raises(ValueError):
        traffic.validate_evidence_bundle(arbitrary_bundle(entries), "office")


def test_bundle_download_and_metadata_are_hard_bounded_at_four_and_half_mib(tmp_path):
    observer = capture.Capture("office", tmp_path)
    observer.running = True
    for _ in range(61):
        observer.accept(frame(payload=b"x" * 64000))
    for index in range(400):
        observer.accept(
            frame(source_port=40000 + index, payload=b'"' * 96, flags=0xFF),
            timestamp_error="x" * 240,
        )
    observer.publish()
    bundle = (tmp_path / "evidence.tar").read_bytes()
    assert len(bundle) <= capture.MAX_EVIDENCE_BYTES == int(4.5 * 1024 * 1024)
    status, pcap = traffic.validate_evidence_bundle(bundle, "office")
    assert len(pcap) > 3.5 * 1024 * 1024
    assert status["captured_packets"] == 461
    assert status["metadata_trimmed_for_bundle"] and 0 < len(status["packets"]) < 400
    assert status["metadata_packets"] == len(status["packets"])
    assert status["packets"][0]["packet_id"].endswith(":" + str(462 - len(status["packets"])))
    with pytest.raises(ValueError, match="bounded tar"):
        traffic.validate_evidence_bundle(bundle + b"x" * capture.MAX_EVIDENCE_BYTES, "office")


def test_collect_polls_then_associates_the_new_complete_pair(backend, tmp_path, monkeypatch):
    monitor, _, _, _, _ = backend
    now = time.time()
    finish = capture.utc(now - 0.2)
    first, first_pcap, before = bundle_generation(
        tmp_path / "before", updated_at=capture.utc(now - 0.3), packet_time=now - 1
    )
    second, second_pcap, after = bundle_generation(
        tmp_path / "after", packets=[frame(), frame(payload=b"230 response")], packet_time=now - 0.5
    )
    replies = iter((before, after))
    reads = []
    original = monitor._download

    def download(identity, kind):
        if kind == "evidence":
            reads.append((identity, kind))
            return next(replies)
        return original(identity, kind)

    monkeypatch.setattr(monitor, "_download", download)
    result, content = monitor.collect("office", 2121, capture.utc(now - 2), finish)
    assert len(reads) == 2 and result["window_published"]
    assert result["session_id"] == second["session_id"] != first["session_id"]
    assert content == second_pcap != first_pcap and result["captured_packets"] == 2
    assert result["packet_ids"] == [packet["packet_id"] for packet in second["packets"]]


def test_collect_rollover_returns_actual_new_generation_without_claiming_association(
    backend, tmp_path, monkeypatch
):
    monitor, _, _, _, _ = backend
    now = time.time()
    finish = capture.utc(now - 0.2)
    _, _, before = bundle_generation(
        tmp_path / "before", updated_at=capture.utc(now - 0.3), packet_time=now - 1
    )
    after_status, after_pcap, after = bundle_generation(tmp_path / "after", packets=[])
    # An empty session created after the action models a rotation whose earlier
    # action packets belong to an unavailable prior generation.
    after_status["started_at"] = capture.utc(now)
    after = capture.evidence_bundle(json.dumps(after_status).encode(), after_pcap)
    replies = iter((before, after))
    monkeypatch.setattr(monitor, "_download", lambda *_: next(replies))
    result, content = monitor.collect("office", 2121, capture.utc(now - 2), finish)
    assert result["session_id"] == after_status["session_id"]
    assert content == after_pcap == capture.PCAP_HEADER
    assert result["captured_packets"] == result["pcap_packets"] == 0
    assert not result["association_established"] and result["association"] == "not_established"
    assert result["packet_ids"] == [] and any(
        "not established" in item for item in result["limitations"]
    )


def test_collect_publication_budget_preserves_one_validated_pair(backend, tmp_path, monkeypatch):
    monitor, _, _, _, _ = backend
    now = time.time()
    status, pcap, bundle = bundle_generation(
        tmp_path / "pending", updated_at=capture.utc(now - 0.3), packet_time=now - 1
    )
    clock = [0.0]
    monkeypatch.setattr(traffic.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        traffic.time, "sleep", lambda duration: clock.__setitem__(0, clock[0] + duration)
    )
    monkeypatch.setattr(monitor, "_download", lambda *_: bundle)
    result, content = monitor.collect("office", 2121, capture.utc(now - 2), capture.utc(now - 0.2))
    assert clock[0] <= 1.500001 and not result["window_published"]
    assert content == pcap and result["session_id"] == status["session_id"]
    assert result["paired_evidence"] and any(
        "has not reached" in item for item in result["limitations"]
    )


def test_collect_timeout_keeps_valid_pair_but_corruption_is_never_accepted(
    backend, tmp_path, monkeypatch
):
    monitor, _, _, _, _ = backend
    now = time.time()
    status, pcap, bundle = bundle_generation(
        tmp_path / "pending", updated_at=capture.utc(now - 0.3), packet_time=now - 1
    )
    read = [0]

    def download(*_):
        read[0] += 1
        if read[0] == 1:
            return bundle
        raise traffic._PublicationDeadline("publication deadline")

    monkeypatch.setattr(monitor, "_download", download)
    result, content = monitor.collect("office", 2121, capture.utc(now - 2), capture.utc(now - 0.2))
    assert content == pcap and result["session_id"] == status["session_id"]
    assert result["publication_error"] == "publication deadline" and not result["window_published"]
    monkeypatch.setattr(monitor, "_download", lambda *_: b"corrupt")
    with pytest.raises(ValueError):
        monitor.collect("office", 2121, capture.utc(now - 2), capture.utc(now - 0.2))


def test_collect_rejects_unknown_scope_stopped_status_and_wrong_project(backend, tmp_path):
    monitor, nodes, files, calls, _ = backend
    for environment, port in (("../office", 2121), ("office", 22), ("office", "2121")):
        with pytest.raises(ValueError):
            monitor.collect(environment, port, "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z")
    assert calls == []
    status, pcap, _ = bundle_generation(tmp_path)
    status["running"] = False
    files["evidence.tar"] = capture.evidence_bundle(json.dumps(status).encode(), pcap)
    with pytest.raises(ValueError, match="stopped"):
        monitor.collect("office", 2121, status["started_at"], status["updated_at"])
    nodes[1]["Config"]["Labels"]["com.docker.compose.project"] = "harbordesk"
    calls.clear()
    with pytest.raises(ValueError, match="wrong Compose project"):
        monitor.collect("office", 2121, status["started_at"], status["updated_at"])
    assert not any(call[0] == "cp" for call in calls)


def test_inspected_tmpfs_receipt_uses_only_fixed_readonly_exec_without_affecting_capture(
    client_backend,
):
    monitor, nodes, _, calls, _ = client_backend
    for raw in (nodes[4], nodes[9], nodes[10]):
        raw["HostConfig"]["Tmpfs"] = {
            "/runtime": "rw,uid=10001,gid=10001,mode=0700,size=2m",
            "/tmp": "rw,size=4m",
        }
    topology = monitor.topology()
    clients = [node for node in topology["nodes"] if node["service"] in traffic.CLIENT_ENDPOINTS]
    assert len(clients) == 3
    for node in clients:
        result = node["client_status"]
        assert node["running"] and node["health"] == "healthy"
        assert "/runtime" in node["tmpfs_mounts"]
        assert result["available"] and result["operation_count"] == 3 and not result["stale"]
        assert result["error"] is None
        assert (
            result["receipt_path"] == "/runtime/client-status.json"
            and result["tmpfs_mount"] == "/runtime"
        )
        assert result["receipt_read_method"] == "fixed_readonly_exec"
        assert result["receipt_storage"] == "docker_tmpfs"
        assert result["evidence_kind"] == "application_client_receipt"
    assert not any(call[0] == "cp" and "/runtime/" in call[1] for call in calls)
    reads = [call for call in calls if call[0] == "exec"]
    assert len(reads) == 3
    assert {call[3] for call in reads} == {nodes[index]["Id"] for index in (4, 9, 10)}
    assert all(call[:3] == ["exec", "--user", "10001:10001"] for call in reads)
    assert all(call[4:] == ["python", "-c", traffic.CLIENT_RECEIPT_READ_SCRIPT] for call in reads)
    assert monitor.snapshot("office")["available"]
    assert monitor.snapshot("office")["captured_packets"] == 1


def test_copy_readable_client_receipt_works_when_runtime_is_not_tmpfs(client_backend):
    monitor, nodes, _, _, _ = client_backend
    nodes[4]["HostConfig"]["Tmpfs"] = {"/tmp": "rw,size=4m"}
    workstation = next(
        node for node in monitor.topology()["nodes"] if node["service"] == "office-workstation"
    )
    assert workstation["tmpfs_mounts"] == ["/tmp"]
    assert (
        workstation["client_status"]["available"]
        and workstation["client_status"]["operation_count"] == 3
    )


def test_tmpfs_path_matching_does_not_confuse_runtime_prefix(client_backend):
    monitor, nodes, _, _, _ = client_backend
    nodes[4]["HostConfig"]["Tmpfs"] = {"/runtime-other": "rw,size=2m"}
    workstation = next(
        node for node in monitor.topology()["nodes"] if node["service"] == "office-workstation"
    )
    assert workstation["client_status"]["available"]


@pytest.mark.parametrize("tmpfs", [[], ["/runtime"], {"runtime": "rw"}, {"/runtime": []}])
def test_malformed_inspected_tmpfs_metadata_is_rejected(backend, tmpfs):
    monitor, nodes, _, _, _ = backend
    nodes[4]["HostConfig"]["Tmpfs"] = tmpfs
    result = monitor.snapshot("office")
    assert not result["available"] and "tmpfs mount metadata" in result["error"]


def fixed_reader_fixture(
    payload,
    *,
    mode=stat.S_IFREG,
    declared_size=None,
    final_size=None,
    symlink=False,
    parent_symlink=False,
    uid=10001,
    gid=10001,
):
    """Exercise the exact Linux reader script with deterministic descriptor I/O."""
    output, calls = io.BytesIO(), []
    state = {"offset": 0, "stats": 0}
    size = len(payload) if declared_size is None else declared_size

    def open_file(path, flags, *, dir_fd=None):
        calls.append(("open", path, flags, dir_fd))
        assert flags & fake_os.O_NOFOLLOW and flags & fake_os.O_CLOEXEC
        if path == "/runtime":
            assert dir_fd is None and flags & fake_os.O_DIRECTORY
            if parent_symlink:
                raise OSError("Parent symlink refused")
            return 10
        assert path == "client-status.json" and dir_fd == 10
        assert flags & fake_os.O_NONBLOCK
        if symlink:
            raise OSError("Receipt symlink refused")
        return 11

    def fstat(descriptor):
        assert descriptor == 11
        state["stats"] += 1
        return SimpleNamespace(
            st_mode=mode, st_size=size if state["stats"] == 1 or final_size is None else final_size
        )

    def read(descriptor, maximum):
        assert (
            descriptor == 11
            and 0 < maximum <= traffic.MAX_CLIENT_STATUS_BYTES + 1 - state["offset"]
        )
        content = payload[state["offset"] : state["offset"] + min(257, maximum)]
        state["offset"] += len(content)
        calls.append(("read", maximum, len(content)))
        return content

    fake_os = SimpleNamespace(
        O_RDONLY=0,
        O_DIRECTORY=1,
        O_NOFOLLOW=2,
        O_NONBLOCK=4,
        O_CLOEXEC=8,
        geteuid=lambda: uid,
        getegid=lambda: gid,
        open=open_file,
        fstat=fstat,
        read=read,
        close=lambda descriptor: calls.append(("close", descriptor)),
    )
    fake_sys = SimpleNamespace(stdout=SimpleNamespace(buffer=output))

    def fixed_import(name, *_args, **_kwargs):
        return {"os": fake_os, "stat": stat, "sys": fake_sys}[name]

    def run():
        exec(
            traffic.CLIENT_RECEIPT_READ_SCRIPT,
            {"__builtins__": {**vars(builtins), "__import__": fixed_import}},
        )

    return SimpleNamespace(run=run, output=output, calls=calls, state=state)


def test_fixed_reader_outputs_only_exact_bounded_binary_contents():
    payload = b"\x00\xff" + b"x" * (traffic.MAX_CLIENT_STATUS_BYTES - 2)
    reader = fixed_reader_fixture(payload)
    reader.run()
    assert reader.output.getvalue() == payload
    assert reader.state["offset"] == traffic.MAX_CLIENT_STATUS_BYTES
    assert [call[1] for call in reader.calls if call[0] == "open"] == [
        "/runtime",
        "client-status.json",
    ]
    assert ("close", 11) in reader.calls and ("close", 10) in reader.calls


@pytest.mark.parametrize(
    "mode", [stat.S_IFIFO, stat.S_IFDIR, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK]
)
def test_fixed_reader_refuses_nonregular_files_before_any_read(mode):
    reader = fixed_reader_fixture(b"", mode=mode)
    with pytest.raises(SystemExit, match="regular file"):
        reader.run()
    assert reader.output.getvalue() == b"" and not any(call[0] == "read" for call in reader.calls)


@pytest.mark.parametrize("parent", [False, True])
def test_fixed_reader_refuses_receipt_and_parent_symlinks(parent):
    reader = fixed_reader_fixture(b"secret", symlink=not parent, parent_symlink=parent)
    with pytest.raises(OSError, match="symlink refused"):
        reader.run()
    assert reader.output.getvalue() == b"" and not any(call[0] == "read" for call in reader.calls)


def test_fixed_reader_rejects_oversized_or_growing_file_without_stdout():
    payload = b"x" * (traffic.MAX_CLIENT_STATUS_BYTES + 1)
    oversized = fixed_reader_fixture(payload)
    with pytest.raises(SystemExit, match="bounded regular"):
        oversized.run()
    assert not any(call[0] == "read" for call in oversized.calls)
    growing = fixed_reader_fixture(payload, declared_size=traffic.MAX_CLIENT_STATUS_BYTES)
    with pytest.raises(SystemExit, match="exceeds fixed"):
        growing.run()
    assert growing.state["offset"] == traffic.MAX_CLIENT_STATUS_BYTES + 1
    assert oversized.output.getvalue() == growing.output.getvalue() == b""


@pytest.mark.parametrize(
    "options", [{"declared_size": 3}, {"final_size": 3}, {"uid": 0}, {"gid": 0}]
)
def test_fixed_reader_refuses_inconsistent_size_or_wrong_identity(options):
    reader = fixed_reader_fixture(b"{}", **options)
    with pytest.raises(SystemExit):
        reader.run()
    assert reader.output.getvalue() == b""


@pytest.mark.parametrize(
    "key,value",
    [
        ("service", "office"),
        ("service", "office-capture"),
        ("service", "harbordesk"),
        ("project", "harbordesk"),
        ("id", "--privileged"),
        ("id", "f" * 64),
        ("id", f"{1:064x}"),
    ],
)
def test_fixed_exec_reader_requires_actual_inspected_allowlisted_client(client_backend, key, value):
    monitor, _, _, calls, _ = client_backend
    node = copy.deepcopy(
        next(row for row in monitor._topology()["nodes"] if row["service"] == "office-workstation")
    )
    node[key] = value
    with pytest.raises(ValueError):
        monitor._read_client_receipt(node)
    assert not any(call[0] == "exec" for call in calls)


@pytest.mark.parametrize(
    "key,value", [("NetworkMode", "host"), ("PidMode", "host"), ("Privileged", True)]
)
def test_fixed_exec_reader_refuses_inspected_host_or_privileged_client(client_backend, key, value):
    monitor, nodes, _, calls, _ = client_backend
    nodes[4]["HostConfig"].update({key: value, "Tmpfs": {"/runtime": "rw,size=2m"}})
    client = next(
        row for row in monitor.topology()["nodes"] if row["service"] == "office-workstation"
    )
    assert (
        not client["client_status"]["available"]
        and client["client_status"]["operation_count"] is None
    )
    assert not any(call[0] == "exec" for call in calls)


def test_tmpfs_exec_still_uses_existing_receipt_validator_and_cache(client_backend):
    monitor, nodes, receipts, calls, _ = client_backend
    nodes[4]["HostConfig"]["Tmpfs"] = {"/runtime": "rw,size=2m"}
    first = next(
        row for row in monitor.topology()["nodes"] if row["service"] == "office-workstation"
    )["client_status"]
    assert first["available"] and first["operation_count"] == 3
    before = sum(call[0] == "exec" for call in calls)
    monitor.topology()
    assert sum(call[0] == "exec" for call in calls) == before
    invalid = json.loads(receipts[nodes[4]["Id"]])
    invalid["observed_source_address"] = "192.0.2.1"
    receipts[nodes[4]["Id"]] = json.dumps(invalid).encode()
    monitor.refresh("office")
    second = next(
        row for row in monitor.topology()["nodes"] if row["service"] == "office-workstation"
    )["client_status"]
    assert not second["available"] and second["operation_count"] is None
    assert "endpoints" in second["error"] and monitor.snapshot("office")["available"]
