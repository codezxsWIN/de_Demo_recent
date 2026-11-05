"""Offline wire-level proofs for the optional live-demo containers."""

import ipaddress
import json
import os
import socket
import struct
import threading
import time
from contextlib import contextmanager, suppress
from pathlib import Path

import pytest
import yaml

from labs.service_networks import clients

LAB = Path(__file__).resolve().parents[1] / "labs" / "service_networks"
TOPIC = b"vulnassess/training/telemetry"
SOCKET_METHODS = {
    name: getattr(socket.socket, name)
    for name in ("bind", "connect", "connect_ex", "send", "sendall", "sendto")
}
CREATE_CONNECTION = socket.create_connection
GETADDRINFO = socket.getaddrinfo


@pytest.fixture(autouse=True)
def offline_transport_guard(monkeypatch):
    """Match the lab runtime tests: real loopback peers, no external network."""

    def check(address):
        assert ipaddress.ip_address(address[0]).is_loopback, address

    for name, original in SOCKET_METHODS.items():

        def local(wire, *args, _name=name, _original=original, **kwargs):
            if wire.family in (socket.AF_INET, socket.AF_INET6):
                if _name in ("bind", "connect", "connect_ex"):
                    check(args[0])
                elif _name == "sendto":
                    check(args[-1])
                else:
                    check(wire.getpeername())
            return _original(wire, *args, **kwargs)

        monkeypatch.setattr(socket.socket, name, local)

    def connect(address, *args, **kwargs):
        check(address)
        return CREATE_CONNECTION(address, *args, **kwargs)

    def resolve(host, *args, **kwargs):
        assert ipaddress.ip_address(host).is_loopback
        return GETADDRINFO(host, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)


@contextmanager
def tcp_peer(handler, connections=1):
    """A real local TCP peer; surface assertions made inside its worker."""
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(4)

        def serve():
            try:
                for index in range(connections):
                    wire, _ = listener.accept()
                    with wire:
                        wire.settimeout(3)
                        handler(wire, index)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield listener.getsockname()
        finally:
            worker.join(5)
            assert not worker.is_alive(), "TCP test peer did not finish"
            if errors:
                raise errors[0]


def exact(wire, count):
    result = b""
    while len(result) < count:
        chunk = wire.recv(count - len(result))
        assert chunk, "client closed an incomplete packet"
        result += chunk
    return result


def peer_packet(wire):
    """Small independent MQTT decoder for inspecting the client's real bytes."""
    header = exact(wire, 1)[0]
    length, factor = 0, 1
    for _ in range(4):
        byte = exact(wire, 1)[0]
        length += (byte & 127) * factor
        if byte < 128:
            return header, exact(wire, length)
        factor *= 128
    pytest.fail("client wrote invalid MQTT length")


def peer_send(wire, header, body):
    length = len(body)
    encoded = []
    while length >= 128:
        encoded.append((length % 128) | 128)
        length //= 128
    wire.sendall(bytes([header, *encoded, length]) + body)


def accept_mqtt(wire):
    header, body = peer_packet(wire)
    assert header == 0x10
    assert body[:10] == b"\x00\x04MQTT\x04\x02\x00\x0a"
    assert int.from_bytes(body[10:12], "big") == len(body[12:])
    assert body[12:].startswith((b"iot-sensor-", b"iot-dashboard-"))
    # Exercise fragmented CONNACK over TCP rather than a socket mock.
    for part in (b"\x20", b"\x02\x00", b"\x00"):
        wire.sendall(part)
        time.sleep(0.005)


def reading(sequence=1):
    return {
        "device": "training-sensor-01",
        "source": "simulated sensor",
        "sequence": sequence,
        "temperature_c": 21.4,
        "humidity_pct": 42,
        "sent_at": "2026-11-01T12:00:00+00:00",
    }


def publication(data):
    return struct.pack("!H", len(TOPIC)) + TOPIC + json.dumps(data).encode()


def await_status(path, predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data = clients.read_status(path)
            if predicate(data):
                return data
        except FileNotFoundError:
            pass
        time.sleep(0.01)
    pytest.fail(f"status did not reach the expected state: {path}")


@contextmanager
def running_client(role, path):
    stop = threading.Event()
    errors = []

    def work():
        try:
            clients.run(role, stop, path)
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    try:
        yield stop
    finally:
        stop.set()
        worker.join(4)
        assert not worker.is_alive(), "client did not honor stop within its I/O bounds"
        if errors:
            raise errors[0]


def point_at_peer(monkeypatch, role, address):
    source, _, _ = clients.ENDPOINTS[role]
    monkeypatch.setitem(clients.ENDPOINTS, role, (source, *address))


def test_mqtt_fragmentation_and_coalesced_frames():
    left, right = socket.socketpair()
    with left, right:
        payload = b"x" * 300
        fragments = [b"\x30", b"\xac", b"\x02", payload[:8], payload[8:], b"\xd0\x00"]

        def feed():
            for part in fragments:
                right.sendall(part)
                time.sleep(0.005)

        feeder = threading.Thread(target=feed)
        feeder.start()
        assert clients.read_packet(left) == (0x30, payload)
        assert clients.read_packet(left) == (0xD0, b"")
        feeder.join(1)


@pytest.mark.parametrize(
    "frame",
    [
        b"\x00\x00",
        b"\xf0\x00",
        b"\x30\xff\x7f",
        b"\x30\x80\x80\x80\x80",
        b"\x30\x80\x00",
    ],
)
def test_malformed_or_oversized_mqtt_frames_fail_before_body(frame):
    left, right = socket.socketpair()
    with left, right:
        right.sendall(frame)
        with pytest.raises(ValueError):
            clients.read_packet(left)


def test_truncated_mqtt_frame_is_not_counted_as_a_packet():
    left, right = socket.socketpair()
    with left, right:
        right.sendall(b"\x30\x03ab")
        right.shutdown(socket.SHUT_WR)
        with pytest.raises(ConnectionError, match="partial frame"):
            clients.read_packet(left)


def test_frame_deadline_applies_across_slow_fragments(monkeypatch):
    monkeypatch.setattr(clients, "FRAME_TIMEOUT", 0.09)
    left, right = socket.socketpair()
    with left, right:

        def drip():
            with suppress(OSError):
                for part in (b"\x30", b"\x03", b"a", b"b", b"c"):
                    right.sendall(part)
                    time.sleep(0.04)

        feeder = threading.Thread(target=drip)
        feeder.start()
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            clients.read_packet(left)
        assert time.monotonic() - started < 0.3
        feeder.join(1)


def test_mqtt_sender_enforces_total_frame_limit():
    left, right = socket.socketpair()
    with left, right:
        with pytest.raises(ValueError, match="bound"):
            clients.send_packet(left, 0x30, b"x" * clients.MAX_FRAME)
        clients.send_packet(left, 0x30, b"x" * 300)
        assert peer_packet(right) == (0x30, b"x" * 300)


@pytest.mark.parametrize(
    "change",
    [
        {"source": "real sensor"},
        {"device": "outside-device"},
        {"sequence": True},
        {"sequence": -1},
        {"temperature_c": float("nan")},
        {"humidity_pct": 150},
        {"humidity_pct": False},
        {"sent_at": "2026-11-01T12:00:00"},
        {"sent_at": "garbage"},
        {"unexpected": "private data"},
    ],
)
def test_dashboard_rejects_unexpected_sensor_data(change):
    data = reading() | change
    with pytest.raises(ValueError):
        clients.parse_reading(0x30, publication(data))


@pytest.mark.parametrize(
    "header,body",
    [
        (0x32, publication(reading())),
        (0x38, publication(reading())),
        (0x30, b"\xff\xffbad"),
        (0x30, b"\x00\x03bad{}"),
        (0x30, struct.pack("!H", len(TOPIC)) + TOPIC + b"[" * 2000),
    ],
)
def test_dashboard_rejects_invalid_publication_shapes(header, body):
    with pytest.raises(ValueError):
        clients.parse_reading(header, body)


def test_sensor_sends_real_qos1_publication_and_counts_only_puback(tmp_path, monkeypatch):
    path = tmp_path / "client-status.json"
    sent = threading.Event()
    release = threading.Event()

    def broker(wire, _):
        accept_mqtt(wire)
        header, body = peer_packet(wire)
        assert header == 0x32  # PUBLISH, QoS 1, no retained state.
        topic_size = int.from_bytes(body[:2], "big")
        assert body[2 : 2 + topic_size] == TOPIC
        packet_id = body[2 + topic_size : 4 + topic_size]
        data = json.loads(body[4 + topic_size :])
        assert data["source"] == "simulated sensor"
        assert data["device"] == "training-sensor-01"
        assert data["sequence"] == 1
        sent.set()
        assert release.wait(2)
        wire.sendall(b"\x40\x02" + packet_id)
        assert peer_packet(wire) == (0xE0, b"")

    with tcp_peer(broker) as address:
        point_at_peer(monkeypatch, "iot-sensor", address)
        with running_client("iot-sensor", path):
            assert sent.wait(2)
            assert clients.read_status(path)["operation_count"] == 0
            release.set()
            data = await_status(path, lambda d: d["operation_count"] == 1)
            assert data["last_success"]
            assert data["latest_sensor_data"]["sequence"] == 1
            assert data["observed_source_address"] == "127.0.0.1"
    assert clients.read_status(path)["state"] == "stopped"


def test_dashboard_receives_multiple_messages_on_one_subscription(tmp_path, monkeypatch):
    path = tmp_path / "client-status.json"

    def broker(wire, _):
        accept_mqtt(wire)
        assert peer_packet(wire) == (
            0x82,
            b"\x00\x01" + struct.pack("!H", len(TOPIC)) + TOPIC + b"\x00",
        )
        wire.sendall(b"\x90\x03\x00\x01\x00")
        for number in (1, 2):
            peer_send(wire, 0x30, publication(reading(number)))
        assert peer_packet(wire) == (0xE0, b"")

    with tcp_peer(broker) as address:
        point_at_peer(monkeypatch, "iot-dashboard", address)
        with running_client("iot-dashboard", path):
            data = await_status(path, lambda d: d["operation_count"] == 2)
            assert data["latest_sensor_data"] == reading(2)
            assert data["source_address"] == "172.30.42.6"


def test_subscriber_handles_retained_message_before_suback(tmp_path, monkeypatch):
    path = tmp_path / "client-status.json"

    def broker(wire, _):
        accept_mqtt(wire)
        assert peer_packet(wire)[0] == 0x82
        peer_send(wire, 0x31, publication(reading()))
        wire.sendall(b"\x90\x03\x00\x01\x00")
        assert peer_packet(wire) == (0xE0, b"")

    with tcp_peer(broker) as address:
        point_at_peer(monkeypatch, "iot-dashboard", address)
        with running_client("iot-dashboard", path):
            await_status(path, lambda d: d["state"] == "waiting" and d["operation_count"] == 1)


def test_reconnect_after_explicit_policy_denial_preserves_failure_history(tmp_path, monkeypatch):
    path = tmp_path / "client-status.json"
    monkeypatch.setattr(clients, "RECONNECT_DELAY", 1)
    monkeypatch.setattr(clients, "HEARTBEAT_INTERVAL", 0.02)

    def broker(wire, index):
        if index == 0:
            assert peer_packet(wire)[0] == 0x10
            wire.sendall(b"\x20\x02\x00\x05")
            return
        accept_mqtt(wire)
        assert peer_packet(wire)[0] == 0x82
        wire.sendall(b"\x90\x03\x00\x01\x00")
        peer_send(wire, 0x30, publication(reading(7)))
        assert peer_packet(wire) == (0xE0, b"")

    with tcp_peer(broker, connections=2) as address:
        point_at_peer(monkeypatch, "iot-dashboard", address)
        with running_client("iot-dashboard", path):
            first = await_status(path, lambda d: d["state"] == "policy_blocked")
            assert first["last_failure"] and first["last_success"] is None
            assert clients.status_is_fresh(path)
            second = await_status(
                path,
                lambda d: (
                    d["heartbeat_at"] > first["heartbeat_at"] and d["state"] == "policy_blocked"
                ),
                timeout=0.75,
            )
            assert second["heartbeat_at"] > first["heartbeat_at"]
            assert second["operation_count"] == 0
            final = await_status(path, lambda d: d["operation_count"] == 1)
            assert final["last_failure"] == first["last_failure"]
            assert final["last_error"] is None
            assert final["latest_sensor_data"]["sequence"] == 7


def test_reconnect_after_transport_eof(tmp_path, monkeypatch):
    path = tmp_path / "client-status.json"
    monkeypatch.setattr(clients, "RECONNECT_DELAY", 0.05)

    def broker(wire, index):
        accept_mqtt(wire)
        assert peer_packet(wire)[0] == 0x82
        wire.sendall(b"\x90\x03\x00\x01\x00")
        if index == 0:
            return
        peer_send(wire, 0x30, publication(reading(9)))
        assert peer_packet(wire) == (0xE0, b"")

    with tcp_peer(broker, connections=2) as address:
        point_at_peer(monkeypatch, "iot-dashboard", address)
        with running_client("iot-dashboard", path):
            data = await_status(path, lambda d: d["operation_count"] == 1)
            assert data["last_failure"]
            assert data["latest_sensor_data"]["sequence"] == 9


def test_idle_dashboard_keeps_subscription_alive_with_pingresp(tmp_path, monkeypatch):
    path = tmp_path / "client-status.json"
    monkeypatch.setattr(clients, "PING_INTERVAL", 0.03)

    def broker(wire, _):
        accept_mqtt(wire)
        assert peer_packet(wire)[0] == 0x82
        wire.sendall(b"\x90\x03\x00\x01\x00")
        assert peer_packet(wire) == (0xC0, b"")
        wire.sendall(b"\xd0\x00")
        peer_send(wire, 0x30, publication(reading()))
        assert peer_packet(wire) == (0xE0, b"")

    with tcp_peer(broker) as address:
        point_at_peer(monkeypatch, "iot-dashboard", address)
        with running_client("iot-dashboard", path):
            data = await_status(path, lambda d: d["operation_count"] == 1)
            assert data["last_failure"] is None


def test_dashboard_reconnects_when_broker_stops_answering_pings(tmp_path, monkeypatch):
    path = tmp_path / "client-status.json"
    monkeypatch.setattr(clients, "PING_INTERVAL", 0.02)
    monkeypatch.setattr(clients, "FRAME_TIMEOUT", 0.08)
    monkeypatch.setattr(clients, "RECONNECT_DELAY", 0.02)

    def broker(wire, index):
        accept_mqtt(wire)
        assert peer_packet(wire)[0] == 0x82
        wire.sendall(b"\x90\x03\x00\x01\x00")
        if index == 0:
            assert peer_packet(wire) == (0xC0, b"")
            # Ignore PINGREQ. The client must close and establish a new session.
            assert peer_packet(wire) == (0xE0, b"")
        else:
            peer_send(wire, 0x30, publication(reading()))
            # The main test polls the status file before asking the client to
            # stop. A valid keepalive can arrive during that scheduling gap.
            # Answer it while still requiring a bounded graceful disconnect.
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                packet = peer_packet(wire)
                if packet == (0xE0, b""):
                    break
                assert packet == (0xC0, b"")
                peer_send(wire, 0xD0, b"")
            else:
                pytest.fail("reconnected client did not disconnect after stop")

    with tcp_peer(broker, connections=2) as address:
        point_at_peer(monkeypatch, "iot-dashboard", address)
        with running_client("iot-dashboard", path):
            data = await_status(path, lambda d: d["operation_count"] == 1)
            assert data["last_failure"]


def test_rejected_subscription_is_policy_blocked(tmp_path, monkeypatch):
    path = tmp_path / "client-status.json"

    def broker(wire, _):
        accept_mqtt(wire)
        assert peer_packet(wire)[0] == 0x82
        wire.sendall(b"\x90\x03\x00\x01\x80")
        assert peer_packet(wire) == (0xE0, b"")

    with tcp_peer(broker) as address:
        point_at_peer(monkeypatch, "iot-dashboard", address)
        with running_client("iot-dashboard", path):
            data = await_status(path, lambda d: d["state"] == "policy_blocked")
            assert data["operation_count"] == 0


def test_wrong_puback_does_not_claim_success(tmp_path, monkeypatch):
    path = tmp_path / "client-status.json"

    def broker(wire, _):
        accept_mqtt(wire)
        assert peer_packet(wire)[0] == 0x32
        wire.sendall(b"\x40\x02\xff\xff")
        assert peer_packet(wire) == (0xE0, b"")

    with tcp_peer(broker) as address:
        point_at_peer(monkeypatch, "iot-sensor", address)
        with running_client("iot-sensor", path):
            data = await_status(path, lambda d: d["state"] == "disconnected")
            assert data["operation_count"] == 0
            assert data["last_success"] is None
            assert "PUBACK" in data["last_error"]


def test_status_is_atomic_and_bounded(tmp_path):
    path = tmp_path / "client-status.json"
    status = clients.Status("office-workstation", path)
    status.update()
    old_inode = path.stat().st_ino
    # A replacement inode proves publication uses rename instead of truncating
    # the live file. This also works on Windows, where open files block rename.
    status.success(bytes_received=42)
    assert path.stat().st_ino != old_inode
    new = clients.read_status(path)
    assert new["operation_count"] == 1
    assert new["role"] == "office-workstation"
    assert new["container_hostname"]
    assert "container_id" in new
    assert new["destination"]["address"] == "172.30.41.3"
    assert not path.with_suffix(".tmp").exists()
    with pytest.raises(ValueError, match="bound"):
        status.update(last_error="x" * clients.MAX_STATUS)
    assert clients.read_status(path) == new


@contextmanager
def windows_file_lock(path):
    """An actual exclusive OS handle, not a mocked permission exception."""
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)
    assert handle != wintypes.HANDLE(-1).value, ctypes.get_last_error()
    try:
        yield
    finally:
        assert kernel.CloseHandle(handle), ctypes.get_last_error()


@pytest.mark.skipif(os.name != "nt", reason="Windows file sharing semantics")
@pytest.mark.parametrize("operation", ["read", "replace"])
def test_status_io_recovers_after_real_windows_sharing_lock(tmp_path, operation):
    path = tmp_path / "client-status.json"
    status = clients.Status("iot-sensor", path)
    status.update()
    errors = []
    entered = threading.Event()

    def work():
        try:
            entered.set()
            if operation == "read":
                assert clients.read_status(path)["role"] == "iot-sensor"
            else:
                status.success()
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=work, daemon=True)
    with windows_file_lock(path):
        worker.start()
        assert entered.wait(1)
        time.sleep(0.03)
        assert worker.is_alive(), "status I/O did not wait for the sharing lock"
    worker.join(2)
    assert not worker.is_alive()
    assert not errors
    assert clients.read_status(path)["operation_count"] == (1 if operation == "replace" else 0)
    assert not path.with_suffix(".tmp").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows file sharing semantics")
@pytest.mark.parametrize("operation", ["read", "replace"])
def test_status_io_surfaces_persistent_windows_access_failure(tmp_path, operation):
    path = tmp_path / "client-status.json"
    status = clients.Status("iot-sensor", path)
    status.update()
    previous = clients.read_status(path)
    with windows_file_lock(path):
        started = time.monotonic()
        with pytest.raises(PermissionError):
            if operation == "read":
                clients.read_status(path)
            else:
                status.success()
        assert time.monotonic() - started < 2
        assert not clients.status_is_fresh(path)
    assert clients.read_status(path) == previous
    assert not path.with_suffix(".tmp").exists()


def test_status_reader_surfaces_malformed_and_oversized_receipts(tmp_path):
    path = tmp_path / "client-status.json"
    path.write_bytes(b'{"operation_count":')
    with pytest.raises(json.JSONDecodeError):
        clients.read_status(path)
    path.write_text(json.dumps({"padding": "x" * clients.MAX_STATUS}))
    with pytest.raises(ValueError, match="bound"):
        clients.read_status(path)


@pytest.mark.parametrize(
    "receipt,healthy",
    [
        ({"heartbeat_at": 95, "state": "running"}, True),
        ({"heartbeat_at": 95, "state": "policy_blocked", "last_success": None}, True),
        ({"heartbeat_at": 95, "state": "disconnected"}, True),
        ({"heartbeat_at": 80}, False),
        ({"heartbeat_at": 101}, False),
        ({"heartbeat_at": 95, "state": "stopped"}, False),
        ({"heartbeat_at": float("nan")}, False),
        ({"heartbeat_at": True}, False),
        ({"updated_at": "1970-01-01T00:01:35+00:00"}, True),
        ({"updated_at": "1970-01-01T00:01:35"}, False),
        ({"last_success": 99}, False),
        ({}, False),
        ([], False),
    ],
)
def test_health_measures_recent_process_heartbeat(tmp_path, receipt, healthy):
    path = tmp_path / "status.json"
    path.write_text(json.dumps(receipt))
    assert clients.status_is_fresh(path, now=100) is healthy


def test_health_rejects_missing_partial_and_oversized_receipts(tmp_path):
    path = tmp_path / "status.json"
    assert not clients.status_is_fresh(path)
    for raw in (b"{", b"x" * (clients.MAX_HEALTH_STATUS + 1), b"\xff"):
        path.write_bytes(raw)
        assert not clients.status_is_fresh(path)


def test_observer_health_allows_packet_metadata_and_checks_running_state(tmp_path):
    path = tmp_path / "status.json"
    receipt = {
        "updated_at": clients.timestamp(),
        "running": True,
        "packets": [{"payload_summary": "fictional packet" * 10} for _ in range(400)],
    }
    path.write_text(json.dumps(receipt))
    assert clients.MAX_STATUS < path.stat().st_size < clients.MAX_HEALTH_STATUS
    assert clients.status_is_fresh(path)
    receipt["running"] = False
    path.write_text(json.dumps(receipt))
    assert not clients.status_is_fresh(path)


@pytest.mark.parametrize("oversized", [False, True])
def test_ftp_reads_only_bounded_fictional_file_through_control_and_data(
    tmp_path, monkeypatch, oversized
):
    path = tmp_path / "client-status.json"
    commands = []
    content = (
        b"x" * (clients.MAX_FILE + 1) if oversized else b"Fictional office training document.\n"
    )
    with socket.socket() as data_listener:
        data_listener.bind(("127.0.0.1", 0))
        data_listener.listen(1)
        data_listener.settimeout(2)
        passive_port = data_listener.getsockname()[1]
        monkeypatch.setattr(clients, "PASSIVE_PORTS", (passive_port,))

        def ftp_server(wire, _):
            wire.sendall(b"220 Fictional training FTP\r\n")
            stream = wire.makefile("rb")
            with stream:
                while True:
                    line = stream.readline(1024).decode().strip()
                    commands.append(line)
                    if line == "USER anonymous":
                        wire.sendall(b"331 Fictional guest\r\n")
                    elif line == "PASS training@example.invalid":
                        wire.sendall(b"230 Guest read allowed\r\n")
                    elif line == "TYPE I":
                        wire.sendall(b"200 Binary\r\n")
                    elif line == "PASV":
                        wire.sendall(
                            f"227 Passive (127,0,0,1,{passive_port // 256},{passive_port % 256})\r\n".encode()
                        )
                    elif line == "RETR network-proof.txt":
                        wire.sendall(b"150 Training file\r\n")
                        data, _ = data_listener.accept()
                        with data:
                            data.sendall(content)
                        wire.sendall(b"226 Read complete\r\n")
                    elif line == "QUIT":
                        wire.sendall(b"221 Goodbye\r\n")
                        break
                    else:
                        pytest.fail(f"Unexpected FTP command: {line}")

        with tcp_peer(ftp_server) as address:
            point_at_peer(monkeypatch, "office-workstation", address)
            status = clients.Status("office-workstation", path)
            if oversized:
                with pytest.raises(ValueError, match="document exceeds"):
                    clients.retrieve_proof(status, threading.Event())
            else:
                clients.retrieve_proof(status, threading.Event())
    receipt = clients.read_status(path)
    assert receipt["operation_count"] == (0 if oversized else 1)
    if not oversized:
        assert receipt["bytes_received"] == len(content)
    assert commands == [
        "USER anonymous",
        "PASS training@example.invalid",
        "TYPE I",
        "PASV",
        "RETR network-proof.txt",
        "QUIT",
    ]


def test_ftp_refusal_is_explicit_policy_state(tmp_path, monkeypatch):
    def server(wire, _):
        wire.sendall(b"220 Training\r\n")
        stream = wire.makefile("rb")
        with stream:
            assert stream.readline().startswith(b"USER anonymous")
            wire.sendall(b"530 Anonymous login blocked\r\n")
            assert stream.readline() == b"QUIT\r\n"
            wire.sendall(b"221 Goodbye\r\n")

    path = tmp_path / "client-status.json"
    with tcp_peer(server) as address:
        point_at_peer(monkeypatch, "office-workstation", address)
        with running_client("office-workstation", path):
            data = await_status(path, lambda d: d["state"] == "policy_blocked")
            assert data["operation_count"] == 0
            assert clients.status_is_fresh(path)


def test_ftp_bounds_multiline_replies():
    left, right = socket.socketpair()
    with left, right:
        ftp = clients.BoundedFTP(threading.Event())
        ftp.sock = left
        right.sendall(b"220-Start\r\n" + b"continued\r\n" * 15)
        with pytest.raises(ValueError, match="multiline"):
            ftp.getmultiline()
        ftp.sock = None


def test_ftp_deadline_applies_to_a_slow_control_reply():
    left, right = socket.socketpair()
    with left, right:
        ftp = clients.BoundedFTP(threading.Event())
        ftp.sock = left
        ftp.deadline = time.monotonic() + 0.09

        def drip():
            with suppress(OSError):
                for part in (b"2", b"2", b"0", b" ", b"\n"):
                    right.sendall(part)
                    time.sleep(0.04)

        feeder = threading.Thread(target=drip)
        feeder.start()
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            ftp.getline()
        assert time.monotonic() - started < 0.3
        ftp.sock = None
        feeder.join(1)


def test_ftp_refuses_a_passive_port_outside_the_gateway_range(tmp_path, monkeypatch):
    def server(wire, _):
        wire.sendall(b"220 Fictional training FTP\r\n")
        with wire.makefile("rb") as stream:
            assert stream.readline() == b"USER anonymous\r\n"
            wire.sendall(b"230 Anonymous read\r\n")
            assert stream.readline() == b"TYPE I\r\n"
            wire.sendall(b"200 Binary\r\n")
            assert stream.readline() == b"PASV\r\n"
            wire.sendall(b"227 Passive (127,0,0,1,0,1)\r\n")
            assert stream.readline() == b"QUIT\r\n"
            wire.sendall(b"221 Goodbye\r\n")

    path = tmp_path / "status.json"
    with tcp_peer(server) as address:
        point_at_peer(monkeypatch, "office-workstation", address)
        status = clients.Status("office-workstation", path)
        with pytest.raises(ValueError, match="outside the fixed gateway range"):
            clients.retrieve_proof(status, threading.Event())
    assert clients.read_status(path)["operation_count"] == 0


def test_live_override_preserves_base_and_internal_network_boundaries():
    base = yaml.safe_load((LAB / "compose.yaml").read_text())
    live = yaml.safe_load((LAB / "live.compose.yaml").read_text())
    expected_clients = {
        "office-workstation": ("office", "172.30.41.5"),
        "iot-sensor": ("iot", "172.30.42.5"),
        "iot-dashboard": ("iot", "172.30.42.6"),
    }
    assert set(base["services"]) == {
        "office",
        "office-gateway",
        "office-redis",
        "iot",
        "iot-gateway",
        "iot-redis",
    }
    assert set(live["services"]) == set(expected_clients) | {"office-capture", "iot-capture"}
    assert not set(base["services"]) & set(live["services"])
    assert "networks" not in live  # inherit the original subnet and internal flag
    assigned = {}
    for name, service in {**base["services"], **live["services"]}.items():
        for network, config in service.get("networks", {}).items():
            address = config["ipv4_address"]
            assert address not in assigned
            assigned[address] = name
            subnet = base["networks"][network]["ipam"]["config"][0]["subnet"]
            assert ipaddress.ip_address(address) in ipaddress.ip_network(subnet)
    for name, (network, address) in expected_clients.items():
        service = live["services"][name]
        assert service["networks"] == {network: {"ipv4_address": address}}
        assert base["networks"][network]["internal"] is True
        assert service["user"] == "10001:10001"
        assert service["entrypoint"] == ["python", "-m", "labs.service_networks.clients"]
        assert service["command"] == [name]
        assert "cap_add" not in service
        assert "volumes" not in service
        assert service["depends_on"] == {network + "-gateway": {"condition": "service_healthy"}}
        assert service["healthcheck"]["test"][-1] == "/runtime/client-status.json"
        source, target, _ = clients.ENDPOINTS[name]
        assert source == address
        assert target == base["services"][network + "-gateway"]["networks"][network]["ipv4_address"]


def test_observers_have_only_raw_socket_capability_and_dedicated_capture_storage():
    live = yaml.safe_load((LAB / "live.compose.yaml").read_text())
    assert set(live["volumes"]) == {"office-capture", "iot-capture"}
    for name, service in live["services"].items():
        assert service["image"] == "vulnassess-service-networks:local"
        assert service["build"] == "."
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["pids_limit"] <= 96
        assert service["mem_limit"] == service["memswap_limit"] == "96m"
        assert 0 < service["cpus"] <= 1
        assert all("size=" in mount and "noexec" in mount for mount in service["tmpfs"])
        assert not any(key in service for key in ("ports", "privileged", "devices", "pid", "ipc"))
        assert not any("docker.sock" in str(value) for value in service.values())
        if not name.endswith("-capture"):
            continue
        environment = name.split("-")[0]
        assert service["user"] == "0:0"
        assert service["cap_add"] == ["NET_RAW"]
        assert service["network_mode"] == "service:" + environment + "-gateway"
        assert "networks" not in service
        assert service["depends_on"] == {environment + "-gateway": {"condition": "service_healthy"}}
        assert service["entrypoint"] == ["python", "-m", "labs.service_networks.traffic_capture"]
        assert service["command"] == [environment]
        assert service["volumes"] == [name + ":/capture"]
        assert service["healthcheck"]["test"][-1] == "/capture/status.json"
