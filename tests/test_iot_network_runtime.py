"""Protocol proofs against actual loopback listeners, with no mock transports."""

import asyncio
import ipaddress
import os
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from labs.service_networks import iot

_SOCKET_METHODS = {
    name: getattr(socket.socket, name)
    for name in ("bind", "connect", "connect_ex", "send", "sendall", "sendto")
}
_CREATE_CONNECTION = socket.create_connection
_GETADDRINFO = socket.getaddrinfo
runtime = pytest.mark.skipif(
    os.environ.get("VULNASSESS_NETWORK_LABS") != "1",
    reason="Set VULNASSESS_NETWORK_LABS=1 to bind the fixed IoT lab ports",
)


@pytest.fixture(autouse=True)
def offline_transport_guard(monkeypatch):
    """Allow loopback traffic only, including asyncio's internal socketpair."""

    def check(address):
        assert ipaddress.ip_address(address[0]).is_loopback, address

    for name, original in _SOCKET_METHODS.items():

        def local(sock, *args, _name=name, _original=original, **kwargs):
            if sock.family in (socket.AF_INET, socket.AF_INET6):
                if _name in ("bind", "connect", "connect_ex"):
                    check(args[0])
                elif _name == "sendto":
                    check(args[-1])
                else:
                    check(sock.getpeername())
            return _original(sock, *args, **kwargs)

        monkeypatch.setattr(socket.socket, name, local)

    def connect(address, *args, **kwargs):
        check(address)
        return _CREATE_CONNECTION(address, *args, **kwargs)

    def resolve(host, *args, **kwargs):
        assert ipaddress.ip_address(host).is_loopback
        return _GETADDRINFO(host, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)


@pytest.fixture
def dependencies():
    for package in ("amqtt", "pysnmp", "cryptography"):
        pytest.importorskip(package)


def _string(value):
    data = value.encode() if isinstance(value, str) else value
    return len(data).to_bytes(2, "big") + data


def _packet(header, body):
    length = len(body)
    encoded = bytearray([header])
    while True:
        digit = length % 128
        length //= 128
        encoded.append(digit | (128 if length else 0))
        if not length:
            return bytes(encoded) + body


async def _read(reader):
    async with asyncio.timeout(3):
        header = (await reader.readexactly(1))[0]
        length = 0
        for index in range(4):
            digit = (await reader.readexactly(1))[0]
            length += (digit & 127) << (index * 7)
            if not digit & 128:
                return header, await reader.readexactly(length)
        raise AssertionError("invalid MQTT remaining length")


async def _connect(port=1883, *, context=None, username=None, will_topic=None):
    reader, writer = await asyncio.open_connection(iot.HOST, port, ssl=context)
    flags = 2 | (128 if username else 0) | (4 if will_topic else 0)
    body = _string("MQTT") + bytes([4, flags, 0, 30]) + _string("vulnassess-proof")
    if will_topic:
        body += _string(will_topic) + _string("fictional-last-will")
    if username:
        body += _string(username)
    writer.write(_packet(0x10, body))
    await writer.drain()
    try:
        ack = await _read(reader)
    except BaseException:
        writer.close()
        await writer.wait_closed()
        raise
    return reader, writer, ack


async def _close(writer):
    writer.write(b"\xe0\x00")
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def _subscribe(reader, writer, topic, packet_id=1):
    writer.write(_packet(0x82, packet_id.to_bytes(2, "big") + _string(topic) + b"\x00"))
    await writer.drain()
    header, body = await _read(reader)
    assert header == 0x90
    assert body[:2] == packet_id.to_bytes(2, "big")
    return body[2]


def _publish_value(packet):
    header, body = packet
    assert header >> 4 == 3
    length = int.from_bytes(body[:2], "big")
    return body[2 : 2 + length].decode(), body[2 + length :]


def test_import_without_optional_packages():
    result = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            "from labs.service_networks import iot; import sys; "
            "assert not any(p in sys.modules for p in ('amqtt', 'pysnmp', 'cryptography'))",
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


@runtime
def test_mqtt_real_message_flow_retained_fixture_and_acl(tmp_path, dependencies):
    async def exercise():
        async with iot.start(tmp_path) as services:
            assert {(s["transport"], s["port"]) for s in services} == {
                ("tcp", 1883),
                ("tcp", 1884),
                ("tcp", 8883),
                ("udp", 1161),
                ("udp", 1162),
            }
            assert all(s["host"] == "127.0.0.3" for s in services)
            reader, writer, ack = await _connect()
            try:
                assert ack == (0x20, b"\x00\x00")
                assert await _subscribe(reader, writer, iot.TOPIC) == 0
                assert _publish_value(await _read(reader)) == (iot.TOPIC, iot.PAYLOAD)
                nonce = b"fictional-probe-unique-82910"
                writer.write(_packet(0x30, _string(iot.TOPIC) + nonce))
                await writer.drain()
                assert _publish_value(await _read(reader)) == (iot.TOPIC, nonce)
                for topic in (
                    "#",
                    "other/topic",
                    "vulnassess/training-escape/#",
                    "vulnassess/training/#",
                    "vulnassess/training/arbitrary",
                ):
                    assert await _subscribe(reader, writer, topic) == 0x80
                # Publish outside the namespace, then a valid barrier message.
                # A forbidden retained publish must not appear after subscribing.
                writer.write(_packet(0x31, _string("other/topic") + b"forbidden"))
                writer.write(_packet(0x30, _string(iot.TOPIC) + b"barrier"))
                await writer.drain()
                assert _publish_value(await _read(reader)) == (iot.TOPIC, b"barrier")
            finally:
                await _close(writer)
            # The nonce was non-retained: a new connection gets the fixture.
            reader, writer, ack = await _connect()
            try:
                assert ack == (0x20, b"\x00\x00")
                assert await _subscribe(reader, writer, iot.TOPIC) == 0
                assert _publish_value(await _read(reader)) == (iot.TOPIC, iot.PAYLOAD)
            finally:
                await _close(writer)

    asyncio.run(exercise())


@runtime
def test_mqtt_protected_returns_not_authorized_promptly(tmp_path, dependencies):
    async def exercise():
        async with iot.start(tmp_path):
            for username in (None, "admin"):
                reader, writer, ack = await _connect(1884, username=username)
                try:
                    assert ack == (0x20, b"\x00\x05")
                    assert await asyncio.wait_for(reader.read(), 1) == b""
                finally:
                    writer.close()
                    await writer.wait_closed()

    asyncio.run(exercise())


@runtime
def test_mqtt_refuses_last_will_outside_training_namespace(tmp_path, dependencies):
    async def exercise():
        async with iot.start(tmp_path):
            for topic in ("outside/training", "vulnassess/training/#"):
                reader, writer, ack = await _connect(will_topic=topic)
                try:
                    assert ack == (0x20, b"\x00\x05")
                    assert await asyncio.wait_for(reader.read(), 1) == b""
                finally:
                    writer.close()
                    await writer.wait_closed()

    asyncio.run(exercise())


@runtime
def test_tls_serves_expired_self_signed_cert_and_real_mqtt(tmp_path, dependencies):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    async def exercise():
        async with iot.start(tmp_path) as services:
            certfile = Path(next(s["certfile"] for s in services if s["port"] == 8883))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            reader, writer, ack = await _connect(8883, context=context)
            try:
                assert ack == (0x20, b"\x00\x00")
                der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der)
                cert.verify_directly_issued_by(cert)
                assert cert.not_valid_after_utc < datetime.now(timezone.utc)
                assert cert.public_bytes(serialization.Encoding.PEM) == certfile.read_bytes()
                assert await _subscribe(reader, writer, iot.TOPIC) == 0
                assert _publish_value(await _read(reader)) == (iot.TOPIC, iot.PAYLOAD)
                writer.write(_packet(0x30, _string(iot.TOPIC) + b"tls-nonce"))
                await writer.drain()
                assert _publish_value(await _read(reader)) == (iot.TOPIC, b"tls-nonce")
            finally:
                await _close(writer)
            trusted = ssl.create_default_context(cafile=str(certfile))
            with pytest.raises(ssl.SSLCertVerificationError, match="expired"):
                await asyncio.open_connection(iot.HOST, 8883, ssl=trusted)

    asyncio.run(exercise())


async def _snmp(port, community, *, write=False):
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        OctetString,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
        set_cmd,
    )

    manager = SnmpEngine()
    try:
        target = await UdpTransportTarget.create((iot.HOST, port), timeout=0.3, retries=0)
        args = (
            [ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0"), OctetString("changed"))]
            if write
            else [ObjectType(ObjectIdentity(f"1.3.6.1.2.1.1.{i}.0")) for i in (1, 5)]
        )
        return await (set_cmd if write else get_cmd)(
            manager,
            CommunityData(community, mpModel=1),
            target,
            ContextData(),
            *args,
        )
    finally:
        manager.close_dispatcher()
        await asyncio.sleep(0)


@runtime
def test_snmp_public_get_private_get_public_timeout_and_read_only(tmp_path, dependencies):
    async def exercise():
        async with iot.start(tmp_path):
            for port, community in ((1161, "public"), (1162, iot.PRIVATE_COMMUNITY)):
                error, status, _, values = await _snmp(port, community)
                assert not error and not status
                assert [str(value) for _, value in values] == [iot.SYS_DESCR, iot.SYS_NAME]
                error, status, _, _ = await _snmp(port, community, write=True)
                assert not error and status
                error, status, _, values = await _snmp(port, community)
                assert not error and not status and str(values[1][1]) == iot.SYS_NAME
            error, status, _, _ = await _snmp(1162, "public")
            assert error and "timeout" in str(error).lower() and not status

    asyncio.run(exercise())


def _assert_rebindable():
    for kind, ports in (
        (socket.SOCK_STREAM, (1883, 1884, 8883)),
        (socket.SOCK_DGRAM, (1161, 1162)),
    ):
        for port in ports:
            with socket.socket(socket.AF_INET, kind) as sock:
                sock.bind((iot.HOST, port))


async def _assert_no_new_tasks(before):
    for _ in range(5):
        await asyncio.sleep(0)
    pending = asyncio.all_tasks() - before
    assert not pending, [(t.get_coro().__qualname__, repr(t)) for t in pending]


@runtime
def test_shutdown_closes_active_and_idle_clients_and_all_tasks(tmp_path, dependencies):
    async def exercise():
        before = asyncio.all_tasks()
        async with iot.start(tmp_path):
            _, active, ack = await _connect()
            assert ack == (0x20, b"\x00\x00")
            idle_reader, idle = await asyncio.open_connection(iot.HOST, 1883)
            await asyncio.sleep(0)
        try:
            assert await asyncio.wait_for(idle_reader.read(), 1) == b""
            _assert_rebindable()
            await _assert_no_new_tasks(before)
        finally:
            for writer in (active, idle):
                writer.close()
                await writer.wait_closed()

    asyncio.run(exercise())


@runtime
@pytest.mark.parametrize("kind,port", [(socket.SOCK_STREAM, 8883), (socket.SOCK_DGRAM, 1162)])
def test_partial_startup_failure_releases_prior_listeners_and_tasks(
    tmp_path, dependencies, kind, port
):
    async def exercise():
        before = asyncio.all_tasks()
        with socket.socket(socket.AF_INET, kind) as occupied:
            if sys.platform == "win32":
                occupied.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            occupied.bind((iot.HOST, port))
            if kind == socket.SOCK_STREAM:
                occupied.listen()
            with pytest.raises(Exception):
                async with iot.start(tmp_path):
                    pytest.fail("startup yielded despite an occupied listener")
        _assert_rebindable()
        await _assert_no_new_tasks(before)

    asyncio.run(exercise())


@runtime
@pytest.mark.parametrize("cancel", [False, True])
def test_exception_and_cancellation_cleanup_preserve_unrelated_tasks(
    tmp_path, dependencies, cancel
):
    async def exercise():
        unrelated = asyncio.create_task(asyncio.Event().wait())
        before = asyncio.all_tasks()
        entered = asyncio.Event()

        async def owner():
            async with iot.start(tmp_path):
                entered.set()
                if cancel:
                    await asyncio.Event().wait()
                raise ValueError("body failed")

        task = asyncio.create_task(owner())
        try:
            if cancel:
                await asyncio.wait_for(entered.wait(), 5)
                task.cancel()
            with pytest.raises(asyncio.CancelledError if cancel else ValueError):
                await task
            assert not unrelated.done()
            _assert_rebindable()
            await _assert_no_new_tasks(before)
        finally:
            unrelated.cancel()
            await asyncio.gather(unrelated, return_exceptions=True)

    asyncio.run(exercise())


def test_network_guard_blocks_external_addresses_and_wildcard_binds():
    with socket.socket() as sock:
        with pytest.raises(AssertionError):
            sock.connect(("192.0.2.1", 1883))
        with pytest.raises(AssertionError):
            sock.bind(("0.0.0.0", 1883))
    with pytest.raises(AssertionError):
        socket.getaddrinfo("192.0.2.1", 1883)


@pytest.mark.parametrize("data", [b"\x30\x05\x00\x01x", b"\x10\x80", b"\x82\xff\xff\xff\xff"])
def test_frame_gate_rejects_truncated_or_invalid_frames_without_sockets(data):
    async def exercise():
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        class Writer:
            closed = False

            def close(self):
                self.closed = True

        writer = Writer()
        stream = iot._BoundedMQTTStream(reader, writer)
        with pytest.raises(asyncio.IncompleteReadError):
            await asyncio.wait_for(stream.readexactly(1), 1)
        assert writer.closed
        with pytest.raises(asyncio.IncompleteReadError):
            await stream.readexactly(1)

    asyncio.run(exercise())


@runtime
def test_mqtt_adversarial_frames_and_retained_flood_in_subprocess(tmp_path, dependencies):
    # The timeout is outside the broker's event loop: even an EOF spin in the
    # parser cannot freeze pytest or leave a background child running.
    env = {**os.environ, "_VULNASSESS_IOT_ATTACK_CHILD": "1"}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(Path(__file__).resolve()),
            "-q",
            "-k",
            "test_mqtt_adversarial_child",
            "--basetemp",
            str(tmp_path / "child"),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=35,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert result.returncode == 0, result.stdout + result.stderr
    _assert_rebindable()


@runtime
@pytest.mark.skipif(
    os.environ.get("_VULNASSESS_IOT_ATTACK_CHILD") != "1",
    reason="Executed by the subprocess regression test",
)
def test_mqtt_adversarial_child(tmp_path, dependencies, monkeypatch):
    brokers = []
    broker_type = iot._broker_type()

    class ObservedBroker(broker_type):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            brokers.append(self)

    monkeypatch.setattr(iot, "_broker_type", lambda: ObservedBroker)
    monkeypatch.setattr(iot, "MQTT_READ_TIMEOUT", 0.4)

    async def echo():
        reader, writer, ack = await _connect()
        try:
            assert ack == (0x20, b"\x00\x00")
            topic = "vulnassess/training/assessment"
            assert await _subscribe(reader, writer, topic) == 0
            writer.write(_packet(0x30, _string(topic) + b"loop-still-alive"))
            await writer.drain()
            assert _publish_value(await _read(reader)) == (topic, b"loop-still-alive")
        finally:
            await _close(writer)

    async def attack(data, *, connected=True, eof=False):
        if connected:
            reader, writer, ack = await _connect()
            assert ack == (0x20, b"\x00\x00")
        else:
            reader, writer = await asyncio.open_connection(iot.HOST, 1883)
        try:
            writer.write(data)
            await writer.drain()
            if eof:
                writer.write_eof()
            try:
                assert await asyncio.wait_for(reader.read(), 2) == b""
            except ConnectionResetError:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionResetError:
                pass
        await echo()

    async def exercise():
        before = asyncio.all_tasks()
        async with iot.start(tmp_path):
            # Valid frame declaration but prematurely closed PUBLISH payload.
            full = _packet(0x30, _string(iot.TOPIC) + b"missing-payload")
            await attack(full[:-5], eof=True)
            # Slow/truncated open streams must hit the deadline, including CONNECT.
            await attack(full[:-5])
            await attack(b"\x10\x10\x00", connected=False)
            await attack(b"\x82\x80", eof=True)
            await attack(b"\x30\xff\xff\xff\xff")
            # Syntactically valid oversized frames across all incoming paths.
            for header, connected in ((0x10, False), (0x82, True), (0x30, True)):
                if header == 0x30:
                    body = _string(iot.TOPIC) + b"x" * 4096
                elif header == 0x82:
                    body = b"\x00\x01" + _string("x" * 4096) + b"\x00"
                else:
                    body = _string("MQTT") + b"\x04\x02\x00\x1e" + _string("x" * 4096)
                await attack(_packet(header, body), connected=connected)
            reader, writer, _ = await _connect()
            try:
                topic = "vulnassess/training/assessment"
                assert await _subscribe(reader, writer, topic) == 0
                for index in range(100):
                    writer.write(
                        _packet(0x31, _string(f"vulnassess/training/flood-{index}") + b"fictional")
                    )
                writer.write(_packet(0x31, _string(topic) + b"bounded-retained-proof"))
                await writer.drain()
                assert _publish_value(await _read(reader)) == (topic, b"bounded-retained-proof")
                assert set(brokers[0]._retained_messages) == set(iot.TOPICS)
                assert all(
                    len(message.data) <= 4096 for message in brokers[0]._retained_messages.values()
                )
            finally:
                await _close(writer)
            error, status, _, values = await _snmp(1161, "public")
            assert not error and not status and str(values[0][1]) == iot.SYS_DESCR
        _assert_rebindable()
        await _assert_no_new_tasks(before)

    asyncio.run(exercise())
