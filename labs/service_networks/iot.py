"""Real, loopback-only MQTT and SNMP training services (optional dependencies)."""

from __future__ import annotations

import asyncio
import ipaddress
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOST = "127.0.0.3"
TOPIC = "vulnassess/training/telemetry"
TOPICS = (TOPIC, "vulnassess/training/assessment")
MAX_MQTT_PACKET = 4096
MQTT_READ_TIMEOUT = 3.0
PAYLOAD = b"VulnAssess IoT network proof"
PRIVATE_COMMUNITY = "vulnassess-private-training-2026"
SYS_DESCR = "VulnAssess training agent (PySNMP)"
SYS_NAME = "vulnassess-fictional-iot"


class _BoundedMQTTStream:
    """Frame gate for aMQTT's StreamReaderAdapter, before any packet parser.

    The adapter calls readexactly(n), not StreamReader.read(n). Buffer one
    complete, bounded frame so PublishPayload never sees a truncated stream or
    an empty successful payload read. No socket read crosses a frame deadline.
    """

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.buffer = b""
        self.failed = False

    def feed_eof(self):
        self.reader.feed_eof()

    async def _frame(self):
        async with asyncio.timeout(MQTT_READ_TIMEOUT):
            header = await self.reader.readexactly(1)
            remaining = 0
            for index in range(4):
                digit = await self.reader.readexactly(1)
                header += digit
                remaining += (digit[0] & 127) << (index * 7)
                if remaining + len(header) > MAX_MQTT_PACKET:
                    raise ValueError("MQTT frame exceeds training limit")
                if not digit[0] & 128:
                    break
            else:
                raise ValueError("Invalid MQTT remaining length")
            self.buffer = header + await self.reader.readexactly(remaining)

    async def readexactly(self, n):
        if n == 0:
            return b""
        try:
            if self.failed or n < 0 or n > MAX_MQTT_PACKET:
                raise ValueError("Invalid MQTT parser read")
            if not self.buffer:
                await self._frame()
            if n > len(self.buffer):
                raise ValueError("MQTT field crosses frame boundary")
            data, self.buffer = self.buffer[:n], self.buffer[n:]
            return data
        except (asyncio.IncompleteReadError, TimeoutError, ValueError):
            self.failed = True
            self.writer.close()
            # aMQTT catches this as a closed connection, rather than retrying
            # TimeoutError (its default handle_read_timeout does not close).
            raise asyncio.IncompleteReadError(b"", n) from None

    async def read(self, n=-1):
        # All installed MQTT parsers request explicit lengths. Fail closed if
        # a future parser asks to consume an unbounded stream until EOF.
        return await self.readexactly(n)


def _certificate(root: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    root.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VulnAssess training MQTT")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now - timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(HOST))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = root / "mqtt-expired-cert.pem", root / "mqtt-training-key.pem"
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return certfile, keyfile


def _broker_type():
    # Imports, including subclass construction, stay lazy for the ordinary app.
    from amqtt.broker import Broker

    class TrainingBroker(Broker):
        def __init__(self, config, *, protected=False):
            super().__init__(config)
            self.protected = protected
            self.connections = set()
            self.writers = set()

        async def retain_message(self, source_session, topic_name, data, qos=None):
            if topic_name not in TOPICS or (data and len(data) > MAX_MQTT_PACKET):
                raise ValueError("Retained message exceeds fixed training bounds")
            await super().retain_message(source_session, topic_name, data, qos)

        async def stream_connected(self, reader, writer, listener_name):
            task = asyncio.current_task()
            self.connections.add(task)
            self.writers.add(writer)
            try:
                await super().stream_connected(
                    _BoundedMQTTStream(reader, writer), writer, listener_name
                )
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
                self.writers.discard(writer)
                self.connections.discard(task)

        async def _handle_client_session(
            self, reader, writer, session, handler, server, listener_name
        ):
            # 0.11.4 otherwise closes on failed authentication without a CONNACK.
            # Also constrain Last Will messages, which bypass the normal publish ACL.
            will_allowed = not session.will_flag or (session.will_topic in TOPICS)
            if self.protected or not will_allowed:
                handler.attach(session, reader, writer)
                try:
                    await handler.mqtt_connack_authorize(False)
                finally:
                    handler.detach()
                    await writer.close()
                return
            await super()._handle_client_session(
                reader, writer, session, handler, server, listener_name
            )

    return TrainingBroker


async def _stop_broker(broker):
    # Closing before shutdown also wakes peers that have not sent CONNECT yet.
    for writer in tuple(broker.writers):
        writer.close()
    try:
        if broker.transitions.state == "started":
            await broker.shutdown()
    finally:
        # shutdown() cannot transition from a failed/partially started broker.
        for server in broker._servers.values():
            await server.close_instance()
        tasks = set(broker.connections)
        tasks.update(t for t in (broker._session_monitor_task, broker._broadcast_task) if t)
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await broker.plugins_manager.close()


async def _start_agent(stack: AsyncExitStack, port: int, community: str, bind_host=HOST):
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config, engine
    from pysnmp.entity.rfc3413 import cmdrsp, context
    from pysnmp.proto import rfc1902
    from pysnmp.smi import builder, instrum

    agent = engine.SnmpEngine()
    stack.callback(agent.close_dispatcher)
    # Await the public asyncio endpoint API: open_server_mode() schedules its bind
    # without awaiting it, so an occupied UDP port would otherwise fail after yield.
    wire, transport = await asyncio.get_running_loop().create_datagram_endpoint(
        udp.UdpTransport, local_addr=(bind_host, port)
    )
    stack.callback(wire.close)
    config.add_transport(agent, udp.DOMAIN_NAME, transport)
    config.add_v1_system(agent, "training-reader", community)
    for model in (1, 2):
        config.add_vacm_user(
            agent, model, "training-reader", "noAuthNoPriv", readSubTree=(1, 3, 6, 1, 2, 1, 1)
        )

    # A separate MIB exposes only the two fictional scalars, with no host OS data.
    mib = builder.MibBuilder()
    scalar, instance = mib.import_symbols("SNMPv2-SMI", "MibScalar", "MibScalarInstance")
    for number, value in ((1, SYS_DESCR), (5, SYS_NAME)):
        oid = (1, 3, 6, 1, 2, 1, 1, number)
        mib.export_symbols(
            "VULNASSESS-TRAINING-MIB",
            scalar(oid, rfc1902.OctetString()).setMaxAccess("read-only"),
            instance(oid, (0,), rfc1902.OctetString(value)),
        )
    ctx = context.SnmpContext(agent)
    ctx.unregister_context_name(b"")
    ctx.register_context_name(b"", instrum.MibInstrumController(mib))
    for responder in (
        cmdrsp.GetCommandResponder,
        cmdrsp.NextCommandResponder,
        cmdrsp.BulkCommandResponder,
        cmdrsp.SetCommandResponder,
    ):
        app = responder(agent, ctx)
        stack.callback(app.close, agent)


@asynccontextmanager
async def start(root: Path, *, bind_host: str = HOST, restrict_anonymous: bool = False):
    """Yield five service metadata dictionaries; release resources on every exit.

    Call inside the launcher's existing asyncio loop. Requires aMQTT 0.11.x,
    PySNMP 7.1.x and cryptography only when entered. Port 1884 is a deny-all
    comparison broker; it has no provisioned accounts.
    """
    from .binding import validate

    validate(bind_host, HOST)
    broker_type = _broker_type()
    certfile, keyfile = _certificate(Path(root))
    services = []
    try:
        async with AsyncExitStack() as stack:
            for port, protected, tls in (
                (1883, restrict_anonymous, False),
                (1884, True, False),
                (8883, False, True),
            ):
                listener = {"type": "tcp", "bind": f"{bind_host}:{port}", "max_connections": 32}
                if tls:
                    listener.update(ssl=True, certfile=str(certfile), keyfile=str(keyfile))
                broker = broker_type(
                    {
                        "listeners": {"default": listener},
                        "plugins": {
                            "amqtt.plugins.authentication.AnonymousAuthPlugin": {
                                "allow_anonymous": not protected,
                            },
                            "amqtt.plugins.topic_checking.TopicAccessControlListPlugin": {
                                "acl": {"anonymous": list(TOPICS)},
                                "publish_acl": {"anonymous": list(TOPICS)},
                            },
                        },
                    },
                    protected=protected,
                )
                stack.push_async_callback(_stop_broker, broker)
                await broker.start()
                if not protected:
                    # Public, installed 0.11 API; the retained message is delivered
                    # by aMQTT's normal SUBSCRIBE path, including on the TLS broker.
                    await broker.retain_message(None, TOPIC, PAYLOAD, 0)
                services.append(
                    {
                        "protocol": "mqtt",
                        "transport": "tcp",
                        "host": bind_host,
                        "port": port,
                        "protected": protected,
                        "tls": tls,
                        "implementation": "aMQTT",
                        "topic": TOPIC,
                        **({"certfile": str(certfile)} if tls else {}),
                    }
                )
            for port, community in ((1161, "public"), (1162, PRIVATE_COMMUNITY)):
                await _start_agent(stack, port, community, bind_host)
                services.append(
                    {
                        "protocol": "snmp",
                        "transport": "udp",
                        "host": bind_host,
                        "port": port,
                        "protected": port == 1162,
                        "implementation": "PySNMP",
                    }
                )
            yield services
    finally:
        # Let datagram connection_lost and cancelled library timers finish before
        # returning to a caller that may immediately rebind or close its loop.
        await asyncio.sleep(0)
