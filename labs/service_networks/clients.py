"""Fixed, fictional lab traffic from three separate container identities.

Only stdlib networking is used. Status is an atomic, bounded local receipt;
heartbeat health describes the process, including when a gateway denies access.
"""

import argparse
import ftplib
import json
import math
import os
import re
import select
import signal
import socket
import struct
import threading
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

TOPIC = b"vulnassess/training/telemetry"
STATUS_PATH = Path("/runtime/client-status.json")
MAX_FRAME = 4096
MAX_FILE = 4096
MAX_STATUS = 8192
MAX_HEALTH_STATUS = 1024 * 1024  # Observer receipts also include bounded packet metadata.
IO_TIMEOUT = 2.0
FRAME_TIMEOUT = 3.0
HEARTBEAT_INTERVAL = 1.0
PING_INTERVAL = 5.0
HEALTH_MAX_AGE = 15.0
RECONNECT_DELAY = 3.0
WINDOWS_FILE_RETRIES = 20
WINDOWS_FILE_RETRY_DELAY = 0.01
PASSIVE_PORTS = range(32200, 32210)
ENDPOINTS = {
    "office-workstation": ("172.30.41.5", "172.30.41.3", 2121),
    "iot-sensor": ("172.30.42.5", "172.30.42.3", 1883),
    "iot-dashboard": ("172.30.42.6", "172.30.42.3", 1883),
}


class PolicyBlocked(ConnectionError):
    """The server explicitly refused the anonymous training operation."""


def timestamp():
    return datetime.now(UTC).isoformat()


def _retry_windows_sharing_error(operation):
    """Retry transient Windows sharing locks, and surface persistent failures."""
    for attempt in range(WINDOWS_FILE_RETRIES):
        try:
            return operation()
        except PermissionError as error:
            # CreateFile can report either sharing/lock violation or access
            # denied while another handle is being replaced. Never retry other
            # operating systems or turn a permanent denial into a valid receipt.
            if (
                os.name != "nt"
                or getattr(error, "winerror", None) not in (None, 5, 32, 33)
                or attempt == WINDOWS_FILE_RETRIES - 1
            ):
                raise
            time.sleep(WINDOWS_FILE_RETRY_DELAY)


def read_status(path, max_bytes=MAX_STATUS):
    """Read one bounded atomic receipt, tolerating brief Windows replace races.

    A malformed receipt is an error immediately. A persistent access failure is
    also an error after the short sharing-lock retry budget.
    """

    def read():
        with Path(path).open("rb") as stream:
            return stream.read(max_bytes + 1)

    raw = _retry_windows_sharing_error(read)
    if len(raw) > max_bytes:
        raise ValueError("Status receipt exceeds fixed bound")
    return json.loads(raw)


def status_is_fresh(path, max_age=HEALTH_MAX_AGE, *, now=None):
    """Accept a recent heartbeat even if an operation failed or was denied.

    Capture observers can use the same check with their own status path. Both
    epoch heartbeat_at and ISO updated_at receipts are accepted.
    """
    try:
        receipt = read_status(path, MAX_HEALTH_STATUS)
        value = receipt.get("heartbeat_at", receipt.get("updated_at"))
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if value.tzinfo is None:
                return False
            value = value.timestamp()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        age = (time.time() if now is None else now) - value
        return (
            math.isfinite(age)
            and 0 <= age <= max_age
            and receipt.get("state") != "stopped"
            and receipt.get("running") is not False
        )
    except (OSError, ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        return False


class Status:
    def __init__(self, role, path=STATUS_PATH):
        source, host, port = ENDPOINTS[role]
        hostname = socket.gethostname()[:128]
        # Docker's default hostname is its short ID. A named hostname is not an ID.
        identity = hostname if re.fullmatch(r"[0-9a-f]{12,64}", hostname) else None
        self.path = Path(path)
        self.lock = threading.Lock()
        self.data = {
            "role": role,
            "container_hostname": hostname,
            "container_id": identity,
            "source_address": source,
            "observed_source_address": None,
            "destination": {
                "address": host,
                "port": port,
                "protocol": "ftp" if role == "office-workstation" else "mqtt",
            },
            "operation": {
                "office-workstation": "FTP RETR network-proof.txt",
                "iot-sensor": "MQTT PUBLISH",
                "iot-dashboard": "MQTT SUBSCRIBE / receive",
            }[role],
            "state": "starting",
            "operation_count": 0,
            "ignored_message_count": 0,
            "last_success": None,
            "last_failure": None,
            "last_error": None,
            "latest_sensor_data": None,
            "started_at": timestamp(),
        }

    def update(self, **changes):
        with self.lock:
            self.data.update(changes)
            self._write()

    def success(self, **changes):
        with self.lock:
            self.data.update(changes)
            self.data.update(
                state="running",
                operation_count=self.data["operation_count"] + 1,
                last_success=timestamp(),
                last_error=None,
            )
            self._write()

    def failure(self, error):
        self.update(
            state="policy_blocked" if isinstance(error, PolicyBlocked) else "disconnected",
            last_failure=timestamp(),
            last_error=f"{type(error).__name__}: {error}"[:256],
        )

    def ignore_message(self, error):
        with self.lock:
            self.data["ignored_message_count"] += 1
            self.data["last_ignored_reason"] = str(error)[:160]
            self._write()

    def _write(self):
        self.data.update(heartbeat_at=time.time(), updated_at=timestamp())
        raw = json.dumps(self.data, ensure_ascii=True, allow_nan=False).encode("utf-8")
        if len(raw) > MAX_STATUS:
            raise ValueError("Client status exceeds fixed bound")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        try:
            temporary.write_bytes(raw)
            # Keep replacement atomic, including when a Windows health reader
            # briefly holds the previous receipt open.
            _retry_windows_sharing_error(lambda: os.replace(temporary, self.path))
        finally:
            temporary.unlink(missing_ok=True)


def send_packet(wire, header, body=b""):
    remaining = len(body)
    length = bytearray()
    while True:
        digit = remaining % 128
        remaining //= 128
        length.append(digit | (128 if remaining else 0))
        if not remaining:
            break
    if 1 + len(length) + len(body) > MAX_FRAME:
        raise ValueError("MQTT frame exceeds fixed bound")
    wire.settimeout(IO_TIMEOUT)
    wire.sendall(bytes([header]) + length + body)


def read_packet(wire):
    """Read one MQTT 3.1.1 frame, with a total deadline across fragments."""
    deadline = time.monotonic() + FRAME_TIMEOUT

    def exact(size):
        result = bytearray()
        while len(result) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("MQTT frame deadline exceeded")
            wire.settimeout(min(IO_TIMEOUT, remaining))
            chunk = wire.recv(size - len(result))
            if not chunk:
                raise ConnectionError("MQTT peer closed a partial frame")
            result.extend(chunk)
        return bytes(result)

    header = exact(1)[0]
    if header >> 4 in (0, 15):
        raise ValueError("Invalid MQTT packet type")
    remaining = 0
    for index in range(4):
        digit = exact(1)[0]
        remaining += (digit & 127) * (128**index)
        if not digit & 128:
            if index and digit == 0:
                raise ValueError("Noncanonical MQTT remaining length")
            if remaining + index + 2 > MAX_FRAME:
                raise ValueError("MQTT frame exceeds fixed bound")
            return header, exact(remaining)
    raise ValueError("Invalid MQTT remaining length")


def connect_mqtt(role, status):
    _, host, port = ENDPOINTS[role]
    wire = socket.create_connection((host, port), timeout=IO_TIMEOUT)
    try:
        status.update(observed_source_address=wire.getsockname()[0], state="connecting")
        identity = (role + "-" + os.urandom(3).hex()).encode("ascii")
        send_packet(
            wire,
            0x10,
            b"\x00\x04MQTT\x04\x02\x00\x0a" + struct.pack("!H", len(identity)) + identity,
        )
        header, body = read_packet(wire)
        if header != 0x20 or len(body) != 2 or body[0] != 0:
            raise ValueError("Invalid MQTT CONNACK")
        if body[1] in (4, 5):
            raise PolicyBlocked("Broker refused anonymous training client")
        if body[1] != 0:
            raise ConnectionError(f"Broker refused connection (code {body[1]})")
        return wire
    except BaseException:
        wire.close()
        raise


def sensor_reading(sequence):
    return {
        "device": "training-sensor-01",
        "source": "simulated sensor",
        "sequence": sequence,
        "temperature_c": round(21 + sequence % 15 / 10, 1),
        "humidity_pct": 40 + sequence % 12,
        "sent_at": timestamp(),
    }


def parse_reading(header, body):
    # The dashboard requests QoS 0. Reject other delivery modes and topics.
    if header not in (0x30, 0x31) or len(body) < 2:
        raise ValueError("Unexpected MQTT publication flags")
    size = int.from_bytes(body[:2], "big")
    if size != len(TOPIC) or body[2 : 2 + size] != TOPIC:
        raise ValueError("Unexpected MQTT topic")
    try:
        data = json.loads(body[2 + size :].decode("utf-8"))
    except RecursionError as error:
        raise ValueError("Training telemetry is nested too deeply") from error
    if not isinstance(data, dict) or set(data) != {
        "device",
        "source",
        "sequence",
        "temperature_c",
        "humidity_pct",
        "sent_at",
    }:
        raise ValueError("Invalid training telemetry fields")
    if data["device"] != "training-sensor-01" or data["source"] != "simulated sensor":
        raise ValueError("Only fictional training telemetry is accepted")
    if type(data["sequence"]) is not int or not 1 <= data["sequence"] < 2**63:
        raise ValueError("Invalid telemetry sequence")
    for field, low, high in (("temperature_c", -50, 100), ("humidity_pct", 0, 100)):
        value = data[field]
        if type(value) not in (int, float) or not low <= value <= high:
            raise ValueError("Invalid training sensor value")
    if not isinstance(data["sent_at"], str) or len(data["sent_at"]) > 40:
        raise ValueError("Invalid telemetry timestamp")
    if datetime.fromisoformat(data["sent_at"].replace("Z", "+00:00")).tzinfo is None:
        raise ValueError("Telemetry timestamp must include its time zone")
    return data


def publish_session(wire, status, stop):
    while not stop.is_set():
        sequence = status.data["operation_count"] + 1
        reading = sensor_reading(sequence)
        identifier = (sequence - 1) % 65535 + 1
        packet_id = struct.pack("!H", identifier)
        body = struct.pack("!H", len(TOPIC)) + TOPIC + packet_id + json.dumps(reading).encode()
        send_packet(wire, 0x32, body)  # QoS 1: count only broker-acknowledged sends.
        if read_packet(wire) != (0x40, packet_id):
            raise ValueError("Invalid MQTT PUBACK")
        status.success(latest_sensor_data=reading)
        if stop.wait(3):
            break


def subscribe_session(wire, status, stop):
    def receive_reading(header, body):
        try:
            reading = parse_reading(header, body)
        except ValueError as error:
            # The broker also retains a plain-text assessment proof. It is a
            # real MQTT message, but is not sensor telemetry or a client failure.
            status.ignore_message(error)
        else:
            status.success(latest_sensor_data=reading)

    send_packet(wire, 0x82, b"\x00\x01" + struct.pack("!H", len(TOPIC)) + TOPIC + b"\x00")
    for _ in range(4):
        header, body = read_packet(wire)
        if (header, body) == (0x90, b"\x00\x01\x00"):
            break
        if (header, body) == (0x90, b"\x00\x01\x80"):
            raise PolicyBlocked("Broker denied the training subscription")
        if header >> 4 != 3:
            raise ValueError("MQTT subscription was not accepted at QoS 0")
        receive_reading(header, body)
    else:
        raise ValueError("MQTT SUBACK not received within fixed packet bound")
    status.update(state="waiting")
    ping_at = time.monotonic() + PING_INTERVAL
    ping_deadline = None
    while not stop.is_set():
        now = time.monotonic()
        if ping_deadline is not None and now >= ping_deadline:
            raise TimeoutError("MQTT PINGRESP deadline exceeded")
        if ping_deadline is None and now >= ping_at:
            send_packet(wire, 0xC0)
            ping_deadline = now + FRAME_TIMEOUT
        if not select.select([wire], [], [], 0.25)[0]:
            continue
        header, body = read_packet(wire)
        if header >> 4 == 3:
            receive_reading(header, body)
        elif (header, body) == (0xD0, b"") and ping_deadline is not None:
            ping_at, ping_deadline = time.monotonic() + PING_INTERVAL, None
        else:
            raise ValueError("Unexpected MQTT subscriber packet")


class BoundedFTP(ftplib.FTP):
    """Bound multiline replies, passive destinations, and the whole retrieval."""

    def __init__(self, stop):
        super().__init__(timeout=IO_TIMEOUT)
        self.stop = stop
        self.deadline = time.monotonic() + 8
        self.reply_buffer = bytearray()

    def check_deadline(self):
        if self.stop.is_set() or time.monotonic() >= self.deadline:
            raise TimeoutError("FTP retrieval stopped or deadline exceeded")

    def getline(self):
        # ftplib's buffered readline can otherwise extend its timeout forever
        # when a peer sends a slow trickle of bytes without a newline.
        while True:
            self.check_deadline()
            end = self.reply_buffer.find(b"\n")
            if end >= 0:
                if end > self.maxline:
                    raise ValueError("FTP reply exceeds fixed line bound")
                line = bytes(self.reply_buffer[: end + 1])
                del self.reply_buffer[: end + 1]
                return line.decode(self.encoding).rstrip("\r\n")
            if len(self.reply_buffer) > self.maxline:
                raise ValueError("FTP reply exceeds fixed line bound")
            self.sock.settimeout(min(IO_TIMEOUT, self.deadline - time.monotonic()))
            chunk = self.sock.recv(512)
            if not chunk:
                raise EOFError("FTP peer closed the control connection")
            self.reply_buffer.extend(chunk)

    def getmultiline(self):
        first = self.getline()
        if first[3:4] != "-":
            return first
        lines = [first]
        for _ in range(15):
            line = self.getline()
            lines.append(line)
            if line[:3] == first[:3] and line[3:4] != "-":
                return "\n".join(lines)
        raise ValueError("FTP multiline reply exceeds fixed bound")

    def makepasv(self):
        host, port = super().makepasv()
        if host != self.sock.getpeername()[0] or port not in PASSIVE_PORTS:
            raise ValueError("FTP passive endpoint is outside the fixed gateway range")
        return host, port


def retrieve_proof(status, stop):
    _, host, port = ENDPOINTS["office-workstation"]
    total = 0
    with BoundedFTP(stop) as ftp:
        try:
            ftp.connect(host, port)
            status.update(observed_source_address=ftp.sock.getsockname()[0])
            ftp.login("anonymous", "training@example.invalid")

            def receive(chunk):
                nonlocal total
                ftp.check_deadline()
                total += len(chunk)
                if total > MAX_FILE:
                    raise ValueError("Training document exceeds fixed bound")

            ftp.retrbinary("RETR network-proof.txt", receive, blocksize=512)
        except ftplib.error_perm as error:
            if str(error).startswith(("530", "532", "550")):
                raise PolicyBlocked("FTP server denied the read-only training operation") from error
            raise
    status.success(bytes_received=total, filename="network-proof.txt")


def run(role, stop=None, status_path=STATUS_PATH):
    stop = threading.Event() if stop is None else stop
    status = Status(role, status_path)
    status.update()

    def heartbeat():
        while not stop.wait(HEARTBEAT_INTERVAL):
            status.update()

    worker = threading.Thread(target=heartbeat, name="client-heartbeat", daemon=True)
    worker.start()
    try:
        while not stop.is_set():
            try:
                if role == "office-workstation":
                    retrieve_proof(status, stop)
                    stop.wait(5)
                else:
                    with connect_mqtt(role, status) as wire:
                        try:
                            if role == "iot-sensor":
                                publish_session(wire, status, stop)
                            else:
                                subscribe_session(wire, status, stop)
                        finally:
                            with suppress(OSError):
                                send_packet(wire, 0xE0)
            except (OSError, ValueError, EOFError, ftplib.Error) as error:
                if not stop.is_set():
                    status.failure(error)
                    stop.wait(RECONNECT_DELAY)
    finally:
        stop.set()
        worker.join(timeout=HEARTBEAT_INTERVAL + 1)
        status.update(state="stopped")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", nargs="?", choices=tuple(ENDPOINTS))
    parser.add_argument("--healthcheck", type=Path, metavar="STATUS_FILE")
    args = parser.parse_args()
    if args.healthcheck is not None:
        return 0 if status_is_fresh(args.healthcheck) else 1
    if args.role is None:
        parser.error("a client role is required")
    stop = threading.Event()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda *_: stop.set())
    run(args.role, stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
