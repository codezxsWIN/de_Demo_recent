"""Independent AF_PACKET observer for the two fixed Docker lab namespaces.

The socket observes Ethernet frames; only parsed, scoped TCP/UDP IPv4 packets
enter the evidence files. These are packet observations, never findings. No
promiscuous mode, host namespace, traffic generation or protocol requests.
"""

import argparse
import hashlib
import io
import ipaddress
import json
import os
import platform
import signal
import socket
import struct
import sys
import tarfile
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

PROJECT = "vulnassess-service-networks"
MAX_PCAP_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_BYTES = MAX_PCAP_BYTES + 512 * 1024
MAX_BUNDLE_STATUS_BYTES = 512 * 1024 - 16384  # Reserve bounded tar headers/alignment.
MAX_PACKETS = 400
MAX_PAYLOAD = 96
SNAPLEN = 65535
PCAP_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 1)
KERNEL_TIMESTAMP = "linux_kernel_so_timestampns"
USERSPACE_TIMESTAMP = "userspace_receive"
LEGACY_TIMESTAMP = "legacy_userspace_receive"
TIMESPEC = struct.Struct("=qq")  # Linux amd64 timespec: signed 64-bit seconds/nanoseconds.
MAX_TIMESTAMP_NS = (2**32) * 1_000_000_000 - 1  # Classic PCAP's uint32 seconds.
SCOPE = {
    "office": {
        "subnets": ("172.30.41.0/29", "172.30.43.0/29"),
        "tcp": {2121, 2122, 2222, 2223, 1445, 1446, 6379, *range(32200, 32210)},
        "udp": set(),
    },
    "iot": {
        "subnets": ("172.30.42.0/29", "172.30.44.0/29"),
        "tcp": {1883, 1884, 8883, 6379},
        "udp": {1161, 1162},
    },
}
NETWORKS = {
    name: tuple(ipaddress.IPv4Network(net) for net in scope["subnets"])
    for name, scope in SCOPE.items()
}


def environment_name(environment):
    if not isinstance(environment, str) or environment not in SCOPE:
        raise ValueError("Only the fixed office and iot environments are supported")
    return environment


def utc(timestamp=None):
    return datetime.fromtimestamp(time.time() if timestamp is None else timestamp, UTC).isoformat()


def utc_ns(timestamp_ns):
    seconds, nanos = divmod(timestamp_ns, 1_000_000_000)
    return (
        datetime.fromtimestamp(seconds, UTC) + timedelta(microseconds=nanos // 1000)
    ).isoformat()


def enable_kernel_timestamps(wire):
    """Use SO_TIMESTAMPNS on the pinned Linux amd64 observer, without NET_ADMIN."""
    if (
        sys.platform != "linux"
        or platform.machine().lower() not in ("amd64", "x86_64")
        or struct.calcsize("P") != 8
    ):
        return (
            None,
            "SO_TIMESTAMPNS ABI is unsupported; userspace receive scheduling delay is unknown",
        )
    # Python 3.12 may omit this constant. Linux amd64's SO_TIMESTAMPNS_OLD is
    # 35, with the same 16-byte timespec ABI as SO_TIMESTAMPNS_NEW (64).
    option = getattr(socket, "SO_TIMESTAMPNS", 35)
    if option not in (35, 64):
        return (
            None,
            "SO_TIMESTAMPNS constant is unsupported; userspace receive scheduling delay is unknown",
        )
    try:
        wire.setsockopt(socket.SOL_SOCKET, option, 1)
    except OSError:
        return (
            None,
            "SO_TIMESTAMPNS could not be enabled; userspace receive scheduling delay is unknown",
        )
    return option, None


def ancillary_timestamp(ancillary, flags, option, processed_ns):
    """Validate one matching kernel control message; never infer missing times.

    A fallback is explicitly a userspace dequeue timestamp. CLOCK_REALTIME can
    step; do not assume it is aligned with the Windows host operation clock.
    """

    def fallback(reason):
        return processed_ns, USERSPACE_TIMESTAMP, reason

    if option is None:
        return fallback(
            "Kernel timestamping unavailable; userspace receive scheduling delay is unknown"
        )
    if flags & getattr(socket, "MSG_CTRUNC", 8):
        return fallback(
            "Kernel timestamp ancillary data was truncated; userspace receive time used"
        )
    if not isinstance(ancillary, (tuple, list)):
        return fallback("Malformed kernel timestamp ancillary data; userspace receive time used")
    values = []
    for item in ancillary:
        if not isinstance(item, tuple) or len(item) != 3:
            return fallback(
                "Malformed kernel timestamp control message; userspace receive time used"
            )
        level, kind, content = item
        if level == socket.SOL_SOCKET and kind == option:
            if not isinstance(content, bytes) or len(content) != TIMESPEC.size:
                return fallback("Invalid kernel timespec size; userspace receive time used")
            seconds, nanos = TIMESPEC.unpack(content)
            if not 0 <= seconds <= 2**32 - 1 or not 0 <= nanos < 1_000_000_000:
                return fallback("Invalid kernel timespec value; userspace receive time used")
            values.append(seconds * 1_000_000_000 + nanos)
    if len(values) != 1:
        return fallback("Missing or ambiguous kernel timestamp; userspace receive time used")
    return values[0], KERNEL_TIMESTAMP, None


def receive_packet(wire, option):
    # 64 bytes accommodates Linux amd64's cmsghdr + 16-byte timespec, including
    # alignment. MSG_CTRUNC still fails timestamp provenance closed.
    frame, ancillary, flags, _ = wire.recvmsg(SNAPLEN + 1, 64)
    processed_ns = time.time_ns()
    timestamp_ns, basis, error = ancillary_timestamp(ancillary, flags, option, processed_ns)
    if flags & getattr(socket, "MSG_TRUNC", 32):
        frame = b""  # Never retain a truncated Ethernet frame as a complete capture.
    return frame, timestamp_ns, basis, error, processed_ns


def packet_network(environment, source, destination):
    """Both endpoints must be usable addresses in this environment's subnets."""
    nets = NETWORKS[environment_name(environment)]
    try:
        addresses = (ipaddress.IPv4Address(source), ipaddress.IPv4Address(destination))
    except ipaddress.AddressValueError:
        return None
    if not all(
        any(ip in net and ip not in (net.network_address, net.broadcast_address) for net in nets)
        for ip in addresses
    ):
        return None
    return environment + ("-ingress" if any(ip in nets[1] for ip in addresses) else "")


def protocol_name(transport, source_port, destination_port):
    ports = {source_port, destination_port}
    if transport == "udp":
        return "SNMP" if ports & {1161, 1162} else "UDP"
    for name, service_ports in (
        ("FTP", {2121, 2122}),
        ("FTP-DATA", set(range(32200, 32210))),
        ("SSH", {2222, 2223}),
        ("SMB", {1445, 1446}),
        ("MQTT-TLS", {8883}),
        ("MQTT", {1883, 1884}),
        ("Redis", {6379}),
    ):
        if ports & service_ports:
            return name
    return "TCP"


def decode_packet(frame, environment, timestamp=None, *, timestamp_ns=None):
    """Return parsed metadata or None; application names are port-based hints.

    Reject incomplete frames, fragments (including the first fragment), invalid
    header lengths and out-of-scope endpoints/ports. Payload remains raw evidence.
    Checksums are not validated: Linux offload may expose unfinished checksums.
    """
    environment_name(environment)
    if not isinstance(frame, bytes) or len(frame) < 34 or len(frame) > SNAPLEN:
        return None
    offset = 14
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    # Bounded support for 802.1Q / QinQ Ethernet headers.
    for _ in range(2):
        if ethertype not in (0x8100, 0x88A8):
            break
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ethertype != 0x0800 or len(frame) < offset + 20:
        return None
    version, ihl = frame[offset] >> 4, (frame[offset] & 15) * 4
    total = struct.unpack_from("!H", frame, offset + 2)[0]
    fragment = struct.unpack_from("!H", frame, offset + 6)[0]
    if version != 4 or ihl < 20 or total < ihl or len(frame) < offset + total:
        return None
    if fragment & 0xBFFF:  # Reserved bit, MF or nonzero offset; DF is allowed.
        return None
    transport = {6: "tcp", 17: "udp"}.get(frame[offset + 9])
    if transport is None:
        return None
    source = socket.inet_ntoa(frame[offset + 12 : offset + 16])
    destination = socket.inet_ntoa(frame[offset + 16 : offset + 20])
    network = packet_network(environment, source, destination)
    segment = frame[offset + ihl : offset + total]
    minimum = 20 if transport == "tcp" else 8
    if network is None or len(segment) < minimum:
        return None
    source_port, destination_port = struct.unpack_from("!HH", segment)
    if not ({source_port, destination_port} & SCOPE[environment][transport]):
        return None
    if transport == "tcp":
        header_length = (segment[12] >> 4) * 4
        if header_length < 20 or header_length > len(segment):
            return None
        flag_bits = segment[13] | ((segment[12] & 1) << 8)
        flags = [
            name
            for bit, name in enumerate(
                ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS")
            )
            if flag_bits & (1 << bit)
        ]
        payload = segment[header_length:]
    else:
        length = struct.unpack_from("!H", segment, 4)[0]
        if length < 8 or length != len(segment):
            return None
        flags, payload = [], segment[8:length]
    sample = payload[:MAX_PAYLOAD]
    return {
        "timestamp": utc(timestamp) if timestamp_ns is None else utc_ns(timestamp_ns),
        "source_ip": source,
        "destination_ip": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        "transport": transport,
        "protocol": protocol_name(transport, source_port, destination_port),
        "protocol_basis": "transport header and fixed service port; application not validated",
        "tcp_flags": flags,
        "length": len(frame),
        "payload_length": len(payload),
        "payload_hex": sample.hex(),
        "payload_summary": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in sample),
        "payload_truncated": len(payload) > MAX_PAYLOAD,
        "network": network,
        "evidence_kind": "captured_packet",
    }


def flow_id(environment, packet):
    endpoints = sorted(
        (
            f"{packet['source_ip']}:{packet['source_port']}",
            f"{packet['destination_ip']}:{packet['destination_port']}",
        )
    )
    key = "|".join((environment, packet["transport"], *endpoints))
    return hashlib.sha256(key.encode("ascii")).hexdigest()[:24]


def summarize_flows(environment, packets):
    flows = {}
    for packet in packets:
        identity = flow_id(environment, packet)
        row = flows.setdefault(
            identity,
            {
                "flow_id": identity,
                "transport": packet["transport"],
                "protocol": packet["protocol"],
                "source_ip": packet["source_ip"],
                "source_port": packet["source_port"],
                "destination_ip": packet["destination_ip"],
                "destination_port": packet["destination_port"],
                "first_seen": packet["timestamp"],
                "last_seen": packet["timestamp"],
                "packets": 0,
                "bytes": 0,
                "count_scope": "retained packet metadata window",
            },
        )
        row["last_seen"] = packet["timestamp"]
        row["packets"] += 1
        row["bytes"] += packet["length"]
    return list(flows.values())


def atomic_write(path, content):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(content)
        stream.flush()
    os.replace(temporary, path)


def evidence_bundle(status, pcap):
    """One complete status/PCAP generation, with no paths supplied by callers."""
    if len(status) > MAX_BUNDLE_STATUS_BYTES or len(pcap) > MAX_PCAP_BYTES:
        raise ValueError("Evidence bundle member exceeds its fixed byte bound")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in (("status.json", status), ("capture.pcap", pcap)):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(content))
    content = output.getvalue()
    if len(content) > MAX_EVIDENCE_BYTES:
        raise ValueError("Evidence bundle exceeds 4.5 MiB")
    return content


class Capture:
    """One bounded, independently readable PCAP session plus a metadata ring."""

    def __init__(self, environment, directory=Path("/capture")):
        self.environment = environment_name(environment)
        self.directory = Path(directory)
        self.running = False
        self.error = None
        self.received_frames = 0
        self.rotations = 0
        self.timestamp_mode = USERSPACE_TIMESTAMP
        self.timestamp_error = "Kernel receive timestamping has not been configured"
        self._reset()

    def _reset(self, timestamp=None):
        self.session_id = uuid4().hex
        self.started_at = utc_ns(
            time.time_ns() if timestamp is None else int(timestamp * 1_000_000_000)
        )
        self.packets = deque(maxlen=MAX_PACKETS)
        self.data = bytearray(PCAP_HEADER)
        self.captured_packets = 0
        self.timestamp_fallback_packets = 0

    def accept(
        self,
        frame,
        timestamp=None,
        *,
        timestamp_ns=None,
        timestamp_basis=USERSPACE_TIMESTAMP,
        timestamp_error=None,
        processed_ns=None,
    ):
        if timestamp_ns is None:
            timestamp_ns = time.time_ns() if timestamp is None else int(timestamp * 1_000_000_000)
        if (
            type(timestamp_ns) is not int
            or not 0 <= timestamp_ns <= MAX_TIMESTAMP_NS
            or timestamp_basis not in (KERNEL_TIMESTAMP, USERSPACE_TIMESTAMP)
        ):
            raise ValueError("Invalid capture timestamp or provenance")
        if processed_ns is None:
            processed_ns = time.time_ns()
        self.received_frames += 1
        packet = decode_packet(frame, self.environment, timestamp_ns=timestamp_ns)
        if packet is None:
            return False
        if len(self.data) + 16 + len(frame) > MAX_PCAP_BYTES:
            self.rotations += 1
            self._reset(timestamp_ns / 1_000_000_000)
            self.started_at = packet["timestamp"]
        seconds, nanos = divmod(timestamp_ns, 1_000_000_000)
        record = struct.pack("<IIII", seconds, nanos // 1000, len(frame), len(frame))
        self.data.extend(record)
        self.data.extend(frame)
        self.captured_packets += 1
        if timestamp_basis != KERNEL_TIMESTAMP:
            self.timestamp_fallback_packets += 1
            timestamp_error = (
                timestamp_error
                or "Userspace receive timestamp; kernel capture time and scheduling delay are unknown"
            )
        packet.update(
            timestamp_ns=timestamp_ns,
            timestamp_basis=timestamp_basis,
            timestamp_error=timestamp_error,
            processed_at=utc_ns(processed_ns),
        )
        packet["packet_id"] = f"{self.session_id}:{self.captured_packets}"
        packet["flow_id"] = flow_id(self.environment, packet)
        self.packets.append(packet)
        return True

    def publish(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Freeze once. The two standalone files and paired bundle all derive
        # from these same bytes, never from separate reads of a live capture.
        pcap = bytes(self.data)
        packets = list(self.packets)
        status = {
            "schema_version": 1,
            "project": PROJECT,
            "environment": self.environment,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "updated_at": utc_ns(time.time_ns()),
            "running": self.running,
            "error": self.error,
            "captured_packets": self.captured_packets,
            "parsed_packets": self.captured_packets,
            "pcap_packets": self.captured_packets,
            "pcap_bytes": len(pcap),
            "pcap_sha256": hashlib.sha256(pcap).hexdigest(),
            "received_frames": self.received_frames,
            "rotations": self.rotations,
            "packets": packets,
            "flows": summarize_flows(self.environment, packets),
            "metadata_packets": len(packets),
            "metadata_packet_limit": MAX_PACKETS,
            "metadata_trimmed_for_bundle": False,
            "evidence_kind": "captured_packets",
            "capture_backend": "linux-af-packet",
            "timestamp_mode": self.timestamp_mode,
            "timestamp_error": self.timestamp_error,
            "timestamp_fallback_packets": self.timestamp_fallback_packets,
            "pcap_timestamp_resolution": "microsecond",
            "limitations": [
                "Only parsed TCP/UDP IPv4 frames within the fixed lab scope are retained.",
                "Application names are inferred from service ports, not protocol validation.",
                "Packet evidence does not establish a vulnerability or an action's causality.",
                "Metadata retains at most 400 packets; PCAP rotates into a new session at 4 MiB.",
                "AF_PACKET delivery can drop frames; observed count is not total network traffic.",
                "Kernel capture timestamps use Linux realtime; alignment with the Windows/WSL operation clock is not verified.",
                "Userspace fallback timestamps can be delayed by receiver scheduling; each packet records its timestamp basis.",
                "Metadata may retain fewer than 400 packets to keep the paired evidence bundle within its hard byte bound.",
            ],
        }
        while True:
            status_bytes = json.dumps(status, allow_nan=False).encode()
            if len(status_bytes) <= MAX_BUNDLE_STATUS_BYTES:
                break
            if not packets:
                raise ValueError("Fixed capture status cannot fit the evidence bundle")
            # Keep the most recent contiguous packet IDs. Both counts and the
            # explicit metadata window describe precisely what is retained.
            packets = packets[max(1, len(packets) // 10) :]
            status.update(
                packets=packets,
                flows=summarize_flows(self.environment, packets),
                metadata_packets=len(packets),
                metadata_trimmed_for_bundle=True,
            )
        bundle = evidence_bundle(status_bytes, pcap)
        atomic_write(self.directory / "capture.pcap", pcap)
        atomic_write(self.directory / "status.json", status_bytes)
        atomic_write(self.directory / "evidence.tar", bundle)


def run(environment):
    capture = Capture(environment)
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    try:
        if (
            sys.platform != "linux"
            or not Path("/.dockerenv").is_file()
            or os.environ.get("VULNASSESS_CONTAINER_LAB") != "1"
        ):
            raise RuntimeError("Capture requires the explicit Linux Docker observer container")
        validate_gateway_interfaces(environment)
        # No bind to a host interface, PACKET_MR_PROMISC or NET_ADMIN is needed.
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as wire:
            wire.settimeout(0.25)
            option, capture.timestamp_error = enable_kernel_timestamps(wire)
            capture.timestamp_mode = KERNEL_TIMESTAMP if option is not None else USERSPACE_TIMESTAMP
            capture.running = True
            capture.publish()
            published = time.monotonic()
            while not stopped:
                try:
                    frame, stamp, basis, error, processed = receive_packet(wire, option)
                    capture.accept(
                        frame,
                        timestamp_ns=stamp,
                        timestamp_basis=basis,
                        timestamp_error=error,
                        processed_ns=processed,
                    )
                except socket.timeout:
                    pass
                if time.monotonic() - published >= 0.5:
                    capture.publish()
                    published = time.monotonic()
    except (OSError, RuntimeError) as error:
        capture.error = f"{type(error).__name__}: independent packet observer unavailable"
        return 1
    finally:
        capture.running = False
        capture.publish()
    return 0


def validate_gateway_interfaces(environment):
    """Refuse unrelated namespaces before opening the raw socket.

    The host adapter additionally verifies the Docker namespace relationship and
    NET_RAW-only policy by inspecting container IDs, labels and HostConfig.
    """
    import fcntl  # Linux only; keep the offline parser importable on Windows.

    base, ingress = (
        ("172.30.41", "172.30.43")
        if environment_name(environment) == "office"
        else ("172.30.42", "172.30.44")
    )
    addresses = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        for _, interface in socket.if_nameindex():
            if interface == "lo":
                continue
            try:
                reply = fcntl.ioctl(
                    control.fileno(), 0x8915, struct.pack("256s", interface.encode("ascii")[:15])
                )
                addresses.add(socket.inet_ntoa(reply[20:24]))
            except OSError:
                continue
    if addresses != {base + ".3", ingress + ".2"}:
        raise RuntimeError("Observer is not in the declared gateway IPv4 namespace")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment", choices=tuple(SCOPE))
    raise SystemExit(run(parser.parse_args().environment))
