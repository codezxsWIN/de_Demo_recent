"""Read-only, label-verified Docker adapter for independent lab packet evidence.

No shell, caller-supplied commands/paths or host namespace. Capture evidence is
copied from inspected observer IDs. Client tmpfs receipts use one constant,
read-only Python reader as UID/GID 10001 in three inspected client services.
"""

import copy
import hashlib
import io
import json
import math
import re
import struct
import subprocess
import tarfile
import threading
import time
from collections import deque
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from labs.service_networks.traffic_capture import (
    KERNEL_TIMESTAMP,
    LEGACY_TIMESTAMP,
    MAX_BUNDLE_STATUS_BYTES,
    MAX_EVIDENCE_BYTES,
    MAX_PACKETS,
    MAX_PAYLOAD,
    MAX_PCAP_BYTES,
    MAX_TIMESTAMP_NS,
    PROJECT,
    SCOPE,
    SNAPLEN,
    USERSPACE_TIMESTAMP,
    decode_packet,
    environment_name,
    flow_id,
    packet_network,
    protocol_name,
    summarize_flows,
    utc,
    utc_ns,
)
from vulnassess import lab_clock

MAX_STATUS_BYTES = 1024 * 1024
MAX_CLIENT_STATUS_BYTES = 8192
CLIENT_RECEIPT_READ_SCRIPT = """import os, stat, sys
if os.geteuid() != 10001 or os.getegid() != 10001:
    raise SystemExit('Client receipt reader requires UID/GID 10001')
directory = os.open('/runtime', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    descriptor = os.open('client-status.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or not 0 <= initial.st_size <= __MAXIMUM__:
            raise SystemExit('Client receipt must be a bounded regular file')
        content = bytearray()
        while len(content) <= __MAXIMUM__:
            chunk = os.read(descriptor, __MAXIMUM__ + 1 - len(content))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > __MAXIMUM__:
            raise SystemExit('Client receipt exceeds fixed byte limit')
        if len(content) != initial.st_size or os.fstat(descriptor).st_size != initial.st_size:
            raise SystemExit('Client receipt changed during its bounded read')
        sys.stdout.buffer.write(content)
        sys.stdout.buffer.flush()
    finally:
        os.close(descriptor)
finally:
    os.close(directory)
""".replace("__MAXIMUM__", str(MAX_CLIENT_STATUS_BYTES))
CLIENT_STALE_SECONDS = 15
OBSERVER_CLOCK_READ_SCRIPT = """import json,select,sys,time
print('clock-ready', flush=True)
if not select.select([sys.stdin], [], [], 3)[0]:
    raise SystemExit('Clock request deadline exceeded')
token = sys.stdin.buffer.readline(34)
if len(token) != 33 or token[-1:] != b'\\n' or any(c not in b'0123456789abcdef' for c in token[:-1]):
    raise SystemExit('Invalid clock challenge')
print(json.dumps({'nonce':token[:-1].decode('ascii'), 'realtime_ns':time.time_ns(), 'monotonic_ns':time.monotonic_ns()}), flush=True)
"""
CLIENT_ENDPOINTS = {
    "office-workstation": ("172.30.41.5", "172.30.41.3", 2121, "ftp", "FTP RETR network-proof.txt"),
    "iot-sensor": ("172.30.42.5", "172.30.42.3", 1883, "mqtt", "MQTT PUBLISH"),
    "iot-dashboard": ("172.30.42.6", "172.30.42.3", 1883, "mqtt", "MQTT SUBSCRIBE / receive"),
}
EVIDENCE_FILES = {
    "office_source": ("/app/labs/service_networks/office.py", "office.py", 196608),
    "iot_source": ("/app/labs/service_networks/iot.py", "iot.py", 196608),
    "capture_status": ("/capture/status.json", "status.json", MAX_STATUS_BYTES),
    "pcap": ("/capture/capture.pcap", "capture.pcap", MAX_PCAP_BYTES),
    "client_status": ("/runtime/client-status.json", "client-status.json", MAX_CLIENT_STATUS_BYTES),
    "evidence": ("/capture/evidence.tar", "evidence.tar", MAX_EVIDENCE_BYTES),
}
DOCKER_TIMEOUT = 5
CONTAINER_ID = re.compile(r"[a-f0-9]{64}\Z")
SERVICE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
SESSION = re.compile(r"[a-f0-9]{32}\Z")
FLAG_NAMES = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS"}
LIMITATIONS = [
    "Independent packet observations are capture evidence, not vulnerability assertions.",
    "Application protocol labels are inferred from fixed service ports.",
    "Correlation in time and endpoint does not validate causality or an operation's outcome.",
    "Missing packets can reflect scope filtering, rotation, dropped frames or capture downtime.",
    "Capture uses the Linux realtime clock; its alignment with Windows/WSL operation timestamps is not verified.",
]


class _PublicationDeadline(ValueError):
    """The bounded publication poll expired without a newer complete read."""


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON key")
        value[key] = item
    return value


def _json(raw, maximum):
    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise ValueError("Docker evidence exceeds its byte limit")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
        )
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError("Malformed Docker evidence JSON") from error


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("An ISO timestamp with timezone is required")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("Invalid evidence timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Evidence timestamps must include a timezone")
    try:
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError) as error:
        raise ValueError("Evidence timestamp is outside the supported UTC range") from error


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def validate_client_status(raw, node):
    """Validate a bounded application receipt against an inspected client identity.

    Successful operation counts are the client's claims, not independently
    captured packet counts or validation of a vulnerability or operation outcome.
    Unknown fields are discarded; sensor data has its own narrow typed schema.
    """
    service = node["service"]
    if service not in CLIENT_ENDPOINTS or node.get("project") != PROJECT:
        raise ValueError("Client receipt requires an inspected allowlisted Compose service")
    source, gateway, port, protocol, operation = CLIENT_ENDPOINTS[service]
    if node.get("ips") != [source] or node.get("network_mode") == "host":
        raise ValueError("Inspected client source network differs from its fixed lab identity")
    document = _json(raw, MAX_CLIENT_STATUS_BYTES)
    if not isinstance(document, dict):
        raise ValueError("Client receipt must be a JSON object")
    try:
        identity = document["container_id"]
        if (
            document["role"] != service
            or not isinstance(identity, str)
            or not re.fullmatch(r"[a-f0-9]{12,64}", identity)
            or not CONTAINER_ID.fullmatch(node["id"])
            or not node["id"].startswith(identity)
            or document["container_hostname"] != identity
        ):
            raise ValueError(
                "Client receipt role/container identity differs from Docker inspection"
            )
        if (
            document["source_address"] != source
            or document["observed_source_address"] not in (None, source)
            or document["destination"] != {"address": gateway, "port": port, "protocol": protocol}
            or type(document["destination"]["port"]) is not int
            or document["operation"] != operation
        ):
            raise ValueError("Client receipt endpoints or operation differ from its fixed lab role")
        started, updated = _timestamp(document["started_at"]), _timestamp(document["updated_at"])
        if started > updated:
            raise ValueError("Client receipt time interval is reversed")
        heartbeat = document["heartbeat_at"]
        if (
            type(heartbeat) not in (int, float)
            or not math.isfinite(heartbeat)
            or abs(heartbeat - updated.timestamp()) > 2
        ):
            raise ValueError("Client receipt heartbeat is invalid or inconsistent")
        count = document["operation_count"]
        if not _integer(count, 0, 2**63 - 1):
            raise ValueError("Client operation count must be a bounded nonnegative integer")
        state = document["state"]
        if state not in (
            "starting",
            "connecting",
            "running",
            "waiting",
            "policy_blocked",
            "disconnected",
            "stopped",
        ):
            raise ValueError("Client receipt has an unknown application state")
        for key in ("last_success", "last_failure"):
            if document[key] is not None and not started <= _timestamp(document[key]) <= updated:
                raise ValueError("Client operation timestamp lies outside its application session")
        if (
            count > 0
            and (document["last_success"] is None or document["observed_source_address"] is None)
            or count == 0
            and document["last_success"] is not None
        ):
            raise ValueError("Client operation count contradicts its success/source receipt")
        error = document["last_error"]
        if error is not None and (not isinstance(error, str) or len(error) > 256):
            raise ValueError("Client error text exceeds its fixed bound")
        sensor = document.get("latest_sensor_data")
        clean_sensor = None
        if sensor is not None:
            if (
                service == "office-workstation"
                or not isinstance(sensor, dict)
                or set(sensor)
                != {"device", "source", "sequence", "temperature_c", "humidity_pct", "sent_at"}
                or sensor["device"] != "training-sensor-01"
                or sensor["source"] != "simulated sensor"
                or not _integer(sensor["sequence"], 1, 2**63 - 1)
            ):
                raise ValueError("Client sensor receipt differs from the fictional training schema")
            for key, low, high in (("temperature_c", -50, 100), ("humidity_pct", 0, 100)):
                value = sensor[key]
                if (
                    type(value) not in (int, float)
                    or not math.isfinite(value)
                    or not low <= value <= high
                ):
                    raise ValueError("Client sensor value is outside its finite training range")
            _timestamp(sensor["sent_at"])
            clean_sensor = {
                key: sensor[key]
                for key in (
                    "device",
                    "source",
                    "sequence",
                    "temperature_c",
                    "humidity_pct",
                    "sent_at",
                )
            }
        optional = {}
        if "ignored_message_count" in document:
            ignored = document["ignored_message_count"]
            reason = document.get("last_ignored_reason")
            if not _integer(ignored, 0, 2**63 - 1) or (
                reason is not None and (not isinstance(reason, str) or len(reason) > 160)
            ):
                raise ValueError("Invalid non-telemetry message receipt")
            optional.update(ignored_message_count=ignored, last_ignored_reason=reason)
        if "bytes_received" in document or "filename" in document:
            if (
                service != "office-workstation"
                or document.get("filename") != "network-proof.txt"
                or not _integer(document.get("bytes_received"), 0, 4096)
            ):
                raise ValueError("Client file receipt differs from the fixed bounded training file")
            optional.update(
                {
                    "bytes_received": document["bytes_received"],
                    "filename": "network-proof.txt",
                }
            )
        now = time.time()
        stale = not (
            -2 <= now - heartbeat <= CLIENT_STALE_SECONDS
            and -2 <= now - updated.timestamp() <= CLIENT_STALE_SECONDS
        )
        receipt_error = (
            "Client application heartbeat is stale or in the future; retained receipt is historical"
            if stale
            else "Client application is stopped; retained receipt is historical"
            if state == "stopped" or not node["running"]
            else None
        )
        return {
            "available": receipt_error is None,
            "error": receipt_error,
            "stale": stale,
            "evidence_kind": "application_client_receipt",
            "role": service,
            "container_id": node["id"],
            "container_hostname": identity,
            "source_address": source,
            "observed_source_address": document["observed_source_address"],
            "destination": {"address": gateway, "port": port, "protocol": protocol},
            "operation": operation,
            "state": state,
            "operation_count": count,
            "started_at": document["started_at"],
            "updated_at": document["updated_at"],
            "heartbeat_at": heartbeat,
            "last_success": document["last_success"],
            "last_failure": document["last_failure"],
            "last_error": error,
            "latest_sensor_data": clean_sensor,
            **optional,
            "count_basis": "Client-reported successful protocol operations; not captured packet counts or independently validated outcomes.",
        }
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        raise ValueError("Malformed bounded client application receipt") from error


def _validate_pcap(data, environment, metadata_limit=0):
    """Validate every record, Ethernet/IPv4 scope and port; return record count.

    Classic Ethernet PCAP only, microsecond or nanosecond timestamps in either
    endian. Truncated downloads, PCAPNG and partially written records fail closed.
    """
    environment_name(environment)
    if not isinstance(data, bytes) or not 24 <= len(data) <= MAX_PCAP_BYTES:
        raise ValueError("PCAP must be a bounded classic Ethernet capture")
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if data[:4] not in formats:
        raise ValueError("Unsupported PCAP magic")
    endian, precision = formats[data[:4]]
    major, minor, zone, sigfigs, snaplen, linktype = struct.unpack_from(endian + "HHiIII", data, 4)
    if (major, minor, zone, sigfigs, linktype) != (2, 4, 0, 0, 1) or not 34 <= snaplen <= SNAPLEN:
        raise ValueError("Invalid Ethernet PCAP header")
    offset, count = 24, 0
    retained = deque(maxlen=metadata_limit)
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("Truncated PCAP record header")
        seconds, fraction, included, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if fraction >= precision or not 34 <= included <= snaplen or included != original:
            raise ValueError("Invalid or truncated PCAP record length/timestamp")
        if offset + included > len(data):
            raise ValueError("Truncated PCAP packet")
        packet = decode_packet(
            data[offset : offset + included],
            environment,
            timestamp_ns=seconds * 1_000_000_000 + fraction * (1_000_000_000 // precision),
        )
        if packet is None:
            raise ValueError("PCAP contains malformed or out-of-scope packets")
        retained.append(packet)
        offset += included
        count += 1
    return count, list(retained)


def validate_pcap(data, environment):
    """Validate bounded classic Ethernet PCAP records and scope; return count."""
    return _validate_pcap(data, environment)[0]


def validate_status(raw, environment):
    environment_name(environment)
    document = _json(raw, MAX_STATUS_BYTES)
    if not isinstance(document, dict):
        raise ValueError("Capture status must be an object")
    try:
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or document["environment"] != environment
            or document["project"] != PROJECT
            or document["capture_backend"] != "linux-af-packet"
            or document["evidence_kind"] != "captured_packets"
            or not isinstance(document["session_id"], str)
            or not SESSION.fullmatch(document["session_id"])
        ):
            raise ValueError("Capture identity/schema mismatch")
        started, updated = _timestamp(document["started_at"]), _timestamp(document["updated_at"])
        if started > updated:
            raise ValueError("Capture time interval is reversed")
        if type(document["running"]) is not bool:
            raise ValueError("Capture running state must be boolean")
        if document.get("error") is not None and (
            not isinstance(document["error"], str) or len(document["error"]) > 240
        ):
            raise ValueError("Invalid capture error")
        count = document["captured_packets"]
        if (
            not _integer(count, 0, MAX_PCAP_BYTES // 50)
            or type(document["parsed_packets"]) is not int
            or document["parsed_packets"] != count
            or type(document["pcap_packets"]) is not int
            or document["pcap_packets"] != count
            or not _integer(document["pcap_bytes"], 24, MAX_PCAP_BYTES)
            or not isinstance(document["pcap_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", document["pcap_sha256"])
        ):
            raise ValueError("Invalid observed packet counts or PCAP identity")
        packets = document["packets"]
        trimmed = document.get("metadata_trimmed_for_bundle", False)
        metadata_count = document.get("metadata_packets", min(count, MAX_PACKETS))
        metadata_limit = document.get("metadata_packet_limit", MAX_PACKETS)
        if (
            not isinstance(packets, list)
            or type(trimmed) is not bool
            or not _integer(metadata_count, min(count, 1), min(count, MAX_PACKETS))
            or type(metadata_limit) is not int
            or metadata_limit != MAX_PACKETS
            or len(packets) != metadata_count
            or not trimmed
            and len(packets) != min(count, MAX_PACKETS)
        ):
            raise ValueError("Capture metadata ring is malformed or unbounded")
        validated_packets = []
        for sequence, packet in enumerate(packets, count - len(packets) + 1):
            if not isinstance(packet, dict):
                raise ValueError("Invalid packet metadata")
            if packet["packet_id"] != f"{document['session_id']}:{sequence}":
                raise ValueError("Invalid or repeated packet identity")
            if not started <= _timestamp(packet["timestamp"]) <= updated:
                raise ValueError("Packet timestamp outside its capture session")
            network = packet_network(environment, packet["source_ip"], packet["destination_ip"])
            transport = packet["transport"]
            if (
                network is None
                or packet["network"] != network
                or transport not in ("tcp", "udp")
                or not _integer(packet["source_port"], 0, 65535)
                or not _integer(packet["destination_port"], 0, 65535)
                or not (
                    {packet["source_port"], packet["destination_port"]}
                    & SCOPE[environment][transport]
                )
                or not _integer(packet["length"], 42 if transport == "udp" else 54, SNAPLEN)
                or not _integer(
                    packet["payload_length"],
                    0,
                    packet["length"] - (42 if transport == "udp" else 54),
                )
            ):
                raise ValueError(
                    "Packet endpoint, transport, network or length outside fixed scope"
                )
            flags = packet["tcp_flags"]
            if (
                not isinstance(flags, list)
                or any(not isinstance(flag, str) or flag not in FLAG_NAMES for flag in flags)
                or len(set(flags)) != len(flags)
                or (transport == "udp" and flags)
            ):
                raise ValueError("Invalid TCP flags")
            payload = packet["payload_hex"]
            if (
                not isinstance(payload, str)
                or not re.fullmatch(r"(?:[a-f0-9]{2}){0,96}", payload)
                or len(payload) // 2 != min(packet["payload_length"], MAX_PAYLOAD)
                or type(packet["payload_truncated"]) is not bool
                or packet["payload_truncated"] != (packet["payload_length"] > MAX_PAYLOAD)
                or packet["payload_summary"]
                != "".join(chr(b) if 32 <= b < 127 else "." for b in bytes.fromhex(payload))
                or packet["flow_id"] != flow_id(environment, packet)
                or packet["protocol"]
                != protocol_name(transport, packet["source_port"], packet["destination_port"])
                or packet["evidence_kind"] != "captured_packet"
            ):
                raise ValueError("Invalid packet payload, protocol hint or flow identity")
            fields = (
                "packet_id",
                "flow_id",
                "timestamp",
                "source_ip",
                "destination_ip",
                "source_port",
                "destination_port",
                "transport",
                "protocol",
                "tcp_flags",
                "length",
                "payload_length",
                "payload_hex",
                "payload_summary",
                "payload_truncated",
                "network",
                "evidence_kind",
            )
            clean = {key: packet[key] for key in fields}
            basis = packet.get("timestamp_basis", LEGACY_TIMESTAMP)
            if basis not in (KERNEL_TIMESTAMP, USERSPACE_TIMESTAMP, LEGACY_TIMESTAMP):
                raise ValueError("Unknown packet timestamp provenance")
            timestamp_error = packet.get("timestamp_error")
            stamp_ns = packet.get("timestamp_ns")
            processed = packet.get("processed_at")
            if basis != LEGACY_TIMESTAMP:
                if (
                    not _integer(stamp_ns, 0, MAX_TIMESTAMP_NS)
                    or _timestamp(utc_ns(stamp_ns)) != _timestamp(packet["timestamp"])
                    or not started <= _timestamp(processed) <= updated
                ):
                    raise ValueError("Packet timestamp provenance contradicts its recorded time")
            elif stamp_ns is not None or processed is not None:
                raise ValueError("Legacy timestamp provenance cannot claim kernel time precision")
            if timestamp_error is not None and (
                not isinstance(timestamp_error, str) or len(timestamp_error) > 240
            ):
                raise ValueError("Invalid packet timestamp uncertainty")
            if basis != KERNEL_TIMESTAMP:
                timestamp_error = (
                    timestamp_error
                    or "Kernel capture time is unknown; userspace receive scheduling can delay this timestamp"
                )
            clean.update(
                timestamp_basis=basis,
                timestamp_ns=stamp_ns,
                processed_at=processed,
                timestamp_error=timestamp_error,
            )
            clean["protocol_basis"] = (
                "transport header and fixed service port; application not validated"
            )
            validated_packets.append(clean)
        retained_bytes = sum(16 + packet["length"] for packet in validated_packets)
        omitted_count = count - len(validated_packets)
        minimum_record = 70 if environment == "office" else 58
        minimum_size = 24 + retained_bytes + omitted_count * minimum_record
        maximum_size = 24 + retained_bytes + omitted_count * (16 + SNAPLEN)
        if not minimum_size <= document["pcap_bytes"] <= maximum_size:
            raise ValueError("PCAP byte count contradicts the observed packet metadata")
        # Recompute aggregates only from validated packet metadata, never trust a
        # status document's independent claims about flow counts or finding text.
        fields = (
            "session_id",
            "started_at",
            "updated_at",
            "running",
            "error",
            "captured_packets",
            "parsed_packets",
            "pcap_packets",
            "pcap_bytes",
            "pcap_sha256",
            "packets",
        )
        result = {key: document.get(key) for key in fields}
        result["packets"] = validated_packets
        mode = document.get("timestamp_mode", LEGACY_TIMESTAMP)
        uncertainty = document.get("timestamp_error")
        if mode not in (KERNEL_TIMESTAMP, USERSPACE_TIMESTAMP, LEGACY_TIMESTAMP):
            raise ValueError("Unknown capture timestamp mode")
        if uncertainty is not None and (not isinstance(uncertainty, str) or len(uncertainty) > 240):
            raise ValueError("Invalid capture timestamp uncertainty")
        fallback_count = document.get("timestamp_fallback_packets")
        if fallback_count is not None:
            retained_fallbacks = sum(
                packet["timestamp_basis"] != KERNEL_TIMESTAMP for packet in validated_packets
            )
            if not _integer(fallback_count, retained_fallbacks, retained_fallbacks + omitted_count):
                raise ValueError("Fallback timestamp count contradicts retained packet provenance")
        result.update(
            timestamp_mode=mode,
            timestamp_error=uncertainty
            or (
                "Legacy observer assigned userspace receive timestamps; kernel capture time is unknown"
                if mode == LEGACY_TIMESTAMP
                else None
            ),
            timestamp_fallback_packets=fallback_count,
            pcap_timestamp_resolution="microsecond",
            metadata_packets=len(validated_packets),
            metadata_packet_limit=MAX_PACKETS,
            metadata_trimmed_for_bundle=trimmed,
        )
        result.update(
            environment=environment,
            flows=summarize_flows(environment, validated_packets),
            evidence_kind="captured_packets",
            capture_backend="linux-af-packet",
        )
        return result
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        raise ValueError("Malformed independent capture status") from error


def validate_evidence_bundle(raw, environment):
    """Return one validated status/PCAP pair, never data from separate reads."""
    environment_name(environment)
    if not isinstance(raw, bytes) or not 1024 <= len(raw) <= MAX_EVIDENCE_BYTES:
        raise ValueError("Paired capture evidence must be a bounded tar archive")
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) != 2 or {member.name for member in members} != {
                "status.json",
                "capture.pcap",
            }:
                raise ValueError(
                    "Paired capture evidence must contain exactly status.json and capture.pcap"
                )
            contents = {}
            for member in members:
                limit = MAX_BUNDLE_STATUS_BYTES if member.name == "status.json" else MAX_PCAP_BYTES
                if (
                    not member.isfile()
                    or member.issym()
                    or member.islnk()
                    or member.sparse is not None
                    or not 0 <= member.size <= limit
                ):
                    raise ValueError("Unsafe or oversized paired capture archive member")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("Paired capture archive has no regular member contents")
                content = stream.read(limit + 1)
                if len(content) != member.size:
                    raise ValueError("Truncated paired capture archive member")
                contents[member.name] = content
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ValueError("Malformed paired capture archive") from error
    status = validate_status(contents["status.json"], environment)
    pcap = contents["capture.pcap"]
    count, retained = _validate_pcap(pcap, environment, len(status["packets"]))
    if (
        len(pcap) != status["pcap_bytes"]
        or count != status["captured_packets"]
        or hashlib.sha256(pcap).hexdigest() != status["pcap_sha256"]
    ):
        raise ValueError("Paired capture hash, size or count identifies different generations")
    for actual, claimed in zip(retained, status["packets"]):
        for key, value in actual.items():
            if key == "timestamp":
                if _timestamp(value) != _timestamp(claimed[key]):
                    raise ValueError("Paired packet timestamp differs from its PCAP record")
            elif claimed.get(key) != value:
                raise ValueError("Paired packet metadata differs from its PCAP record")
    return status, pcap


class TrafficMonitor:
    def __init__(self, root, *, cache_seconds=1.5, stale_seconds=6):
        self.root = Path(root)  # Integration context only; never a download source/destination.
        if (
            not isinstance(cache_seconds, (int, float))
            or not math.isfinite(cache_seconds)
            or not 0 <= cache_seconds <= 2
            or not math.isfinite(stale_seconds)
            or not 2 <= stale_seconds <= 60
        ):
            raise ValueError("Invalid capture cache/staleness interval")
        self.cache_seconds = cache_seconds
        self.stale_seconds = stale_seconds
        self._cache = {}
        self._lock = threading.RLock()
        self._timeouts = threading.local()

    def refresh(self, environment=None):
        if environment is not None:
            environment_name(environment)
        with self._lock:
            if environment is None:
                self._cache.clear()
            else:
                self._cache.pop(("snapshot", environment), None)
                self._cache.pop("topology", None)
                for key in list(self._cache):
                    if (
                        isinstance(key, tuple)
                        and key[0] == "client_status"
                        and key[1].startswith(environment + "-")
                    ):
                        self._cache.pop(key, None)

    def _cached(self, key, build):
        with self._lock:
            existing = self._cache.get(key)
            if existing and time.monotonic() - existing[0] < self.cache_seconds:
                return copy.deepcopy(existing[1])
            result = build()
            self._cache[key] = (time.monotonic(), result)
            return copy.deepcopy(result)

    def _docker(self, arguments, limit):
        deadline = getattr(self._timeouts, "deadline", None)
        timeout = (
            DOCKER_TIMEOUT if deadline is None else min(DOCKER_TIMEOUT, deadline - time.monotonic())
        )
        if timeout <= 0:
            raise _PublicationDeadline(
                "Docker capture read exceeded the correlation publication deadline"
            )
        try:
            with subprocess.Popen(
                ["docker", *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ) as process:
                timed_out = threading.Event()

                def expire():
                    timed_out.set()
                    with suppress(OSError):
                        process.kill()

                timer = threading.Timer(timeout, expire)
                timer.daemon = True
                timer.start()
                try:
                    if process.stdout is None:
                        raise ValueError("Docker evidence pipe is unavailable")
                    content = process.stdout.read(limit + 1)
                    if len(content) > limit:
                        process.kill()
                        raise ValueError("Docker evidence exceeds the bounded download limit")
                    code = process.wait(timeout=timeout)
                    if timed_out.is_set():
                        if deadline is not None:
                            raise _PublicationDeadline(
                                "Docker capture read exceeded the correlation publication deadline"
                            )
                        raise ValueError("Docker inspection or fixed evidence read timed out")
                finally:
                    timer.cancel()
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError(
                "Docker inspection or fixed evidence read unavailable or timed out"
            ) from error
        if code:
            raise ValueError(
                "Docker inspection or fixed evidence read failed; container or receipt may be unavailable"
            )
        return content

    def _inspect(self):
        raw = self._docker(
            [
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"label=com.docker.compose.project={PROJECT}",
                "--format",
                "{{.ID}}",
            ],
            8192,
        )
        try:
            ids = raw.decode("ascii").split()
        except UnicodeError as error:
            raise ValueError("Malformed Docker container identifiers") from error
        if (
            len(ids) > 32
            or any(not CONTAINER_ID.fullmatch(identity) for identity in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("Invalid or unbounded Docker container identifiers")
        if not ids:
            return []
        documents = _json(self._docker(["inspect", *ids], 1024 * 1024), 1024 * 1024)
        if not isinstance(documents, list) or len(documents) != len(ids):
            raise ValueError("Malformed Docker inspect response")
        nodes = []
        seen = set()
        try:
            for doc in documents:
                identity = doc["Id"]
                if identity not in ids or identity in seen:
                    raise ValueError("Docker inspection identity mismatch")
                seen.add(identity)
                labels = doc["Config"]["Labels"]
                service = labels["com.docker.compose.service"]
                if labels["com.docker.compose.project"] != PROJECT:
                    raise ValueError("Inspected container belongs to the wrong Compose project")
                if not isinstance(service, str) or not SERVICE.fullmatch(service):
                    raise ValueError("Invalid inspected Compose service label")
                state, host = doc["State"], doc["HostConfig"]
                if (
                    type(state["Running"]) is not bool
                    or not isinstance(state["Status"], str)
                    or not isinstance(host["NetworkMode"], str)
                    or not isinstance(doc["Name"], str)
                    or not all(
                        isinstance(host.get(key) or [], list)
                        and all(isinstance(cap, str) for cap in host.get(key) or [])
                        for key in ("CapAdd", "CapDrop")
                    )
                ):
                    raise ValueError("Malformed inspected Docker state")
                tmpfs = host.get("Tmpfs")
                if tmpfs is None:
                    tmpfs = {}
                if not isinstance(tmpfs, dict) or any(
                    not isinstance(path, str)
                    or not path.startswith("/")
                    or not isinstance(options, str)
                    for path, options in tmpfs.items()
                ):
                    raise ValueError("Malformed inspected Docker tmpfs mount metadata")
                networks = {
                    name: {"ip_address": entry["IPAddress"], "network_id": entry["NetworkID"]}
                    for name, entry in doc["NetworkSettings"]["Networks"].items()
                }
                if not all(
                    isinstance(key, str)
                    and isinstance(net["ip_address"], str)
                    and isinstance(net["network_id"], str)
                    for key, net in networks.items()
                ):
                    raise ValueError("Malformed inspected Docker networks")
                environment = next(
                    (name for name in SCOPE if service == name or service.startswith(name + "-")),
                    None,
                )
                role = (
                    "capture"
                    if service.endswith("-capture")
                    else "gateway"
                    if service.endswith("-gateway")
                    else "client"
                    if service in ("office-workstation", "iot-sensor", "iot-dashboard")
                    or "client" in service
                    else "service"
                )
                nodes.append(
                    {
                        "service": service,
                        "id": identity,
                        "name": doc["Name"].lstrip("/"),
                        "running": state["Running"],
                        "status": state["Status"],
                        "health": (state.get("Health") or {}).get("Status", "not-configured"),
                        "networks": networks,
                        "network_mode": host["NetworkMode"],
                        "project": PROJECT,
                        "cap_add": host.get("CapAdd") or [],
                        "cap_drop": host.get("CapDrop") or [],
                        "privileged": host.get("Privileged", False),
                        "pid_mode": host.get("PidMode", ""),
                        "ips": [
                            net["ip_address"] for net in networks.values() if net["ip_address"]
                        ],
                        "state": state["Status"],
                        "role": role,
                        "environment": environment,
                        "client_status": None,
                        "tmpfs_mounts": sorted(tmpfs),
                    }
                )
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError("Malformed Docker inspection metadata") from error
        return nodes

    @staticmethod
    def _observer(nodes, environment):
        def one(service):
            rows = [row for row in nodes if row["service"] == service]
            if len(rows) != 1:
                raise ValueError(f"Exactly one inspected {service} service is required")
            return rows[0]

        capture, gateway = one(environment + "-capture"), one(environment + "-gateway")
        if not capture["running"] or not gateway["running"]:
            raise ValueError("Independent capture or its gateway is stopped")
        mode = capture["network_mode"]
        if not isinstance(mode, str) or not mode.startswith("container:"):
            raise ValueError("Capture must share the inspected gateway network namespace")
        target = mode.removeprefix("container:")
        if not re.fullmatch(r"[a-f0-9]{12,64}", target) or not gateway["id"].startswith(target):
            raise ValueError("Capture is attached to a different gateway network namespace")
        if gateway["network_mode"] in ("host", "none") or gateway["network_mode"].startswith(
            ("container:", "service:")
        ):
            raise ValueError("Gateway does not have an independent lab network namespace")
        added = {cap.removeprefix("CAP_") for cap in capture["cap_add"]}
        dropped = {cap.removeprefix("CAP_") for cap in capture["cap_drop"]}
        if (
            added != {"NET_RAW"}
            or "ALL" not in dropped
            or capture["privileged"] is not False
            or capture["pid_mode"] == "host"
        ):
            raise ValueError(
                "Observer requires dropped capabilities and NET_RAW only, without host access"
            )
        base = "172.30.41" if environment == "office" else "172.30.42"
        ingress = "172.30.43" if environment == "office" else "172.30.44"
        actual = gateway["networks"]
        expected = {base + ".3", ingress + ".2"}
        if len(actual) != 2 or {net["ip_address"] for net in actual.values()} != expected:
            raise ValueError("Gateway inspected IP networks differ from the declared lab scope")
        for network in actual.values():
            if not isinstance(network["network_id"], str) or not CONTAINER_ID.fullmatch(
                network["network_id"]
            ):
                raise ValueError("Gateway network identity was not inspected")
        return capture, gateway

    def _topology(self):
        def build():
            result = {
                "available": False,
                "error": None,
                "project": PROJECT,
                "inspected_at": utc(),
                "nodes": [],
                "containers": [],
                "environments": {},
                "limitations": [
                    "Docker inspection reports container state, not service reachability.",
                    "Client application receipts report operations, separately from captured packet evidence.",
                ],
            }
            try:
                nodes = self._inspect()
                result.update(nodes=nodes, containers=nodes)
                errors = []
                for environment in SCOPE:
                    try:
                        capture, gateway = self._observer(nodes, environment)
                        result["environments"][environment] = {
                            "available": True,
                            "error": None,
                            "capture": capture,
                            "gateway": gateway,
                        }
                    except ValueError as error:
                        errors.append(f"{environment}: {error}")
                        result["environments"][environment] = {
                            "available": False,
                            "error": str(error),
                        }
                result["available"] = bool(nodes)
                result["error"] = "; ".join(errors) or None
            except ValueError as error:
                result["error"] = str(error)
            return result

        return self._cached("topology", build)

    def topology(self):
        result = self._topology()
        for node in result["nodes"]:
            if node["service"] in CLIENT_ENDPOINTS:
                node["client_status"] = self._cached(
                    ("client_status", node["service"], node["id"]),
                    lambda node=node: self._client_status(node),
                )
        return result

    def source_receipt(self, environment):
        """Bind lab expectations to the code in the actual running backend image."""
        environment_name(environment)
        self.refresh(environment)
        result = {"available": False, "environment": environment, "error": None}
        try:
            topology = self._topology()
            nodes = [node for node in topology["nodes"] if node["service"] == environment]
            if len(nodes) != 1 or not nodes[0]["running"]:
                raise ValueError("Exactly one running inspected lab backend is required")
            node = nodes[0]
            expected_ip = "172.30.41.2" if environment == "office" else "172.30.42.2"
            if node["project"] != PROJECT or node["ips"] != [expected_ip]:
                raise ValueError("Backend source does not belong to the expected lab identity")
            raw = self._download(node["id"], environment + "_source")
            result.update(
                available=True,
                container_id=node["id"],
                source_sha256=hashlib.sha256(raw).hexdigest(),
                source=f"labs/service_networks/{environment}.py",
                evidence_kind="deployed_backend_source",
            )
        except ValueError as error:
            result["error"] = str(error)
        return result

    def _client_status(self, node):
        result = {
            "available": False,
            "error": None,
            "stale": None,
            "evidence_kind": "application_client_receipt",
            "role": node["service"],
            "operation_count": None,
            "updated_at": None,
        }
        try:
            if node["service"] not in CLIENT_ENDPOINTS or node["project"] != PROJECT:
                raise ValueError("Client receipt requires an inspected allowlisted Compose service")
            if not node["running"]:
                raise ValueError(
                    "Inspected client container is stopped; application receipt unavailable"
                )
            source = EVIDENCE_FILES["client_status"][0]
            covering_tmpfs = next(
                (
                    mount
                    for mount in sorted(node.get("tmpfs_mounts", []), key=len, reverse=True)
                    if source == mount or source.startswith(mount.rstrip("/") + "/")
                ),
                None,
            )
            if covering_tmpfs is not None:
                result.update(
                    receipt_path=source,
                    receipt_storage="docker_tmpfs",
                    tmpfs_mount=covering_tmpfs,
                    receipt_read_method="fixed_readonly_exec",
                )
                receipt = validate_client_status(self._read_client_receipt(node), node)
                return {**result, **receipt}
            return validate_client_status(self._download(node["id"], "client_status"), node)
        except ValueError as error:
            result["error"] = f"Client application receipt unavailable: {error}"
        return result

    def _read_client_receipt(self, node):
        """One fixed, read-only reader for inspected client application receipts."""
        if (
            node.get("service") not in CLIENT_ENDPOINTS
            or node.get("project") != PROJECT
            or not isinstance(node.get("id"), str)
            or not CONTAINER_ID.fullmatch(node["id"])
        ):
            raise ValueError(
                "Fixed client reader requires an allowlisted inspected service identity"
            )
        matches = [entry for entry in self._topology()["nodes"] if entry["id"] == node["id"]]
        if len(matches) != 1 or matches[0]["service"] != node["service"]:
            raise ValueError(
                "Fixed client reader container identity was not inspected for this service"
            )
        actual = matches[0]
        if (
            actual["project"] != PROJECT
            or not actual["running"]
            or actual["ips"] != [CLIENT_ENDPOINTS[actual["service"]][0]]
            or actual["network_mode"] == "host"
            or actual["pid_mode"] == "host"
            or actual["privileged"] is not False
        ):
            raise ValueError(
                "Fixed client reader requires its running isolated lab client identity"
            )
        return self._docker(
            [
                "exec",
                "--user",
                "10001:10001",
                actual["id"],
                "python",
                "-c",
                CLIENT_RECEIPT_READ_SCRIPT,
            ],
            MAX_CLIENT_STATUS_BYTES,
        )

    def _copy(self, identity, filename):
        if filename not in ("status.json", "capture.pcap"):
            raise ValueError("Only fixed capture evidence filenames may be downloaded")
        return self._download(identity, "capture_status" if filename == "status.json" else "pcap")

    def _download(self, identity, kind):
        if not isinstance(identity, str) or not CONTAINER_ID.fullmatch(identity):
            raise ValueError("Only an inspected immutable container ID can be read")
        if not isinstance(kind, str) or kind not in EVIDENCE_FILES:
            raise ValueError("Only allowlisted fixed evidence paths may be downloaded")
        source, filename, limit = EVIDENCE_FILES[kind]
        raw = self._docker(["cp", f"{identity}:{source}", "-"], limit + 65536)
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                members = archive.getmembers()
                if len(members) != 1:
                    raise ValueError("Unexpected members in capture download")
                member = members[0]
                if (
                    member.name != filename
                    or not member.isfile()
                    or member.issym()
                    or member.islnk()
                    or member.sparse is not None
                    or not 0 <= member.size <= limit
                ):
                    raise ValueError("Unsafe or oversized capture download")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("Capture download has no regular file")
                content = stream.read(limit + 1)
                if len(content) != member.size:
                    raise ValueError("Truncated capture download")
                return content
        except (tarfile.TarError, OSError, EOFError) as error:
            raise ValueError("Malformed capture download archive") from error

    def _capture_node(self, environment):
        # Packet capture must not depend on client application receipt reads.
        topology = self._topology()
        if not topology["available"]:
            raise ValueError(topology["error"] or "No inspected Docker lab containers")
        return self._observer(topology["nodes"], environment)[0]

    def _available_status(self, status, capture, *, clock_alignment=None):
        result = {**status, "available": False, "limitations": list(LIMITATIONS)}
        age = (datetime.now(UTC) - _timestamp(status["updated_at"])).total_seconds()
        if clock_alignment and clock_alignment.get("status") == "bounded":
            # Compare clocks using their measured relationship. Require the
            # entire possible age interval to satisfy the freshness policy.
            lower_age = age + clock_alignment["offset_lower_ns"] / 1e9
            upper_age = age + clock_alignment["offset_upper_ns"] / 1e9
            result["stale"] = not (-2 <= lower_age and upper_age <= self.stale_seconds)
            result["freshness_clock_basis"] = "measured_observer_offset_envelope"
        else:
            result["stale"] = not -2 <= age <= self.stale_seconds
        result["capture_service"] = capture["service"]
        result["capture_container_id"] = capture["id"]
        if result["stale"]:
            result["error"] = (
                "Capture heartbeat is stale or its timestamp is in the future; retained packets are historical"
            )
        elif not status["running"]:
            result["error"] = (
                status["error"] or "Independent capture is stopped; retained packets are historical"
            )
        elif status["error"]:
            result["error"] = status["error"]
        else:
            result.update(available=True, error=None)
        return result

    def snapshot(self, environment, force=False):
        environment_name(environment)
        if type(force) is not bool:
            raise ValueError("Capture force refresh must be boolean")
        if force:
            with self._lock:
                self._cache.pop(("snapshot", environment), None)

        def build():
            result = {
                "available": False,
                "error": None,
                "environment": environment,
                "session_id": None,
                "started_at": None,
                "updated_at": None,
                "running": False,
                "stale": True,
                "packets": [],
                "flows": [],
                "captured_packets": None,
                "parsed_packets": None,
                "pcap_packets": None,
                "pcap_bytes": None,
                "evidence_kind": "captured_packets",
                "limitations": LIMITATIONS,
            }
            try:
                capture = self._capture_node(environment)
                status = validate_status(self._copy(capture["id"], "status.json"), environment)
                return self._available_status(status, capture)
            except ValueError as error:
                result["error"] = str(error)
            return result

        return self._cached(("snapshot", environment), build)

    def pcap(self, environment):
        environment_name(environment)
        # Fresh inspection prevents a cached available status from authorising a
        # download after the observer/gateway was replaced or stopped.
        self.refresh(environment)
        status = self.snapshot(environment)
        if not status["available"]:
            raise ValueError(status["error"] or "Independent capture is unavailable")
        content = self._copy(status["capture_container_id"], "capture.pcap")
        # Each publication replaces the complete file atomically. Docker's copy
        # opens one inode, so the archive contains one complete PCAP generation
        # even across rotation. Validate these bytes themselves: comparing with
        # a separately sampled status hash would reject healthy live capture.
        # A bytes-only download does not claim to match a prior snapshot session.
        validate_pcap(content, environment)
        return content

    @staticmethod
    def _window(environment, port, started_at, finished_at):
        environment_name(environment)
        if (
            type(port) is not int
            or port not in SCOPE[environment]["tcp"] | SCOPE[environment]["udp"]
        ):
            raise ValueError("Correlation port is outside the fixed lab service scope")
        start, finish = _timestamp(started_at), _timestamp(finished_at)
        if start > finish:
            raise ValueError("Correlation interval is reversed")
        return start, finish

    def _clock_exchange(self, observer_id):
        """Measure only a nonce exchange after the fixed reader is ready.

        Docker process startup is outside the measured interval. A five-second
        process watchdog and fixed line limits bound both transport and output.
        """
        if not isinstance(observer_id, str) or not CONTAINER_ID.fullmatch(observer_id):
            raise ValueError("Clock read requires an inspected immutable observer ID")
        token = uuid4().hex
        with subprocess.Popen(
            [
                "docker",
                "exec",
                "-i",
                "--user",
                "10001:10001",
                observer_id,
                "python",
                "-c",
                OBSERVER_CLOCK_READ_SCRIPT,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ) as process:
            expired = threading.Event()

            def expire():
                expired.set()
                with suppress(OSError):
                    process.kill()

            timer = threading.Timer(DOCKER_TIMEOUT, expire)
            timer.daemon = True
            timer.start()
            try:
                if (
                    process.stdout is None
                    or process.stdin is None
                    or process.stdout.readline(64) != b"clock-ready\n"
                ):
                    raise ValueError(
                        "Observer clock reader did not complete its readiness handshake"
                    )
                before = time.time_ns()
                # Python 3.12's Windows monotonic clock can have a 15.6 ms
                # tick. perf_counter is monotonic and uses the high-resolution
                # performance counter, so sub-tick exchanges remain measurable.
                monotonic_before = time.perf_counter_ns()
                process.stdin.write(token.encode("ascii") + b"\n")
                process.stdin.flush()
                raw = process.stdout.readline(1025)
                monotonic_after = time.perf_counter_ns()
                after = time.time_ns()
                process.stdin.close()
                process.wait(timeout=DOCKER_TIMEOUT)
                if expired.is_set() or process.returncode != 0 or process.stdout.read(1):
                    raise ValueError("Observer clock reader exceeded its transport contract")
                document = _json(raw, 1024)
                if (
                    not isinstance(document, dict)
                    or set(document) != {"nonce", "realtime_ns", "monotonic_ns"}
                    or document["nonce"] != token
                ):
                    raise ValueError("Observer clock response does not match its challenge")
                return document, before, after, monotonic_before, monotonic_after
            except subprocess.TimeoutExpired as error:
                raise ValueError("Observer clock reader exceeded its process deadline") from error
            finally:
                # Kill before the context manager waits, including malformed
                # readiness/JSON paths. The fixed reader also has a stdin timeout.
                if process.poll() is None:
                    with suppress(OSError):
                        process.kill()
                timer.cancel()

    def clock_sample(self, environment):
        """Bracket a fixed, non-root clock read from the inspected observer."""
        environment_name(environment)
        self.refresh(environment)
        capture = self._capture_node(environment)
        document, before, after, monotonic_before, monotonic_after = self._clock_exchange(
            capture["id"]
        )
        return {
            "environment": environment,
            "observer_container_id": capture["id"],
            "method": "fixed_readonly_observer_clock",
            "host_before_ns": before,
            "host_after_ns": after,
            "host_monotonic_before_ns": monotonic_before,
            "host_monotonic_after_ns": monotonic_after,
            "observer_realtime_ns": document["realtime_ns"],
            "observer_monotonic_ns": document["monotonic_ns"],
        }

    def _alignment(self, environment, capture_id, started_at, finished_at, samples):
        if samples is None:
            return {
                "status": "not_measured",
                "reason": "No bracketed observer clock samples were retained",
            }
        try:
            return lab_clock.alignment(samples, environment, capture_id, started_at, finished_at)
        except (ValueError, TypeError, OverflowError) as error:
            return {"status": "unavailable", "reason": str(error)}

    def collect(self, environment, port, started_at, finished_at, *, clock_samples=None):
        """Return association and PCAP from one atomic bundle, or raise ValueError.

        Publication polling has a 1.5s budget after the initial bounded download.
        A later generation replaces the previous pair only after full validation.
        Empty association still returns this generation's actual validated bytes.
        """
        _, finish = self._window(environment, port, started_at, finished_at)
        self.refresh(environment)
        capture = self._capture_node(environment)
        clock = self._alignment(environment, capture["id"], started_at, finished_at, clock_samples)
        if clock["status"] == "bounded":
            finish = _timestamp(clock["observer_finished_at"])

        def read_pair():
            document, pcap = validate_evidence_bundle(
                self._download(capture["id"], "evidence"), environment
            )
            status = self._available_status(document, capture, clock_alignment=clock)
            if not status["available"]:
                raise ValueError(status["error"] or "Independent paired capture is unavailable")
            return status, pcap

        status, pcap = read_pair()
        deadline = time.monotonic() + 1.5
        previous_deadline = getattr(self._timeouts, "deadline", None)
        self._timeouts.deadline = deadline
        publication_error = None
        try:
            while _timestamp(status["updated_at"]) < finish and time.monotonic() < deadline:
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
                if time.monotonic() >= deadline:
                    break
                try:
                    newer_status, newer_pcap = read_pair()
                except _PublicationDeadline as error:
                    publication_error = str(error)
                    break
                status, pcap = newer_status, newer_pcap
        finally:
            self._timeouts.deadline = previous_deadline
        result = self._correlation_result(
            environment, port, started_at, finished_at, status, clock_alignment=clock
        )
        result.update(
            paired_evidence=True,
            evidence_pairing="atomic_status_and_pcap_bundle",
            publication_error=publication_error,
            pcap_sha256=status["pcap_sha256"],
            pcap_packets=status["pcap_packets"],
            pcap_bytes=len(pcap),
        )
        if publication_error:
            result["limitations"].append(
                "Publication polling timed out; the returned status and PCAP are the last fully validated pair."
            )
        return result, pcap

    def correlate(self, environment, port, started_at, finished_at):
        _, finish = self._window(environment, port, started_at, finished_at)
        deadline = time.monotonic() + 1.5
        previous_deadline = getattr(self._timeouts, "deadline", None)
        self._timeouts.deadline = deadline
        try:
            self.refresh(environment)
            status = self.snapshot(environment)
            while (
                status["available"]
                and _timestamp(status["updated_at"]) < finish
                and time.monotonic() < deadline
            ):
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
                if time.monotonic() < deadline:
                    newer = self.snapshot(environment, force=True)
                    # A deadline during the final refresh should not erase the
                    # last independently read evidence; expose its incomplete
                    # publication window in limitations below.
                    if newer["available"] or time.monotonic() < deadline:
                        status = newer
        finally:
            self._timeouts.deadline = previous_deadline
        return self._correlation_result(environment, port, started_at, finished_at, status)

    def _correlation_result(
        self, environment, port, started_at, finished_at, status, *, clock_alignment=None
    ):
        start, finish = self._window(environment, port, started_at, finished_at)
        clock = clock_alignment or {
            "status": "not_measured",
            "reason": "No bracketed observer clock samples were retained",
        }
        bounded = clock["status"] == "bounded"
        if bounded:
            start = _timestamp(clock["observer_started_at"])
            finish = _timestamp(clock["observer_finished_at"])
        result = {
            "available": status["available"],
            "error": status["error"],
            "environment": environment,
            "session_id": status["session_id"],
            "capture_container_id": status.get("capture_container_id"),
            "started_at": started_at,
            "finished_at": finished_at,
            "port": port,
            "packet_ids": [],
            "packets": [],
            "correlation_only": True,
            "causal_validation": False,
            "limitations": list(LIMITATIONS),
            "method": "endpoint_and_time_window",
            "matched_packets": 0,
            "association_established": False,
            "association": "not_established",
            "captured_packets": status["captured_packets"],
            "clock_alignment": clock,
            "association_window": {
                "clock": "observer_realtime_bounded" if bounded else "host_realtime_unaligned",
                "started_at": start.isoformat(),
                "finished_at": finish.isoformat(),
            },
            "window_published": bool(
                status["updated_at"] and _timestamp(status["updated_at"]) >= finish
            ),
        }
        if bounded:
            result["method"] = "endpoint_and_bounded_clock_window"
            result["limitations"] = [
                line for line in result["limitations"] if "alignment with Windows/WSL" not in line
            ]
            result["limitations"].extend([clock["assumption"], clock["limit"]])
        elif clock["status"] == "unavailable":
            result["limitations"].append("Clock alignment was withheld: " + clock["reason"])
        if not status["available"]:
            return result
        if not result["window_published"]:
            result["limitations"].append(
                "Capture publication has not reached the operation finish time; matches may be incomplete."
            )
        if start < _timestamp(status["started_at"]):
            result["limitations"].append(
                "The operation began before this capture session; earlier packets are unavailable."
            )
        base, ingress = (
            ("172.30.41", "172.30.43") if environment == "office" else ("172.30.42", "172.30.44")
        )
        endpoints = {base + (".4" if port == 6379 else ".2"), base + ".3", ingress + ".2"}
        transport = "udp" if port in SCOPE[environment]["udp"] else "tcp"
        result["packets"] = [
            packet
            for packet in status["packets"]
            if start <= _timestamp(packet["timestamp"]) <= finish
            and packet["transport"] == transport
            and any(
                packet[ip] in endpoints and packet[key] == port
                for ip, key in (
                    ("source_ip", "source_port"),
                    ("destination_ip", "destination_port"),
                )
            )
        ]
        result["packet_ids"] = [packet["packet_id"] for packet in result["packets"]]
        result["matched_packets"] = len(result["packets"])
        result["association_established"] = bool(result["packets"])
        result["association"] = (
            "endpoint_and_time_window_matches" if result["packets"] else "not_established"
        )
        result["captured_packets"] = status["captured_packets"]
        result["limitations"].append(
            "Matches cover only the bounded packet metadata window (at most 400 packets) and current session."
        )
        if any(packet.get("timestamp_basis") != KERNEL_TIMESTAMP for packet in status["packets"]):
            result["limitations"].append(
                "Some retained timestamps use userspace receive time; receiver scheduling delay is unknown and can omit time-window matches."
            )
        if not result["packets"]:
            result["limitations"].append(
                "Packet association is not established for this capture generation; rotation, bounded retention or capture gaps can omit the operation's packets."
            )
        return result
