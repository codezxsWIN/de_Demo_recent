"""Independently audit retained live investigations with dpkt; no network calls.

Usage: python scripts/verify_live_capture.py live-<id> [live-<id> ...]
Install the live-verification extra in the network-labs Python environment.
"""

import argparse
import hashlib
import io
import json
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _utc_ns(value):
    """Parse UTC nanoseconds independently, without floating-point epoch arithmetic."""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Association timestamps must include a timezone")
    delta = parsed.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def association_window(case, evidence):
    """Re-derive clock bounds independently of the production association code."""
    start = _utc_ns(case["started_at"])
    finish = _utc_ns(case["finished_at"])
    if finish < start:
        raise ValueError("Association interval is reversed")
    clock = evidence.get("clock_alignment", {})
    window = evidence.get("association_window")
    if clock.get("status") != "bounded":
        if window and (
            window.get("clock") != "host_realtime_unaligned"
            or _utc_ns(window["started_at"]) != start
            or _utc_ns(window["finished_at"]) != finish
        ):
            raise ValueError("Unmeasured association cannot claim an adjusted clock window")
        return start / 1_000_000_000, finish / 1_000_000_000, "host_clock_unaligned", None
    samples = clock.get("samples")
    observer = evidence.get("capture_container_id")
    if (
        not isinstance(samples, list)
        or len(samples) != 2
        or not isinstance(observer, str)
        or len(observer) != 64
        or any(c not in "0123456789abcdef" for c in observer)
        or clock.get("observer_container_id") != observer
        or clock.get("environment") != case["environment"]
        or clock.get("method") != "bracketed_round_trip_offset_envelope"
    ):
        raise ValueError("Clock association has no matching inspected observer receipts")
    keys = {
        "environment",
        "observer_container_id",
        "method",
        "host_before_ns",
        "host_after_ns",
        "host_monotonic_before_ns",
        "host_monotonic_after_ns",
        "observer_realtime_ns",
        "observer_monotonic_ns",
    }
    lower_bounds, upper_bounds = [], []
    for sample in samples:
        if not isinstance(sample, dict) or set(sample) != keys:
            raise ValueError("Clock receipt has an unexpected structure")
        if (
            sample["environment"] != case["environment"]
            or sample["observer_container_id"] != observer
            or sample["method"] != "fixed_readonly_observer_clock"
        ):
            raise ValueError("Clock receipt identity differs from captured evidence")
        for key in keys - {"environment", "observer_container_id", "method"}:
            if type(sample[key]) is not int or not 0 < sample[key] < 2**63:
                raise ValueError("Clock receipt has an invalid timestamp")
        elapsed = sample["host_monotonic_after_ns"] - sample["host_monotonic_before_ns"]
        wall = sample["host_after_ns"] - sample["host_before_ns"]
        if (
            not 0 < elapsed <= 3_000_000_000
            or not 0 < wall <= 3_000_000_000
            or abs(elapsed - wall) > 20_000_000
        ):
            raise ValueError("Clock receipt exceeds its latency or wall-clock stability budget")
        lower_bounds.append(sample["observer_realtime_ns"] - sample["host_after_ns"])
        upper_bounds.append(sample["observer_realtime_ns"] - sample["host_before_ns"])
    lower, upper = min(lower_bounds), max(upper_bounds)
    if not 0 <= upper - lower <= 2_000_000_000:
        raise ValueError("Clock offset intervals do not establish usable bounds")
    before, after = samples
    for wall, mono in (
        ("host_before_ns", "host_monotonic_before_ns"),
        ("observer_realtime_ns", "observer_monotonic_ns"),
    ):
        elapsed = after[mono] - before[mono]
        if elapsed <= 0 or abs(after[wall] - before[wall] - elapsed) > 20_000_000:
            raise ValueError("A sampled clock stepped during the exchange")
    if not 0 <= finish - start <= 60_000_000_000:
        raise ValueError("Operation exceeds the clock association budget")
    if (
        not -1000 <= start - before["host_after_ns"] <= 10_000_000_000
        or not -1000 <= after["host_before_ns"] - finish <= 10_000_000_000
    ):
        raise ValueError("Clock samples do not bracket this operation")
    # Stored datetime windows round outward to microseconds, exactly.
    expected_start = ((start + lower) // 1000) * 1000
    expected_finish = ((finish + upper + 999) // 1000) * 1000
    if (
        type(clock.get("offset_lower_ns")) is not int
        or type(clock.get("offset_upper_ns")) is not int
        or type(clock.get("uncertainty_ms")) not in (int, float)
        or clock.get("offset_lower_ns") != lower
        or clock.get("offset_upper_ns") != upper
        or clock.get("uncertainty_ms") != (upper - lower) / 1e6
    ):
        raise ValueError("Claimed clock offset differs from the independent receipt calculation")
    if not isinstance(window, dict) or window.get("clock") != "observer_realtime_bounded":
        raise ValueError("Measured clock association is missing its observer window")
    adjusted = [_utc_ns(window[k]) for k in ("started_at", "finished_at")]
    if adjusted != [expected_start, expected_finish]:
        raise ValueError("Adjusted packet window is not supported by measured clock bounds")
    if any(
        _utc_ns(clock[key]) != stamp
        for key, stamp in zip(("observer_started_at", "observer_finished_at"), adjusted)
    ):
        raise ValueError("Clock and packet association windows disagree")
    # Keep the existing dpkt-facing seconds interface; all validation above is integer-only.
    return (
        adjusted[0] / 1_000_000_000,
        adjusted[1] / 1_000_000_000,
        "bounded_observer_clock_interval",
        (upper - lower) / 1e6,
    )


def audit(identifier):
    import dpkt

    from vulnassess.lab_live import LiveLab

    lab = LiveLab(ROOT)
    case = lab.load(identifier)
    raw = lab.pcap(identifier)
    evidence = case["packet_evidence"]
    if not evidence.get("paired_evidence"):
        raise ValueError("This historical case predates atomic capture pairing; rerun the check")
    if hashlib.sha256(raw).hexdigest() != evidence["pcap_sha256"]:
        raise ValueError("PCAP is not the correlated generation")
    start, finish, clock_basis, uncertainty = association_window(case, evidence)
    records = list(dpkt.pcap.Reader(io.BytesIO(raw)))
    if len(records) != evidence["pcap_packets"]:
        raise ValueError("PCAP count differs from paired metadata")
    responses = set()
    for metadata in evidence["packets"]:
        session, index = metadata["packet_id"].split(":")
        if session != evidence["session_id"] or not 1 <= int(index) <= len(records):
            raise ValueError("Packet reference does not identify this capture generation")
        timestamp, frame = records[int(index) - 1]
        packet = dpkt.ethernet.Ethernet(frame).data
        if not isinstance(packet, dpkt.ip.IP):
            raise ValueError("Associated packet is not IPv4")
        transport = packet.data
        if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            raise ValueError("Associated packet is not TCP or UDP")
        # dpkt creates header fields dynamically from each packet's __hdr__.
        source_ip = socket.inet_ntoa(getattr(packet, "src"))
        destination_ip = socket.inet_ntoa(getattr(packet, "dst"))
        source_port = getattr(transport, "sport")
        destination_port = getattr(transport, "dport")
        recorded = datetime.fromisoformat(metadata["timestamp"]).timestamp()
        if abs(float(timestamp) - recorded) > 0.000002:
            raise ValueError("Referenced PCAP timestamp contradicts metadata")
        if not start <= float(timestamp) <= finish:
            raise ValueError("Associated packet lies outside the recorded operation window")
        if (
            source_ip != metadata["source_ip"]
            or destination_ip != metadata["destination_ip"]
            or source_port != metadata["source_port"]
            or destination_port != metadata["destination_port"]
        ):
            raise ValueError("Referenced endpoints contradict the independently parsed PCAP")
        if metadata.get("timestamp_basis") != "linux_kernel_so_timestampns":
            raise ValueError("Operation association lacks a kernel receive timestamp")
        payload = bytes(transport.data)
        if case["action"].startswith("ftp-") and source_port == case["port"]:
            for line in payload.splitlines():
                if line[:3] in {b"230", b"530"}:
                    responses.add(line[:3].decode())
        if case["action"].startswith("mqtt-") and source_port == case["port"]:
            if payload[:3] == b"\x20\x02\x00" and len(payload) >= 4:
                responses.add("CONNACK " + str(payload[3]))
    proof = case["result"]["proof"]
    expected = None
    if "anonymous_accepted" in proof and case["action"].startswith("ftp-"):
        expected = "230" if proof["anonymous_accepted"] else "530"
    if case["action"].startswith("mqtt-") and "anonymous_accepted" in proof:
        connack = bytes.fromhex(proof["connack_hex"])
        if len(connack) != 2 or connack[1] not in {0, 4, 5}:
            raise ValueError("Recorded CONNACK is not a supported authentication decision")
        expected = "CONNACK " + str(connack[1])
    if expected and expected not in responses:
        raise ValueError(f"No independently parsed {expected} response in the associated window")
    return {
        "case_id": identifier,
        "environment": case["environment"],
        "pcap_sha256": evidence["pcap_sha256"],
        "pcap_records": len(records),
        "associated_records_verified": len(evidence["packets"]),
        "protocol_responses": sorted(responses),
        "expected_response": expected,
        "status": "passed",
        "clock_basis": clock_basis,
        "clock_uncertainty_ms": uncertainty,
        "limits": "Endpoint and temporal association only; matching packets do not independently establish CVE applicability or causality.",
    }


def main():
    import dpkt

    from vulnassess.errors import ConfigError

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_ids", nargs="+")
    args = parser.parse_args()
    results = []
    for identifier in args.case_ids:
        try:
            results.append(audit(identifier))
        except (ConfigError, ValueError, OSError, dpkt.Error) as error:
            results.append({"case_id": identifier, "status": "failed", "error": str(error)})
    print(json.dumps(results, indent=2))
    return int(any(row["status"] != "passed" for row in results))


if __name__ == "__main__":
    raise SystemExit(main())
