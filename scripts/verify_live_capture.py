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
from datetime import datetime
from pathlib import Path

import dpkt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def audit(identifier):
    from vulnassess.lab_live import LiveLab

    lab = LiveLab(ROOT)
    case = lab.load(identifier)
    raw = lab.pcap(identifier)
    evidence = case["packet_evidence"]
    if not evidence.get("paired_evidence"):
        raise ValueError("This historical case predates atomic capture pairing; rerun the check")
    if hashlib.sha256(raw).hexdigest() != evidence["pcap_sha256"]:
        raise ValueError("PCAP is not the correlated generation")
    start = datetime.fromisoformat(case["started_at"]).timestamp()
    finish = datetime.fromisoformat(case["finished_at"]).timestamp()
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
        "limits": "Endpoint and temporal association only; matching packets do not independently establish CVE applicability or causality.",
    }


def main():
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
