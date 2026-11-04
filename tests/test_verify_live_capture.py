"""Synthetic raw-PCAP regressions for the offline verifier; no files or network IO."""

import hashlib
import importlib
import json
import socket
import struct
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from vulnassess import lab_live
from vulnassess.errors import ConfigError

CASE_ID = "live-" + "a" * 32
MISSING_ID = "live-" + "b" * 32


@pytest.fixture
def verifier():
    pytest.importorskip("dpkt", reason="Requires the live-verification extra")
    return importlib.import_module("scripts.verify_live_capture")


@pytest.fixture
def capture_lab(monkeypatch):
    lab = SimpleNamespace()
    monkeypatch.setattr(lab_live, "LiveLab", lambda _root: lab)
    return lab


@pytest.fixture
def raw_mqtt_case():
    def make(code):
        # Encode the fixture independently of the verifier's dpkt parser.
        timestamp = 1_762_080_001
        at = datetime.fromtimestamp(timestamp, UTC).isoformat()
        source, destination = "172.30.42.2", "172.30.42.3"
        payload = b"\x20\x02\x00" + bytes([code])
        tcp = struct.pack("!HHIIBBHHH", 1883, 41000, 1, 1, 0x50, 0x18, 4096, 0, 0)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(tcp) + len(payload),
            1,
            0x4000,
            64,
            6,
            0,
            socket.inet_aton(source),
            socket.inet_aton(destination),
        )
        frame = b"\x01" * 6 + b"\x02" * 6 + b"\x08\x00" + ip + tcp + payload
        raw = (
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", timestamp, 0, len(frame), len(frame))
            + frame
        )
        packet = {
            "packet_id": "session:1",
            "timestamp": at,
            "source_ip": source,
            "destination_ip": destination,
            "source_port": 1883,
            "destination_port": 41000,
            "timestamp_basis": "linux_kernel_so_timestampns",
        }
        case = {
            "id": CASE_ID,
            "environment": "iot",
            "action": "mqtt-exchange",
            "port": 1883,
            "started_at": at,
            "finished_at": at,
            "packet_evidence": {
                "paired_evidence": True,
                "pcap_sha256": hashlib.sha256(raw).hexdigest(),
                "pcap_packets": 1,
                "session_id": "session",
                "packet_ids": [packet["packet_id"]],
                "packets": [packet],
            },
            "result": {
                "proof": {
                    "anonymous_accepted": code == 0,
                    "connack_hex": bytes([0, code]).hex(),
                }
            },
        }
        return case, raw

    return make


def test_audit_passes_independently_encoded_raw_capture(verifier, capture_lab, raw_mqtt_case):
    case, raw = raw_mqtt_case(0)
    capture_lab.load = lambda _identifier: case
    capture_lab.pcap = lambda _identifier: raw

    result = verifier.audit(CASE_ID)

    assert result["status"] == "passed"
    assert result["case_id"] == CASE_ID
    assert result["pcap_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["pcap_records"] == result["associated_records_verified"] == 1
    assert result["expected_response"] == "CONNACK 0"
    assert result["protocol_responses"] == ["CONNACK 0"]


@pytest.mark.parametrize("code", [4, 5])
def test_audit_matches_exact_recorded_mqtt_refusal(verifier, capture_lab, raw_mqtt_case, code):
    case, raw = raw_mqtt_case(code)
    capture_lab.load = lambda _identifier: case
    capture_lab.pcap = lambda _identifier: raw

    result = verifier.audit(CASE_ID)

    assert result["status"] == "passed"
    assert result["expected_response"] == f"CONNACK {code}"
    assert result["protocol_responses"] == [f"CONNACK {code}"]
    assert result["associated_records_verified"] == 1


@pytest.mark.parametrize("failure_stage", ["load", "pcap"])
def test_main_reports_config_error_and_continues_batch(
    verifier, capture_lab, raw_mqtt_case, monkeypatch, capsys, failure_stage
):
    case, raw = raw_mqtt_case(0)
    attempted = []
    message = f"Unavailable {failure_stage} evidence"

    def load(identifier):
        attempted.append(identifier)
        if identifier == MISSING_ID and failure_stage == "load":
            raise ConfigError(message)
        return case

    def pcap(identifier):
        if identifier == MISSING_ID and failure_stage == "pcap":
            raise ConfigError(message)
        return raw

    capture_lab.load = load
    capture_lab.pcap = pcap
    monkeypatch.setattr(verifier.sys, "argv", ["verify_live_capture.py", MISSING_ID, CASE_ID])

    assert verifier.main() == 1

    output = capsys.readouterr()
    results = json.loads(output.out)
    assert attempted == [MISSING_ID, CASE_ID]
    assert results[0] == {"case_id": MISSING_ID, "status": "failed", "error": message}
    assert results[1]["case_id"] == CASE_ID
    assert results[1]["status"] == "passed"
    assert results[1]["associated_records_verified"] == 1
    assert output.err == ""
