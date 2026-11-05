"""Synthetic raw-PCAP regressions for the offline verifier; no files or network IO."""

import hashlib
import importlib
import json
import socket
import struct
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnassess import lab_live
from vulnassess.errors import ConfigError

CASE_ID = "live-" + "a" * 32
MISSING_ID = "live-" + "b" * 32
BASE_NS = 1_762_080_000_000_000_000
OBSERVER_ID = "c" * 64


def iso_time(ns):
    return (datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=ns // 1000)).isoformat()


@pytest.fixture
def clock_verifier():
    # This helper must work even when the optional packet parser is absent.
    return importlib.import_module("scripts.verify_live_capture").association_window


@pytest.fixture
def envelope_case():
    samples = []
    for phase, drift in ((0, 0), (400_000_000, 1_500_000)):
        samples.append(
            {
                "environment": "iot",
                "observer_container_id": OBSERVER_ID,
                "method": "fixed_readonly_observer_clock",
                "host_before_ns": BASE_NS + phase,
                "host_after_ns": BASE_NS + phase + 2_000_000,
                "host_monotonic_before_ns": 100_000_000_000 + phase,
                "host_monotonic_after_ns": 100_002_000_000 + phase,
                "observer_realtime_ns": BASE_NS + phase + 1_000_000 + drift,
                "observer_monotonic_ns": 200_001_000_000 + phase,
            }
        )
    case = {
        "environment": "iot",
        "started_at": iso_time(BASE_NS + 3_000_000),
        "finished_at": iso_time(BASE_NS + 399_000_000),
    }
    # Independent fixture: intervals [-1, 1] ms and [0.5, 2.5] ms.
    clock = {
        "status": "bounded",
        "method": "bracketed_round_trip_offset_envelope",
        "environment": "iot",
        "observer_container_id": OBSERVER_ID,
        "samples": samples,
        "offset_lower_ns": -1_000_000,
        "offset_upper_ns": 2_500_000,
        "uncertainty_ms": 3.5,
        "observer_started_at": iso_time(BASE_NS + 2_000_000),
        "observer_finished_at": iso_time(BASE_NS + 401_500_000),
    }
    evidence = {
        "capture_container_id": OBSERVER_ID,
        "clock_alignment": clock,
        "association_window": {
            "clock": "observer_realtime_bounded",
            "started_at": clock["observer_started_at"],
            "finished_at": clock["observer_finished_at"],
        },
    }
    return case, evidence


def test_drift_envelope_preserves_both_measured_intervals(clock_verifier, envelope_case):
    case, evidence = envelope_case
    start, finish, basis, uncertainty = clock_verifier(case, evidence)
    assert basis == "bounded_observer_clock_interval" and uncertainty == 3.5
    assert start == 1_762_080_000.002
    assert finish == 1_762_080_000.4015
    # A linear 1.5 ms slew over 400 ms used to exclude these real boundary packets.
    assert start <= (BASE_NS + 3_011_250) / 1_000_000_000 <= finish
    assert start <= (BASE_NS + 400_496_250) / 1_000_000_000 <= finish


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("overlap", [1000, 1001])
def test_phase_allowance_is_exactly_one_microsecond(clock_verifier, envelope_case, phase, overlap):
    case, evidence = envelope_case
    clock = evidence["clock_alignment"]
    extra = overlap - 1000
    if phase == "before":
        clock["samples"][0]["host_after_ns"] += extra
        clock["samples"][0]["host_monotonic_after_ns"] += extra
        case["started_at"] = iso_time(BASE_NS + 1_999_000)
        clock["offset_lower_ns"] -= extra
        clock["observer_started_at"] = iso_time(BASE_NS + 999_000 - extra)
        evidence["association_window"]["started_at"] = clock["observer_started_at"]
    else:
        clock["samples"][1]["host_before_ns"] -= extra
        clock["samples"][1]["host_monotonic_before_ns"] -= extra
        case["finished_at"] = iso_time(BASE_NS + 400_001_000)
        clock["offset_upper_ns"] += extra
        clock["observer_finished_at"] = iso_time(BASE_NS + 402_501_000 + extra * 1000)
        evidence["association_window"]["finished_at"] = clock["observer_finished_at"]
    clock["uncertainty_ms"] = (clock["offset_upper_ns"] - clock["offset_lower_ns"]) / 1e6
    if overlap == 1001:
        with pytest.raises(ValueError, match="bracket"):
            clock_verifier(case, evidence)
    else:
        assert clock_verifier(case, evidence)[2] == "bounded_observer_clock_interval"


def test_window_rounding_is_exact_floor_start_and_ceiling_finish(clock_verifier, envelope_case):
    case, evidence = envelope_case
    clock = evidence["clock_alignment"]
    clock["samples"][0]["observer_realtime_ns"] += 123
    clock["samples"][1]["observer_realtime_ns"] += 456
    clock.update(offset_lower_ns=-999_877, offset_upper_ns=2_500_456, uncertainty_ms=3.500333)
    clock["observer_finished_at"] = iso_time(BASE_NS + 401_501_000)
    evidence["association_window"]["finished_at"] = clock["observer_finished_at"]
    assert clock_verifier(case, evidence)[3] == 3.500333


@pytest.mark.parametrize(
    "damage",
    [
        "lower",
        "upper",
        "uncertainty",
        "start",
        "finish",
        "clock_window",
        "old_method",
        "sample_method",
        "replacement",
        "capture_identity",
        "bool_time",
        "naive_case",
        "naive_window",
    ],
)
def test_tampered_or_unsupported_clock_claims_are_rejected(clock_verifier, envelope_case, damage):
    case, evidence = envelope_case
    clock, window = evidence["clock_alignment"], evidence["association_window"]
    if damage == "lower":
        clock["offset_lower_ns"] += 1
    elif damage == "upper":
        clock["offset_upper_ns"] -= 1
    elif damage == "uncertainty":
        clock["uncertainty_ms"] += 0.001
    elif damage == "start":
        window["started_at"] = clock["observer_started_at"] = iso_time(BASE_NS + 1_999_000)
    elif damage == "finish":
        window["finished_at"] = clock["observer_finished_at"] = iso_time(BASE_NS + 401_501_000)
    elif damage == "clock_window":
        clock["observer_started_at"] = iso_time(BASE_NS + 1_999_000)
    elif damage == "old_method":
        clock["method"] = "intersected_round_trip_offset_intervals"
    elif damage == "sample_method":
        clock["samples"][0]["method"] = "assumed"
    elif damage == "replacement":
        clock["samples"][1]["observer_container_id"] = "d" * 64
    elif damage == "capture_identity":
        evidence["capture_container_id"] = "d" * 64
    elif damage == "bool_time":
        clock["samples"][0]["host_before_ns"] = True
    elif damage == "naive_case":
        case["started_at"] = case["started_at"].removesuffix("+00:00")
    else:
        window["started_at"] = window["started_at"].removesuffix("+00:00")
    with pytest.raises(ValueError):
        clock_verifier(case, evidence)


@pytest.mark.parametrize(
    "damage",
    ["rtt", "width", "host_step", "observer_step", "stale_before", "stale_after", "duration"],
)
def test_measurement_budgets_are_enforced(clock_verifier, envelope_case, damage):
    case, evidence = envelope_case
    samples = evidence["clock_alignment"]["samples"]
    if damage in {"rtt", "width"}:
        elapsed = 3_000_000_001 if damage == "rtt" else 2_500_000_000
        samples[0]["host_after_ns"] = samples[0]["host_before_ns"] + elapsed
        samples[0]["host_monotonic_after_ns"] = samples[0]["host_monotonic_before_ns"] + elapsed
    elif damage == "host_step":
        samples[0]["host_after_ns"] += 20_000_001
    elif damage == "observer_step":
        samples[1]["observer_realtime_ns"] += 20_000_001
    elif damage in {"stale_before", "stale_after"}:
        sample, shift = (
            (samples[0], -11_000_000_000)
            if damage == "stale_before"
            else (samples[1], 11_000_000_000)
        )
        for key in (
            "host_before_ns",
            "host_after_ns",
            "host_monotonic_before_ns",
            "host_monotonic_after_ns",
            "observer_realtime_ns",
            "observer_monotonic_ns",
        ):
            sample[key] += shift
    else:
        case["finished_at"] = iso_time(BASE_NS + 60_003_001_000)
    with pytest.raises(ValueError):
        clock_verifier(case, evidence)


def test_association_helper_imports_and_runs_without_dpkt():
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            "import sys; sys.modules['dpkt'] = None; "
            "from scripts.verify_live_capture import association_window; "
            "case={'started_at':'2026-01-01T00:00:00+00:00','finished_at':'2026-01-01T00:00:00+00:00'}; "
            "assert association_window(case, {})[2] == 'host_clock_unaligned'",
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


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
