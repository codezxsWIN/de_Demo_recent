"""Bound clock offsets from receipts; never infer latency or pad a failed audit."""

import copy
import io
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from vulnassess import lab_clock as clocks
from vulnassess import lab_traffic as traffic

BASE = 1_762_080_000_000_000_000
MILLISECOND = 1_000_000
OBSERVER = "a" * 64


def receipts(offset=3_000_000):
    result = []
    for phase in (0, 400 * MILLISECOND):
        result.append(
            {
                "environment": "iot",
                "observer_container_id": OBSERVER,
                "method": "fixed_readonly_observer_clock",
                "host_before_ns": BASE + phase,
                "host_after_ns": BASE + phase + 200 * MILLISECOND,
                "host_monotonic_before_ns": 10_000_000_000 + phase,
                "host_monotonic_after_ns": 10_200_000_000 + phase,
                "observer_realtime_ns": BASE + phase + 100 * MILLISECOND + offset,
                "observer_monotonic_ns": 20_100_000_000 + phase,
            }
        )
    return result


def aligned(samples=None):
    return clocks.alignment(
        receipts() if samples is None else samples,
        "iot",
        OBSERVER,
        clocks.iso_ns(BASE + 250 * MILLISECOND),
        clocks.iso_ns(BASE + 350 * MILLISECOND),
    )


@pytest.mark.parametrize("offset", [-3_000_000_000, 0, 3_000_000, 3_000_000_000])
def test_windows_and_observer_offsets_are_measured_in_both_directions(offset):
    result = aligned(receipts(offset))
    assert result["offset_lower_ns"] == offset - 100 * MILLISECOND
    assert result["offset_upper_ns"] == offset + 100 * MILLISECOND
    assert result["uncertainty_ms"] == 200
    assert clocks.timestamp_ns(result["observer_started_at"]) == BASE + 150 * MILLISECOND + offset
    assert clocks.timestamp_ns(result["observer_finished_at"]) == BASE + 450 * MILLISECOND + offset
    assert "neither exact clock synchronisation nor transaction causality" in result["limit"]


def test_permitted_clock_slew_uses_both_sampling_intervals_not_their_intersection():
    samples = receipts()
    for sample in samples:
        sample["host_after_ns"] = sample["host_before_ns"] + 2 * MILLISECOND
        sample["host_monotonic_after_ns"] = sample["host_monotonic_before_ns"] + 2 * MILLISECOND
    samples[1]["observer_realtime_ns"] += 1_500_000
    result = aligned(samples)
    assert result["offset_lower_ns"] == 101 * MILLISECOND
    assert result["offset_upper_ns"] == 104_500_000
    assert result["uncertainty_ms"] == 3.5
    assert result["method"] == "bracketed_round_trip_offset_envelope"
    assert result["offset_lower_ns"] <= 102 * MILLISECOND <= result["offset_upper_ns"]
    assert result["offset_lower_ns"] <= 103_500_000 <= result["offset_upper_ns"]


def test_capture_freshness_compares_measured_clocks_instead_of_epoch_values(tmp_path):
    monitor = traffic.TrafficMonitor(tmp_path)
    status = {
        "updated_at": (datetime.now(UTC) + timedelta(seconds=3)).isoformat(),
        "running": True,
        "error": None,
    }
    node = {"service": "iot-capture", "id": OBSERVER}
    assert monitor._available_status(status, node)["stale"] is True
    result = monitor._available_status(
        status,
        node,
        clock_alignment={
            "status": "bounded",
            "offset_lower_ns": 2_900_000_000,
            "offset_upper_ns": 3_100_000_000,
        },
    )
    assert result["available"] and not result["stale"]
    assert result["freshness_clock_basis"] == "measured_observer_offset_envelope"


@pytest.mark.parametrize(
    "damage",
    [
        "identity",
        "environment",
        "method",
        "extra",
        "missing",
        "bool",
        "negative",
        "huge",
        "reverse",
        "rtt",
        "host_step",
        "observer_step",
        "phase",
        "conflicting",
        "stale",
    ],
)
def test_unusable_or_forged_clock_receipts_cannot_adjust_a_window(damage):
    samples = receipts()
    first, last = samples
    if damage == "identity":
        last["observer_container_id"] = "b" * 64
    elif damage == "environment":
        last["environment"] = "office"
    elif damage == "method":
        first["method"] = "assumed"
    elif damage == "extra":
        first["unexpected"] = 1
    elif damage == "missing":
        first.pop("host_after_ns")
    elif damage == "bool":
        first["host_after_ns"] = True
    elif damage == "negative":
        first["observer_monotonic_ns"] = -1
    elif damage == "huge":
        first["host_before_ns"] = 2**64
    elif damage == "reverse":
        first["host_after_ns"] = first["host_before_ns"] - 1
    elif damage == "rtt":
        first["host_monotonic_after_ns"] += 4_000_000_000
    elif damage == "host_step":
        first["host_after_ns"] += 100 * MILLISECOND
    elif damage == "observer_step":
        last["observer_realtime_ns"] += 100 * MILLISECOND
    elif damage == "phase":
        first["host_before_ns"] += 250 * MILLISECOND
        first["host_after_ns"] += 250 * MILLISECOND
    elif damage == "conflicting":
        first["host_after_ns"] = first["host_before_ns"] + MILLISECOND
        first["host_monotonic_after_ns"] = first["host_monotonic_before_ns"] + MILLISECOND
        last["host_after_ns"] = last["host_before_ns"] + MILLISECOND
        last["host_monotonic_after_ns"] = last["host_monotonic_before_ns"] + MILLISECOND
        last["observer_realtime_ns"] += 50 * MILLISECOND
    else:
        for key in (
            "host_before_ns",
            "host_after_ns",
            "host_monotonic_before_ns",
            "host_monotonic_after_ns",
            "observer_realtime_ns",
            "observer_monotonic_ns",
        ):
            first[key] -= 11_000_000_000
    with pytest.raises(ValueError):
        aligned(samples)


@pytest.mark.parametrize("samples", [None, [], [{}], {}, "assumed", [None, None]])
def test_missing_or_incomplete_receipts_do_not_become_calibration(samples):
    with pytest.raises(ValueError):
        clocks.alignment(samples, "iot", OBSERVER, clocks.iso_ns(BASE), clocks.iso_ns(BASE))


def test_observer_clock_read_is_fixed_non_root_and_read_only(monkeypatch, tmp_path):
    monitor = traffic.TrafficMonitor(tmp_path)
    monkeypatch.setattr(monitor, "refresh", lambda *_: None)
    monkeypatch.setattr(monitor, "_capture_node", lambda _: {"id": OBSERVER})
    wall = iter([BASE, BASE + 200 * MILLISECOND])
    mono = iter([10_000_000_000, 10_200_000_000])
    monkeypatch.setattr(traffic.time, "time_ns", lambda: next(wall))
    monkeypatch.setattr(traffic.time, "monotonic_ns", lambda: next(mono))
    calls = []

    def exchange(identity):
        calls.append(identity)
        before, monotonic_before = traffic.time.time_ns(), traffic.time.monotonic_ns()
        monotonic_after, after = traffic.time.monotonic_ns(), traffic.time.time_ns()
        return (
            {"realtime_ns": BASE + 103 * MILLISECOND, "monotonic_ns": 20_100_000_000},
            before,
            after,
            monotonic_before,
            monotonic_after,
        )

    monkeypatch.setattr(monitor, "_clock_exchange", exchange)
    sample = monitor.clock_sample("iot")
    assert sample == receipts()[0]
    assert calls == [OBSERVER]
    assert (
        "open(" not in traffic.OBSERVER_CLOCK_READ_SCRIPT
        and "socket" not in traffic.OBSERVER_CLOCK_READ_SCRIPT
    )
    with pytest.raises(ValueError):
        monitor.clock_sample("external")
    assert len(calls) == 1


@pytest.mark.parametrize(
    "damage", [None, "readiness", "nonce", "extra", "oversized", "fields", "exit"]
)
def test_clock_transport_requires_readiness_nonce_and_bounded_reply(tmp_path, monkeypatch, damage):
    token = "c" * 32
    document = {"nonce": token, "realtime_ns": BASE, "monotonic_ns": 20_100_000_000}
    if damage == "nonce":
        document["nonce"] = "d" * 32
    if damage == "fields":
        document["unexpected"] = 1
    raw = json.dumps(document).encode() + b"\n"
    if damage == "oversized":
        raw = b"x" * 1026 + b"\n"
    if damage == "extra":
        raw += b"extra"

    class Input(io.BytesIO):
        def close(self):
            pass

    class Process:
        def __init__(self):
            self.stdin = Input()
            self.stdout = io.BytesIO(
                (b"not-ready\n" if damage == "readiness" else b"clock-ready\n") + raw
            )
            self.returncode = None
            self.killed = False

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def wait(self, timeout):
            assert timeout == traffic.DOCKER_TIMEOUT
            self.returncode = 1 if damage == "exit" else 0

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -1

    process = Process()
    calls = []

    def popen(arguments, **kwargs):
        assert kwargs == {
            "stdin": traffic.subprocess.PIPE,
            "stdout": traffic.subprocess.PIPE,
            "stderr": traffic.subprocess.DEVNULL,
            "shell": False,
            "creationflags": getattr(traffic.subprocess, "CREATE_NO_WINDOW", 0),
        }
        calls.append(arguments)
        return process

    monkeypatch.setattr(traffic.subprocess, "Popen", popen)
    monkeypatch.setattr(traffic, "uuid4", lambda: SimpleNamespace(hex=token))
    monitor = traffic.TrafficMonitor(tmp_path)
    if damage:
        with pytest.raises(ValueError):
            monitor._clock_exchange(OBSERVER)
    else:
        answer = monitor._clock_exchange(OBSERVER)
        assert answer[0] == document
        assert process.stdin.getvalue() == token.encode() + b"\n"
        assert answer[1] <= answer[2] and answer[3] <= answer[4]
    assert calls == [
        [
            "docker",
            "exec",
            "-i",
            "--user",
            "10001:10001",
            OBSERVER,
            "python",
            "-c",
            traffic.OBSERVER_CLOCK_READ_SCRIPT,
        ]
    ]
    if damage == "readiness":
        assert process.killed and process.stdin.getvalue() == b""


def test_correlation_uses_measured_observer_window_without_claiming_causality(tmp_path):
    monitor = traffic.TrafficMonitor(tmp_path)
    clock = aligned()
    # This response is just after the host's finish time but is inside the
    # measured observer-clock interval. A later unrelated packet stays outside.
    finish = BASE + 350 * MILLISECOND
    packets = [
        {
            "packet_id": f"session:{index}",
            "timestamp": clocks.iso_ns(stamp),
            "transport": "tcp",
            "source_ip": "172.30.42.2",
            "source_port": 1883,
            "destination_ip": "172.30.42.3",
            "destination_port": 45000,
            "timestamp_basis": traffic.KERNEL_TIMESTAMP,
        }
        for index, stamp in enumerate((finish + 2 * MILLISECOND, finish + 2_000 * MILLISECOND), 1)
    ]
    status = {
        "available": True,
        "error": None,
        "session_id": "session",
        "capture_container_id": OBSERVER,
        "updated_at": clocks.iso_ns(BASE + 3_000 * MILLISECOND),
        "started_at": clocks.iso_ns(BASE - 1000 * MILLISECOND),
        "captured_packets": 2,
        "packets": packets,
    }
    start, end = clocks.iso_ns(BASE + 250 * MILLISECOND), clocks.iso_ns(finish)
    legacy = monitor._correlation_result("iot", 1883, start, end, status)
    result = monitor._correlation_result("iot", 1883, start, end, status, clock_alignment=clock)
    assert legacy["packet_ids"] == []
    assert result["packet_ids"] == ["session:1"]
    assert result["method"] == "endpoint_and_bounded_clock_window"
    assert result["causal_validation"] is False
    assert result["clock_alignment"]["uncertainty_ms"] == 200
    assert result["association_window"]["clock"] == "observer_realtime_bounded"


def test_invalid_alignment_falls_back_to_an_explicit_unmeasured_window(tmp_path):
    monitor = traffic.TrafficMonitor(tmp_path)
    clock = monitor._alignment("iot", OBSERVER, clocks.iso_ns(BASE), clocks.iso_ns(BASE), [{}])
    assert clock["status"] == "unavailable" and "one sample" in clock["reason"]


def test_offline_verifier_independently_rejects_altered_clock_bounds():
    from scripts.verify_live_capture import association_window

    clock = aligned()
    case = {
        "environment": "iot",
        "started_at": clocks.iso_ns(BASE + 250 * MILLISECOND),
        "finished_at": clocks.iso_ns(BASE + 350 * MILLISECOND),
    }
    evidence = {
        "clock_alignment": clock,
        "capture_container_id": OBSERVER,
        "association_window": {
            "clock": "observer_realtime_bounded",
            "started_at": clock["observer_started_at"],
            "finished_at": clock["observer_finished_at"],
        },
    }
    result = association_window(case, evidence)
    assert result[2:] == ("bounded_observer_clock_interval", 200)
    tampered = copy.deepcopy(evidence)
    tampered["clock_alignment"]["offset_upper_ns"] += 1
    with pytest.raises(ValueError, match="independent receipt"):
        association_window(case, tampered)
    tampered = copy.deepcopy(evidence)
    tampered["association_window"]["finished_at"] = clocks.iso_ns(BASE + 10_000 * MILLISECOND)
    with pytest.raises(ValueError, match="not supported"):
        association_window(case, tampered)
