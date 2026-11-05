"""Measured host/observer clock bounds for lab packet association, not causality."""

from datetime import UTC, datetime, timedelta

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
MAX_RTT_NS = 3_000_000_000
MAX_UNCERTAINTY_NS = 2_000_000_000
MAX_SAMPLE_GAP_NS = 10_000_000_000
MAX_OPERATION_NS = 60_000_000_000
STEP_TOLERANCE_NS = 20_000_000
FIELDS = {
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


def timestamp_ns(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Clock boundaries require timezone-aware timestamps")
    delta = parsed.astimezone(UTC) - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def iso_ns(value, *, ceiling=False):
    micros = (value + 999) // 1000 if ceiling else value // 1000
    return (EPOCH + timedelta(microseconds=micros)).isoformat()


def alignment(samples, environment, observer_id, started_at, finished_at):
    """Enclose both RTT-derived offset intervals when the clocks appear stable.

    Each observer sample occurred between the host send and receive times. No
    midpoint estimate or assumed zero latency is used. Monotonic elapsed times
    detect observed wall-clock steps; an undetected step between samples remains
    a stated assumption, never a claim of exact synchronisation.
    """
    if not isinstance(samples, list) or len(samples) != 2:
        raise ValueError("Clock alignment requires one sample before and one after the operation")
    for sample in samples:
        if (
            not isinstance(sample, dict)
            or set(sample) != FIELDS
            or sample["environment"] != environment
            or sample["observer_container_id"] != observer_id
            or sample["method"] != "fixed_readonly_observer_clock"
        ):
            raise ValueError("Clock sample does not identify the inspected observer")
        for key in FIELDS - {"environment", "observer_container_id", "method"}:
            if type(sample[key]) is not int or not 0 < sample[key] < 2**63:
                raise ValueError("Clock sample has an invalid nanosecond timestamp")
        wall_elapsed = sample["host_after_ns"] - sample["host_before_ns"]
        elapsed = sample["host_monotonic_after_ns"] - sample["host_monotonic_before_ns"]
        if (
            not 0 < wall_elapsed <= MAX_RTT_NS
            or not 0 < elapsed <= MAX_RTT_NS
            or abs(wall_elapsed - elapsed) > STEP_TOLERANCE_NS
        ):
            raise ValueError("Host clock stepped or the observer round trip exceeded its budget")
    before, after = samples
    start, finish = timestamp_ns(started_at), timestamp_ns(finished_at)
    if not 0 <= finish - start <= MAX_OPERATION_NS:
        raise ValueError("Operation duration is outside the clock-alignment budget")
    # Operation ISO timestamps have microsecond resolution. Allow its single
    # microsecond truncation, not an arbitrary network-timing margin.
    if not -1000 <= start - before["host_after_ns"] <= MAX_SAMPLE_GAP_NS:
        raise ValueError("First clock sample does not immediately precede this operation")
    if not -1000 <= after["host_before_ns"] - finish <= MAX_SAMPLE_GAP_NS:
        raise ValueError("Second clock sample does not immediately follow this operation")
    for wall, mono in (
        ("host_before_ns", "host_monotonic_before_ns"),
        ("observer_realtime_ns", "observer_monotonic_ns"),
    ):
        elapsed = after[mono] - before[mono]
        if elapsed <= 0 or abs(after[wall] - before[wall] - elapsed) > STEP_TOLERANCE_NS:
            raise ValueError("A sampled clock stepped during the operation")
    # An intersection assumes a constant offset and can exclude real packets
    # when a small, permitted slew occurs. Retain the complete envelope of both
    # measured intervals; its explicit stability assumption includes that drift.
    lower = min(s["observer_realtime_ns"] - s["host_after_ns"] for s in samples)
    upper = max(s["observer_realtime_ns"] - s["host_before_ns"] for s in samples)
    if not 0 <= upper - lower <= MAX_UNCERTAINTY_NS:
        raise ValueError("Observer clock bounds conflict or their uncertainty is too wide")
    return {
        "status": "bounded",
        "method": "bracketed_round_trip_offset_envelope",
        "environment": environment,
        "observer_container_id": observer_id,
        "offset_lower_ns": lower,
        "offset_upper_ns": upper,
        "uncertainty_ms": (upper - lower) / 1_000_000,
        "observer_started_at": iso_ns(start + lower),
        "observer_finished_at": iso_ns(finish + upper, ceiling=True),
        "samples": samples,
        "assumption": "Clock offset remained within the envelope of both sampled intervals during this operation and capture publication. Elapsed-clock discrepancies above 20 ms are rejected; unsampled excursions cannot be excluded.",
        "limit": "This conservative observer-clock window can include unrelated packets. It establishes neither exact clock synchronisation nor transaction causality.",
    }
