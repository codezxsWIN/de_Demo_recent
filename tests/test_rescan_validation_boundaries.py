"""Corrupt re-scan artifacts must not become remediation evidence."""

import json
from dataclasses import replace

import pytest

from tests.test_rescan import coverage, finding, host, observation
from vulnassess import rescan
from vulnassess.errors import ConfigError


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("run_id", "", "run_id is required"),
        ("config_hash", "", "config_hash is required"),
        ("feed_snapshot_hash", "", "feed_snapshot_hash is required"),
        ("scope_hash", "", "scope_hash is required"),
        ("findings", (finding(), finding()), "duplicate finding"),
        ("hosts", (host(), host()), "duplicate host"),
        ("coverage", (coverage(), coverage()), "duplicate host/tool"),
        (
            "coverage",
            (replace(coverage(), host_ip="192.0.2.99"),),
            "coverage references missing host",
        ),
    ],
)
def test_observation_rejects_invalid_identity_and_relationships(field, value, message):
    source = replace(observation("before", findings=(finding(),)), **{field: value})
    with pytest.raises(ConfigError, match=message):
        rescan.build_observation_artifact(source, evidence_status="NOT RUN")


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("schema_version", 999, "schema must"),
        ("evidence_status", "complete", "evidence_status"),
        ("unexpected", True, "unknown key"),
        ("hosts", [{}], "invalid re-scan observation"),
        ("run_id", 42, "not canonical"),
    ],
)
def test_hash_valid_but_semantically_invalid_artifacts_fail_closed(tmp_path, field, value, message):
    payload = rescan.build_observation_artifact(observation("before"), evidence_status="NOT RUN")
    payload[field] = value
    payload["observation_hash"] = rescan._digest(
        {k: v for k, v in payload.items() if k != "observation_hash"}
    )
    path = tmp_path / "observation.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        rescan.load_observation_artifact(path)


def test_artifact_must_be_an_object(tmp_path):
    path = tmp_path / "observation.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ConfigError, match="expected an object"):
        rescan.load_observation_artifact(path)


@pytest.mark.parametrize(
    "change,message",
    [
        ({"status": "complete"}, "coverage status"),
        ({"scanner_fingerprint": " "}, "scanner_fingerprint"),
    ],
)
def test_coverage_requires_real_status_and_fingerprint(change, message):
    with pytest.raises(ValueError, match=message):
        replace(coverage(), **change)


@pytest.mark.parametrize(
    "change,message",
    [
        ({"product": "Different"}, "product is missing or changed"),
        ({"version": ""}, "version is missing"),
        ({"version": "not-a-version"}, "not parseable"),
        ({"version": "2.4.48"}, "version decreased"),
    ],
)
def test_absent_finding_does_not_prove_a_fix_with_inadequate_version_evidence(change, message):
    before = observation("before", findings=(finding(),))
    after_host = replace(host(), services=(replace(host().services[0], **change),))
    after = replace(observation("after"), hosts=(after_host,))
    result = rescan.compare_runs(before, after)
    assert result["outcomes"][0]["outcome"] == "still_open"
    assert result["outcomes"][0]["evidence_loss"] is True
    assert message in result["outcomes"][0]["evidence"]


def test_missing_services_and_coverage_are_not_observable():
    before = observation("before", findings=(finding(),))
    for after in (
        replace(observation("after"), coverage=()),
        replace(observation("after"), hosts=()),
    ):
        assert rescan.compare_runs(before, after)["counts"]["not_observable"] == 1
    with pytest.raises(ConfigError, match="duplicate finding"):
        rescan.compare_runs(replace(before, findings=(finding(), finding())), observation("after"))
    assert rescan._origin("/relative/path") is None
    assert rescan._newer_version(None, host().services[0]) == (
        False,
        "service is not observed in both captures",
    )
