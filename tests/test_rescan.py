"""Comparability-aware re-scan outcome tests."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess.errors import ConfigError
from vulnassess.rescan import (
    CoverageRecord,
    RunObservation,
    build_observation_artifact,
    compare_runs,
    load_observation_artifact,
)
from vulnassess.schema import Finding, Host, Provenance, Service


def finding(
    native_id: str = "vulners:CVE-1999-9001",
    *,
    tool: str = "nmap",
    url: str | None = None,
) -> Finding:
    return Finding.make(
        host_ip="192.0.2.10",
        port=80,
        protocol="tcp",
        url=url,
        tool=tool,
        tool_native_id=native_id,
        title="SYNTHETIC vulnerable Apache",
        description="SYNTHETIC",
        evidence="SYNTHETIC CVE-1999-9001",
        cve_ids=("CVE-1999-9001",),
        first_seen="2026-09-01T00:00:00Z",
        last_seen="2026-09-01T00:00:00Z",
        provenance=Provenance(tool, "tests/synthetic/synthetic_rescan.json", 1, "before"),
    )


def host(version: str = "2.4.49") -> Host:
    return Host(
        ip="192.0.2.10",
        services=(
            Service(
                port=80,
                protocol="tcp",
                name="http",
                product="Apache httpd",
                version=version,
                banner=f"80/tcp http Apache httpd {version}",
            ),
        ),
    )


def coverage(
    *,
    tool: str = "nmap",
    status: str = "success",
    fingerprint: str = "nmap-v1-sV-O-vulners",
    endpoints: tuple[str, ...] = (),
) -> CoverageRecord:
    return CoverageRecord(
        host_ip="192.0.2.10",
        tool=tool,
        status=status,
        scanner_fingerprint=fingerprint,
        endpoints=endpoints,
    )


def observation(
    run_id: str,
    *,
    findings: tuple[Finding, ...] = (),
    version: str = "2.4.49",
    records: tuple[CoverageRecord, ...] | None = None,
    config_hash: str = "config-a",
    feed_hash: str = "feed-a",
    scope_hash: str = "scope-a",
) -> RunObservation:
    return RunObservation(
        run_id=run_id,
        findings=findings,
        hosts=(host(version),),
        coverage=records or (coverage(),),
        config_hash=config_hash,
        feed_snapshot_hash=feed_hash,
        scope_hash=scope_hash,
    )


class TestRescan(unittest.TestCase):
    def test_observation_artifact_round_trips_and_rejects_tampering(self):
        source = observation("before", findings=(finding(),))
        payload = build_observation_artifact(source, evidence_status="NOT RUN")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "observation.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_observation_artifact(path)
            tampered = dict(payload)
            tampered["scope_hash"] = "changed"
            path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(ConfigError) as caught:
                load_observation_artifact(path)

        self.assertEqual(loaded.observation, source)
        self.assertEqual(loaded.evidence_status, "NOT RUN")
        self.assertEqual(loaded.artifact_hash, payload["observation_hash"])
        self.assertIn("hash mismatch", str(caught.exception))

    def test_observation_artifact_requires_known_status_and_host_relationships(self):
        with self.assertRaises(ConfigError):
            build_observation_artifact(observation("before"), evidence_status="SYNTHETIC")
        invalid = RunObservation(
            run_id="before",
            findings=(finding(),),
            hosts=(),
            coverage=(coverage(),),
            config_hash="config-a",
            feed_snapshot_hash="feed-a",
            scope_hash="scope-a",
        )
        with self.assertRaises(ConfigError) as caught:
            build_observation_artifact(invalid, evidence_status="NOT RUN")
        self.assertIn("missing host", str(caught.exception))

    def test_same_fingerprint_is_still_open(self):
        item = finding()
        result = compare_runs(
            observation("before", findings=(item,)),
            observation("after", findings=(item,)),
        )

        self.assertEqual(result["counts"]["still_open"], 1)
        self.assertIn("observed again", result["outcomes"][0]["evidence"])
        self.assertFalse(result["outcomes"][0]["evidence_loss"])

    def test_absence_with_newer_version_is_only_a_fixed_candidate(self):
        item = finding()
        result = compare_runs(
            observation("before", findings=(item,), version="2.4.49"),
            observation("after", version="2.4.51"),
        )

        self.assertEqual(result["counts"]["fixed_candidate"], 1)
        self.assertIn("increased from 2.4.49 to 2.4.51", result["outcomes"][0]["evidence"])
        self.assertIn("human adjudication", result["interpretation"])

    def test_absence_with_unchanged_version_is_still_open_with_evidence_loss(self):
        item = finding()
        result = compare_runs(
            observation("before", findings=(item,)),
            observation("after"),
        )

        outcome = result["outcomes"][0]
        self.assertEqual(outcome["outcome"], "still_open")
        self.assertTrue(outcome["evidence_loss"])
        self.assertIn("unchanged", outcome["evidence"])

    def test_failed_or_changed_scanner_coverage_is_not_observable(self):
        item = finding()
        cases = (
            (coverage(status="failed"), "not successful"),
            (coverage(fingerprint="nmap-v2-different-flags"), "fingerprint changed"),
        )
        for record, message in cases:
            with self.subTest(record=record):
                result = compare_runs(
                    observation("before", findings=(item,)),
                    observation("after", records=(record,)),
                )
                outcome = result["outcomes"][0]
                self.assertEqual(outcome["outcome"], "not_observable")
                self.assertIn(message, outcome["evidence"])

    def test_web_finding_requires_the_same_endpoint_coverage(self):
        item = finding(
            "zap-plugin",
            tool="zap",
            url="http://192.0.2.10/login",
        )
        baseline = observation(
            "before",
            findings=(item,),
            records=(coverage(tool="zap", endpoints=("http://192.0.2.10",)),),
        )
        after = observation(
            "after",
            records=(coverage(tool="zap", endpoints=("http://192.0.2.10:8080",)),),
        )

        result = compare_runs(baseline, after)

        self.assertEqual(result["outcomes"][0]["outcome"], "not_observable")
        self.assertIn("endpoint", result["outcomes"][0]["evidence"])

    def test_new_finding_on_previously_covered_instance_is_a_regression_candidate(self):
        item = finding("new-cve")
        result = compare_runs(
            observation("before"),
            observation("after", findings=(item,)),
        )

        self.assertEqual(result["counts"]["regression_candidate"], 1)
        self.assertIn("previously observed", result["outcomes"][0]["evidence"])

    def test_new_finding_without_baseline_coverage_stays_new(self):
        item = finding("new-zap", tool="zap", url="http://192.0.2.10/")
        result = compare_runs(
            observation("before", records=(coverage(),)),
            observation(
                "after",
                findings=(item,),
                records=(coverage(tool="zap", endpoints=("http://192.0.2.10",)),),
            ),
        )

        self.assertEqual(result["counts"]["new_finding"], 1)

    def test_configuration_feed_and_scope_drift_remain_visible(self):
        result = compare_runs(
            observation("before"),
            observation(
                "after",
                config_hash="config-b",
                feed_hash="feed-b",
                scope_hash="scope-b",
            ),
        )

        self.assertEqual(
            result["drift"],
            {
                "config_changed": True,
                "feed_snapshot_changed": True,
                "scope_changed": True,
            },
        )

    def test_same_run_id_and_duplicate_findings_fail_closed(self):
        with self.assertRaises(ConfigError):
            compare_runs(observation("same"), observation("same"))

        item = finding()
        with self.assertRaises(ConfigError):
            compare_runs(
                observation("before", findings=(item, item)),
                observation("after"),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
