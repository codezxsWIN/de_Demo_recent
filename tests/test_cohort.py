"""Blind cohort freeze tests using synthetic pure-logic records only."""

import copy
import json
import unittest
from hashlib import sha256
from tempfile import TemporaryDirectory

import yaml

from vulnassess.assessment_snapshot import _digest
from vulnassess.cohort import (
    METRICS,
    freeze_cohort,
    load_evidence,
    load_manifest,
    save_cohort,
    validate_snapshot_against_manifest,
    validate_truth_against_cohort,
)
from vulnassess.errors import ConfigError


def synthetic_snapshot(count: int = 3) -> dict:
    host = {
        "ip": "172.28.0.10",
        "hostname": "synthetic-host",
        "os_guess": "synthetic-os",
        "services": [
            {
                "port": 443,
                "protocol": "tcp",
                "name": "https",
                "product": "synthetic-service",
                "version": "1.0",
                "cpe": None,
                "banner": "synthetic banner",
                "tls": True,
            }
        ],
    }
    findings = []
    for index in range(count):
        finding_id = f"finding-{index:02d}"
        findings.append(
            {
                "id": finding_id,
                "host_ip": host["ip"],
                "port": 443,
                "protocol": "tcp",
                "url": f"https://{host['ip']}/synthetic/{index}",
                "tool": "synthetic",
                "tool_native_id": f"SYN-{index}",
                "title": f"Synthetic finding {index}",
                "description": "synthetic description",
                "evidence": f"synthetic evidence {index}",
                "cve_ids": [],
                "cwe_ids": [],
                "reference_urls": [],
                "native_severity": "medium",
                "native_confidence": "synthetic",
                "first_seen": "",
                "last_seen": "",
                "provenance": {
                    "tool": "synthetic",
                    "raw_path": "tests/synthetic/synthetic_cohort_input.json",
                    "record_index": index,
                    "run_id": "synthetic-cohort-run",
                },
            }
        )
    core = {
        "schema_version": 1,
        "evidence_status": "NOT RUN",
        "run": {
            "run_id": "synthetic-cohort-run",
            "config_hash": sha256(b"synthetic-config").hexdigest()[:16],
        },
        "configuration": {
            "hash_current": sha256(b"synthetic-config").hexdigest()[:16],
            "hash_at_run_start": sha256(b"synthetic-config").hexdigest()[:16],
            "drift": False,
            "validated": {"weights.yaml": {"synthetic": True}},
        },
        "feed_snapshot": {},
        "model_hash": None,
        "hosts": [host],
        "findings": findings,
        "enrichments": {finding["id"]: [] for finding in findings},
        "profiles": [],
        "scores": [],
        "rationales": {},
        "limitations": ["synthetic pure-logic input"],
    }
    return {**core, "snapshot_hash": _digest(core)}


class TestCohortFreeze(unittest.TestCase):
    def test_freeze_is_blind_deterministic_and_hash_bound(self):
        snapshot = synthetic_snapshot()
        first, first_items = freeze_cohort(
            snapshot,
            ["finding-02", "finding-00"],
            cohort_id="synthetic-pilot",
            created_on="2026-09-10",
            evidence_status="NOT RUN",
        )
        second, second_items = freeze_cohort(
            snapshot,
            ["finding-00", "finding-02"],
            cohort_id="synthetic-pilot",
            created_on="2026-09-10",
            evidence_status="NOT RUN",
        )

        self.assertEqual(first, second)
        self.assertEqual(first_items, second_items)
        self.assertEqual(first.finding_ids, ("finding-00", "finding-02"))
        self.assertEqual(first.metrics, METRICS)
        self.assertEqual(
            first.grouping_map,
            {"finding-00": ("finding-00",), "finding-02": ("finding-02",)},
        )
        self.assertEqual(len(first.config_hash), 16)
        self.assertEqual(first.snapshot_hash, snapshot["snapshot_hash"])
        self.assertEqual(len(first.weights_hash), 64)
        self.assertEqual(len(first.feed_snapshot_hash), 64)
        forbidden = {"score", "scores", "risk", "band", "rank", "reason", "rationale"}
        for item in first_items:
            self.assertFalse(forbidden.intersection(item))
            self.assertFalse(forbidden.intersection(item["finding"]))
        self.assertEqual(validate_snapshot_against_manifest(snapshot, first), first_items)

    def test_save_round_trip_and_evidence_tampering(self):
        manifest, items = freeze_cohort(
            synthetic_snapshot(),
            ["finding-00", "finding-01"],
            cohort_id="synthetic-pilot",
            created_on="2026-09-10",
            evidence_status="NOT RUN",
        )
        with TemporaryDirectory() as directory:
            output = save_cohort(manifest, items, directory)
            loaded_manifest = load_manifest(output / "manifest.json")
            loaded_items = load_evidence(output / "evidence.json", loaded_manifest)
            template = yaml.safe_load(
                (output / "expert-ranking-template.yaml").read_text(encoding="utf-8")
            )
            tampered_items = copy.deepcopy(loaded_items)
            tampered_items[0]["finding"]["title"] = "changed"
            (output / "evidence.json").write_text(json.dumps(tampered_items), encoding="utf-8")

            with self.assertRaises(ConfigError) as caught:
                load_evidence(output / "evidence.json", loaded_manifest)

        self.assertEqual(loaded_manifest, manifest)
        self.assertEqual(template["cohort_hash"], manifest.manifest_hash)
        self.assertIn("does not match", str(caught.exception))

    def test_manifest_tampering_is_rejected(self):
        manifest, items = freeze_cohort(
            synthetic_snapshot(),
            ["finding-00"],
            cohort_id="synthetic-pilot",
            created_on="2026-09-10",
            evidence_status="NOT RUN",
        )
        with TemporaryDirectory() as directory:
            output = save_cohort(manifest, items, directory)
            path = output / "manifest.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["cohort_id"] = "tampered"
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(ConfigError) as caught:
                load_manifest(path)

        self.assertIn("hash mismatch", str(caught.exception))

    def test_truth_must_match_hash_and_cover_every_finding_once(self):
        manifest, _ = freeze_cohort(
            synthetic_snapshot(),
            ["finding-00", "finding-01", "finding-02"],
            cohort_id="synthetic-pilot",
            created_on="2026-09-10",
            evidence_status="NOT RUN",
        )
        truth = {
            "cohort_id": manifest.cohort_id,
            "cohort_hash": manifest.manifest_hash,
            "experts": [
                {
                    "name": "synthetic-expert",
                    "ranking": [["finding-00", "finding-01"], "finding-02"],
                    "critical": ["finding-00"],
                }
            ],
        }

        self.assertIs(validate_truth_against_cohort(truth, manifest), truth)
        incomplete = copy.deepcopy(truth)
        incomplete["experts"][0]["ranking"] = ["finding-00", "finding-01"]
        with self.assertRaises(ConfigError) as incomplete_error:
            validate_truth_against_cohort(incomplete, manifest)
        wrong_hash = copy.deepcopy(truth)
        wrong_hash["cohort_hash"] = "0" * 64
        with self.assertRaises(ConfigError) as hash_error:
            validate_truth_against_cohort(wrong_hash, manifest)
        overstated = copy.deepcopy(truth)
        overstated["evidence_status"] = "VERIFIED"
        with self.assertRaises(ConfigError) as evidence_error:
            validate_truth_against_cohort(overstated, manifest)

        self.assertIn("exactly cover", str(incomplete_error.exception))
        self.assertIn("cohort_hash", str(hash_error.exception))
        self.assertIn("VERIFIED cohort", str(evidence_error.exception))

    def test_confirmatory_cohort_rejects_too_few_findings(self):
        with self.assertRaises(ConfigError) as caught:
            freeze_cohort(
                synthetic_snapshot(),
                ["finding-00", "finding-01"],
                cohort_id="invalid-confirmatory",
                created_on="2026-09-10",
                evidence_status="VERIFIED",
                reviewer="synthetic-reviewer",
                approval_id="synthetic-approval",
            )

        self.assertIn("20-50", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
