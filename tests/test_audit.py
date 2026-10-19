"""Strict audit-artifact loading tests with synthetic JSON only."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess.audit import _digest, load_artifact
from vulnassess.errors import ConfigError


def scan_artifact(status: str = "NOT RUN") -> dict:
    core = {
        "run_id": "synthetic-run",
        "executed": False,
        "evidence_status": status,
        "notice": "not run by the agent",
        "missing": ["nmap"],
    }
    return {**core, "summary_hash": _digest(core)}


class TestAuditArtifacts(unittest.TestCase):
    def test_valid_artifact_round_trips_and_tampering_fails(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            payload = scan_artifact()
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_artifact("scan", path, "synthetic-run")
            payload["missing"] = []
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ConfigError) as caught:
                load_artifact("scan", path, "synthetic-run")

        self.assertEqual(loaded.evidence_status, "NOT RUN")
        self.assertEqual(loaded.artifact_hash, scan_artifact()["summary_hash"])
        self.assertIn("planned only", loaded.summary)
        self.assertIn("hash mismatch", str(caught.exception))

    def test_wrong_run_and_unsupported_status_fail_closed(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            path.write_text(json.dumps(scan_artifact()), encoding="utf-8")
            with self.assertRaises(ConfigError) as run_error:
                load_artifact("scan", path, "other-run")
            invalid = scan_artifact("TESTED WITH SYNTHETIC")
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaises(ConfigError) as status_error:
                load_artifact("scan", path, "synthetic-run")

        self.assertIn("other-run", str(run_error.exception))
        self.assertIn("unsupported evidence_status", str(status_error.exception))

    def test_duplicate_keys_and_non_finite_numbers_are_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            path.write_text(
                '{"run_id":"synthetic-run","run_id":"other","evidence_status":"NOT RUN"}',
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError) as duplicate_error:
                load_artifact("scan", path, "synthetic-run")
            path.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaises(ConfigError) as finite_error:
                load_artifact("scan", path, "synthetic-run")

        self.assertIn("duplicate key", str(duplicate_error.exception))
        self.assertIn("non-finite", str(finite_error.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
