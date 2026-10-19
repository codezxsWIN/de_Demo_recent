"""Frozen assessment snapshot tests."""

import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess import intel, pipeline
from vulnassess.assessment_snapshot import (
    build_snapshot,
    load_snapshot,
    save_snapshot,
    validate_snapshot,
)
from vulnassess.errors import ConfigError
from vulnassess.settings import Settings
from vulnassess.store import Store

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC = ROOT / "tests" / "synthetic"
SETTINGS = Settings(ROOT / "config")


def prepared_store(directory: str) -> Store:
    store = Store(Path(directory) / "assessment.db")
    nmap = SYNTHETIC / "synthetic_nmap_two_machines.xml"
    zap = SYNTHETIC / "synthetic_zap_dvwa.json"
    pipeline.do_import(SETTINGS, store, "snapshot", "172.28.0.10", nmap)
    pipeline.do_import(SETTINGS, store, "snapshot", "172.28.0.12", nmap)
    pipeline.do_import(SETTINGS, store, "snapshot", "172.28.0.11", nmap, zap)
    intel.load_feeds(SYNTHETIC / "feeds", store)
    intel.enrich_run("snapshot", store)
    pipeline.do_context(SETTINGS, store, "snapshot")
    pipeline.do_rank(SETTINGS, store, "snapshot")
    return store


class TestAssessmentSnapshot(unittest.TestCase):
    def test_snapshot_contains_every_stage_and_round_trips(self):
        with TemporaryDirectory() as directory:
            with prepared_store(directory) as store:
                snapshot = build_snapshot(SETTINGS, store, "snapshot", model_hash="synthetic-model")
            path = save_snapshot(snapshot, Path(directory) / "snapshot.json")
            loaded = load_snapshot(path)

        self.assertEqual(loaded, snapshot)
        self.assertEqual(len(loaded["hosts"]), 3)
        self.assertEqual(len(loaded["findings"]), 6)
        self.assertEqual(len(loaded["scores"]), 6)
        self.assertEqual(set(loaded["enrichments"]), {item["id"] for item in loaded["findings"]})
        self.assertEqual(loaded["model_hash"], "synthetic-model")
        self.assertFalse(loaded["configuration"]["drift"])
        self.assertEqual(loaded["limitations"], [])
        self.assertIsNotNone(loaded["history"]["intelligence_hash"])

    def test_repeated_snapshot_builds_are_identical(self):
        with TemporaryDirectory() as directory:
            with prepared_store(directory) as store:
                first = build_snapshot(SETTINGS, store, "snapshot")
                second = build_snapshot(SETTINGS, store, "snapshot")

        self.assertEqual(first, second)
        self.assertEqual(len(first["snapshot_hash"]), 64)

    def test_tampering_is_rejected(self):
        with TemporaryDirectory() as directory:
            with prepared_store(directory) as store:
                snapshot = build_snapshot(SETTINGS, store, "snapshot")
        tampered = copy.deepcopy(snapshot)
        tampered["scores"][0]["risk"] = 0

        with self.assertRaises(ConfigError) as caught:
            validate_snapshot(tampered)

        self.assertIn("hash mismatch", str(caught.exception))

    def test_relationship_corruption_is_rejected_even_with_a_recomputed_hash(self):
        with TemporaryDirectory() as directory:
            with prepared_store(directory) as store:
                snapshot = build_snapshot(SETTINGS, store, "snapshot")
        corrupted = copy.deepcopy(snapshot)
        corrupted["scores"][0]["finding_id"] = "missing-finding"
        core = {key: value for key, value in corrupted.items() if key != "snapshot_hash"}
        from vulnassess.assessment_snapshot import _digest

        corrupted["snapshot_hash"] = _digest(core)

        with self.assertRaises(ConfigError) as caught:
            validate_snapshot(corrupted)

        self.assertIn("score without its finding", str(caught.exception))

    def test_missing_snapshot_names_the_path(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"
            with self.assertRaises(ConfigError) as caught:
                load_snapshot(path)
        self.assertIn(str(path), str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
