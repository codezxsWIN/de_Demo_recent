"""Operational preview CLI tests using synthetic pure-logic inputs only."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.test_assessment_snapshot import prepared_store
from tests.test_rescan import finding, observation
from vulnassess.assessment_snapshot import build_snapshot, save_snapshot
from vulnassess.cli import main
from vulnassess.model_governance import PromotionManifest
from vulnassess.rescan import build_observation_artifact
from vulnassess.role_model import PREPROCESSING_VERSION, load_model
from vulnassess.settings import Settings
from vulnassess.store import Store

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = Settings(ROOT / "config")
MODEL_PATH = ROOT / "models" / "synthetic-role-model.json"


class TestOperationsCli(unittest.TestCase):
    def _base(self, database: Path) -> list[str]:
        return [
            "--config",
            str(ROOT / "config"),
            "--db",
            str(database),
        ]

    def test_unification_is_snapshot_bound_and_does_not_change_scores(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "assessment.db"
            with prepared_store(directory) as store:
                before = [item.to_json() for item in store.scores("snapshot")]
                snapshot = build_snapshot(SETTINGS, store, "snapshot")
            snapshot_path = save_snapshot(snapshot, root / "snapshot.json")
            output_path = root / "unification.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(
                    self._base(database)
                    + [
                        "unify",
                        "--run-id",
                        "snapshot",
                        "--snapshot",
                        str(snapshot_path),
                        "--out",
                        str(output_path),
                        "--json",
                    ]
                )
            result = json.loads(stdout.getvalue())
            saved = json.loads(output_path.read_text(encoding="utf-8"))
            with Store(database) as store:
                after = [item.to_json() for item in store.scores("snapshot")]

        self.assertEqual(code, 0)
        self.assertEqual(result["mode"], "preview_only")
        self.assertFalse(result["downstream_ranking_changed"])
        self.assertEqual(result["snapshot_hash"], snapshot["snapshot_hash"])
        self.assertEqual(result["raw_count"], len(snapshot["findings"]))
        self.assertEqual(len(result["preview_hash"]), 64)
        self.assertEqual(saved["preview_hash"], result["preview_hash"])
        self.assertEqual(before, after)

    def test_rescan_compares_hash_verified_observations_without_claiming_fixed(self):
        baseline = observation("before", findings=(finding(),), version="2.4.49")
        follow_up = observation("after", version="2.4.51")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            before_path = root / "before.json"
            after_path = root / "after.json"
            before_path.write_text(
                json.dumps(build_observation_artifact(baseline, evidence_status="NOT RUN")),
                encoding="utf-8",
            )
            after_path.write_text(
                json.dumps(build_observation_artifact(follow_up, evidence_status="NOT RUN")),
                encoding="utf-8",
            )
            output_path = root / "comparison.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(
                    self._base(root / "unused.db")
                    + [
                        "rescan",
                        "--run-id",
                        "after",
                        "--before",
                        str(before_path),
                        "--after",
                        str(after_path),
                        "--out",
                        str(output_path),
                        "--json",
                    ]
                )
            result = json.loads(stdout.getvalue())

        self.assertEqual(code, 0)
        self.assertEqual(result["evidence_status"], "NOT RUN")
        self.assertEqual(result["counts"]["fixed_candidate"], 1)
        self.assertNotIn("fixed", result["counts"])
        self.assertIn("human adjudication", result["interpretation"])
        self.assertEqual(len(result["comparison_hash"]), 64)

    def test_promotion_and_hybrid_preview_are_read_only_and_fail_closed(self):
        model = load_model(MODEL_PATH)
        manifest = PromotionManifest(
            model_hash=model.model_hash,
            preprocessing_version=PREPROCESSING_VERSION,
            test_dataset_hash="f" * 64,
            test_evidence_status="VERIFIED",
            label_source="human",
            groups_disjoint=True,
            manual_tags_used=False,
            test_groups=4,
            metrics={
                "role_accuracy": 0.90,
                "coverage": 0.90,
                "expected_calibration_error": 0.05,
            },
            thresholds={
                "minimum_role_accuracy": 0.85,
                "minimum_coverage": 0.80,
                "maximum_ece": 0.10,
                "prediction_confidence": 0.55,
                "prediction_margin": 0.10,
            },
            reviewer="synthetic-reviewer",
            approval_id="synthetic-approval",
            mentor_approval_id="synthetic-mentor-approval",
            issued_on="2026-09-01",
            expires_on="2026-12-31",
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "assessment.db"
            with prepared_store(directory) as store:
                before = [item.to_json() for item in store.profiles("snapshot")]
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest.to_json()), encoding="utf-8")

            validation_output = io.StringIO()
            with redirect_stdout(validation_output):
                validation_code = main(
                    self._base(database)
                    + [
                        "model",
                        "validate-promotion",
                        "--model",
                        str(MODEL_PATH),
                        "--manifest",
                        str(manifest_path),
                        "--as-of",
                        "2026-09-10",
                        "--json",
                    ]
                )
            validation = json.loads(validation_output.getvalue())

            preview_output = io.StringIO()
            with redirect_stdout(preview_output):
                preview_code = main(
                    self._base(database)
                    + [
                        "model",
                        "hybrid-preview",
                        "--run-id",
                        "snapshot",
                        "--model",
                        str(MODEL_PATH),
                        "--manifest",
                        str(manifest_path),
                        "--as-of",
                        "2026-09-10",
                        "--json",
                    ]
                )
            preview = json.loads(preview_output.getvalue())
            with Store(database) as store:
                after = [item.to_json() for item in store.profiles("snapshot")]

            denied = manifest.to_json()
            denied["test_evidence_status"] = "NOT RUN"
            manifest_path.write_text(json.dumps(denied), encoding="utf-8")
            errors = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                denied_code = main(
                    self._base(database)
                    + [
                        "model",
                        "validate-promotion",
                        "--model",
                        str(MODEL_PATH),
                        "--manifest",
                        str(manifest_path),
                        "--as-of",
                        "2026-09-10",
                    ]
                )

        self.assertEqual(validation_code, 0)
        self.assertTrue(validation["authorized"])
        self.assertFalse(validation["canonical_context_changed"])
        self.assertEqual(preview_code, 0)
        self.assertFalse(preview["canonical_context_changed"])
        self.assertIn("SHADOW ONLY", preview["notice"])
        self.assertEqual(len(preview["recommendations"]), 3)
        self.assertEqual(before, after)
        self.assertEqual(denied_code, 2)
        self.assertIn("promotion denied", errors.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
