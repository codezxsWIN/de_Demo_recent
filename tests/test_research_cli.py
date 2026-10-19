"""Research CLI tests using synthetic pipeline state only."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from tests.test_assessment_snapshot import prepared_store
from vulnassess.assessment_snapshot import load_snapshot
from vulnassess.cli import main
from vulnassess.cohort import load_manifest
from vulnassess.store import Store

ROOT = Path(__file__).resolve().parents[1]


class TestResearchCli(unittest.TestCase):
    def _base(self, database: Path) -> list[str]:
        return [
            "--config",
            str(ROOT / "config"),
            "--db",
            str(database),
            "research",
        ]

    def test_snapshot_and_cohort_commands_round_trip_without_store_mutation(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "assessment.db"
            with prepared_store(directory) as store:
                before = [item.to_json() for item in store.scores("snapshot")]

            snapshot_path = root / "snapshot.json"
            output = io.StringIO()
            with redirect_stdout(output):
                export_code = main(
                    self._base(database)
                    + [
                        "snapshot-export",
                        "--run-id",
                        "snapshot",
                        "--out",
                        str(snapshot_path),
                        "--json",
                    ]
                )
            export_result = json.loads(output.getvalue())
            snapshot = load_snapshot(snapshot_path)

            output = io.StringIO()
            with redirect_stdout(output):
                verify_code = main(
                    self._base(database)
                    + [
                        "snapshot-verify",
                        "--run-id",
                        "snapshot",
                        "--snapshot",
                        str(snapshot_path),
                        "--json",
                    ]
                )
            verify_result = json.loads(output.getvalue())

            finding_ids = [item["id"] for item in snapshot["findings"][:2]]
            cohort_dir = root / "cohort"
            output = io.StringIO()
            with redirect_stdout(output):
                freeze_code = main(
                    self._base(database)
                    + [
                        "cohort-freeze",
                        "--run-id",
                        "snapshot",
                        "--snapshot",
                        str(snapshot_path),
                        "--cohort-id",
                        "synthetic-pilot",
                        "--created-on",
                        "2026-09-10",
                        "--evidence-status",
                        "NOT RUN",
                        "--out-dir",
                        str(cohort_dir),
                        "--finding-id",
                        finding_ids[1],
                        "--finding-id",
                        finding_ids[0],
                        "--json",
                    ]
                )
            freeze_result = json.loads(output.getvalue())

            output = io.StringIO()
            with redirect_stdout(output):
                cohort_verify_code = main(
                    self._base(database)
                    + [
                        "cohort-verify",
                        "--run-id",
                        "snapshot",
                        "--manifest",
                        str(cohort_dir / "manifest.json"),
                        "--evidence",
                        str(cohort_dir / "evidence.json"),
                        "--json",
                    ]
                )
            cohort_result = json.loads(output.getvalue())
            with Store(database) as store:
                after = [item.to_json() for item in store.scores("snapshot")]

        self.assertEqual(
            (export_code, verify_code, freeze_code, cohort_verify_code),
            (0, 0, 0, 0),
        )
        self.assertEqual(export_result["snapshot_hash"], verify_result["snapshot_hash"])
        self.assertEqual(export_result["findings"], 6)
        self.assertEqual(freeze_result["findings"], 2)
        self.assertEqual(freeze_result["evidence_status"], "NOT RUN")
        self.assertTrue(cohort_result["evidence_verified"])
        self.assertFalse(cohort_result["truth_validated"])
        self.assertEqual(before, after)

    def test_cohort_verify_requires_exact_truth_and_matching_run(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "assessment.db"
            with prepared_store(directory):
                pass
            snapshot_path = root / "snapshot.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        self._base(database)
                        + [
                            "snapshot-export",
                            "--run-id",
                            "snapshot",
                            "--out",
                            str(snapshot_path),
                        ]
                    ),
                    0,
                )
            finding_ids = [item["id"] for item in load_snapshot(snapshot_path)["findings"][:2]]
            cohort_dir = root / "cohort"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        self._base(database)
                        + [
                            "cohort-freeze",
                            "--run-id",
                            "snapshot",
                            "--snapshot",
                            str(snapshot_path),
                            "--cohort-id",
                            "synthetic-pilot",
                            "--created-on",
                            "2026-09-10",
                            "--evidence-status",
                            "NOT RUN",
                            "--out-dir",
                            str(cohort_dir),
                            "--finding-id",
                            finding_ids[0],
                            "--finding-id",
                            finding_ids[1],
                        ]
                    ),
                    0,
                )
            manifest = load_manifest(cohort_dir / "manifest.json")
            truth_path = root / "truth.yaml"
            truth = {
                "_comment": "SYNTHETIC expert ranking for a CLI code-path test.",
                "cohort_id": manifest.cohort_id,
                "cohort_hash": manifest.manifest_hash,
                "experts": [
                    {
                        "name": "synthetic-expert",
                        "ranking": [[finding_ids[0], finding_ids[1]]],
                        "critical": [finding_ids[0]],
                    }
                ],
            }
            truth_path.write_text(yaml.safe_dump(truth, sort_keys=False), encoding="utf-8")

            with redirect_stdout(io.StringIO()):
                valid_code = main(
                    self._base(database)
                    + [
                        "cohort-verify",
                        "--run-id",
                        "snapshot",
                        "--manifest",
                        str(cohort_dir / "manifest.json"),
                        "--evidence",
                        str(cohort_dir / "evidence.json"),
                        "--truth",
                        str(truth_path),
                    ]
                )

            bundle = [
                "--snapshot",
                str(snapshot_path),
                "--manifest",
                str(cohort_dir / "manifest.json"),
                "--evidence",
                str(cohort_dir / "evidence.json"),
                "--truth",
                str(truth_path),
            ]
            ranking_output = io.StringIO()
            with redirect_stdout(ranking_output):
                ranking_code = main(
                    self._base(database)
                    + ["ranking-eval", "--run-id", "snapshot", *bundle, "--json"]
                )
            ranking_result = json.loads(ranking_output.getvalue())

            ablation_output = io.StringIO()
            with redirect_stdout(ablation_output):
                ablation_code = main(
                    self._base(database)
                    + [
                        "ablate",
                        "--run-id",
                        "snapshot",
                        "--scenario",
                        "no_kev",
                        *bundle,
                        "--json",
                    ]
                )
            ablation_result = json.loads(ablation_output.getvalue())

            stability_output = io.StringIO()
            with redirect_stdout(stability_output):
                stability_code = main(
                    self._base(database)
                    + [
                        "stability",
                        "--run-id",
                        "snapshot",
                        "--snapshot",
                        str(snapshot_path),
                        "--repeats",
                        "3",
                        "--json",
                    ]
                )
            stability_result = json.loads(stability_output.getvalue())

            truth["experts"][0]["ranking"] = [finding_ids[0]]
            truth_path.write_text(yaml.safe_dump(truth, sort_keys=False), encoding="utf-8")
            errors = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                incomplete_code = main(
                    self._base(database)
                    + [
                        "cohort-verify",
                        "--run-id",
                        "snapshot",
                        "--manifest",
                        str(cohort_dir / "manifest.json"),
                        "--evidence",
                        str(cohort_dir / "evidence.json"),
                        "--truth",
                        str(truth_path),
                    ]
                )
                wrong_run_code = main(
                    self._base(database)
                    + [
                        "cohort-verify",
                        "--run-id",
                        "different-run",
                        "--manifest",
                        str(cohort_dir / "manifest.json"),
                        "--evidence",
                        str(cohort_dir / "evidence.json"),
                    ]
                )

        self.assertEqual(valid_code, 0)
        self.assertEqual(ranking_code, 0)
        self.assertEqual(ablation_code, 0)
        self.assertEqual(stability_code, 0)
        self.assertEqual(ranking_result["cohort_hash"], manifest.manifest_hash)
        self.assertEqual(set(ranking_result["methods"]["ours"]["tau_b"]), {"synthetic-expert"})
        self.assertEqual(set(ablation_result["orders"]["full"]), set(finding_ids))
        self.assertEqual(
            ablation_result["research_binding"]["snapshot_hash"],
            manifest.snapshot_hash,
        )
        self.assertTrue(stability_result["deterministic"])
        self.assertEqual(stability_result["unique_score_hashes"], 1)
        self.assertEqual(incomplete_code, 2)
        self.assertEqual(wrong_run_code, 2)
        self.assertIn("exactly cover", errors.getvalue())
        self.assertIn("different-run", errors.getvalue())

    def test_context_eval_reports_synthetic_truth_as_ineligible(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "assessment.db"
            with prepared_store(directory) as store:
                profiles = store.profiles("snapshot")
            truth_path = root / "context-truth.yaml"
            truth_path.write_text(
                yaml.safe_dump(
                    {
                        "version": 1,
                        "_comment": "SYNTHETIC context truth for a CLI code-path test.",
                        "hosts": [
                            {
                                "host_ip": profile.host_ip,
                                "group": f"synthetic-{profile.host_ip}",
                                "role": str(profile.role.value),
                                "exposure": str(profile.exposure.value),
                                "controls": {
                                    key: bool(feature.value)
                                    for key, feature in profile.controls.items()
                                },
                                "label_source": "synthetic",
                                "provenance": "synthetic pure-logic test",
                            }
                            for profile in profiles
                        ],
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(
                    self._base(database)
                    + [
                        "context-eval",
                        "--run-id",
                        "snapshot",
                        "--truth",
                        str(truth_path),
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())

        self.assertEqual(code, 0)
        self.assertEqual(result["truth_hosts"], 3)
        self.assertFalse(result["h1"]["eligible"])
        self.assertIn("synthetic", result["h1"]["reason"])
        self.assertIsNone(result["model_hash"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
