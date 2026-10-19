"""Audit report integration using synthetic pipeline state only."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from tests.test_assessment_snapshot import prepared_store
from vulnassess.cli import main

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "models" / "synthetic-role-model.json"


class TestAuditReport(unittest.TestCase):
    def test_report_shows_validated_present_and_missing_evidence(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "assessment.db"
            with prepared_store(directory) as store:
                profiles = store.profiles("snapshot")
            base = [
                "--config",
                str(ROOT / "config"),
                "--db",
                str(database),
            ]
            snapshot = root / "snapshot.json"
            context_artifact = root / "context.json"
            unification_artifact = root / "unification.json"
            report = root / "audit.html"
            context_truth = root / "context-truth.yaml"
            context_truth.write_text(
                yaml.safe_dump(
                    {
                        "version": 1,
                        "_comment": "SYNTHETIC audit report code-path truth.",
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

            commands = [
                [
                    *base,
                    "research",
                    "snapshot-export",
                    "--run-id",
                    "snapshot",
                    "--out",
                    str(snapshot),
                ],
                [
                    *base,
                    "research",
                    "context-eval",
                    "--run-id",
                    "snapshot",
                    "--truth",
                    str(context_truth),
                    "--out",
                    str(context_artifact),
                ],
                [
                    *base,
                    "unify",
                    "--run-id",
                    "snapshot",
                    "--snapshot",
                    str(snapshot),
                    "--out",
                    str(unification_artifact),
                ],
                [
                    *base,
                    "report",
                    "--run-id",
                    "snapshot",
                    "--out",
                    str(report),
                    "--snapshot",
                    str(snapshot),
                    "--context-artifact",
                    str(context_artifact),
                    "--unification-artifact",
                    str(unification_artifact),
                    "--model",
                    str(MODEL),
                ],
            ]
            with redirect_stdout(io.StringIO()):
                codes = [main(command) for command in commands]
            html = report.read_text(encoding="utf-8")

        self.assertEqual(codes, [0, 0, 0, 0])
        self.assertIn("6. Research and audit evidence", html)
        self.assertIn("assessment snapshot", html)
        self.assertIn("NOT RUN", html)
        self.assertIn("MISSING", html)
        self.assertIn("Intelligence matching decisions", html)
        self.assertIn("Raw-to-group mapping (preview only)", html)
        self.assertIn("shadow role model", html)
        self.assertIn("canonical context unchanged", html)
        self.assertIn("Feature coverage", html)
        self.assertIn("Out-of-vocabulary features", html)
        self.assertIn("Model hash", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("href=", html)
        self.assertNotIn("src=", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
