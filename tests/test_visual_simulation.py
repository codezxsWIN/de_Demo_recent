"""Regression tests proving simulations use the canonical assessment workbench."""

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from run_visual_simulation import build
from vulnassess.cli import main

ROOT = Path(__file__).resolve().parents[1]
DATABASE = ROOT / "data" / "visual-simulation.db"


def embedded_bootstrap(html: str) -> dict:
    prefix = '<script id="assessment-data" type="application/json">'
    start = html.index(prefix) + len(prefix)
    end = html.index("</script>", start)
    return json.loads(html[start:end])


class TestVisualSimulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = build()
        cls.html = cls.path.read_text(encoding="utf-8")
        cls.bootstrap = embedded_bootstrap(cls.html)
        cls.assessment = cls.bootstrap["assessment"]

    def test_build_exports_actual_synthetic_assessment(self):
        self.assertEqual(self.assessment["run"]["run_id"], "visual-sim")
        self.assertEqual(len(self.assessment["hosts"]), 3)
        self.assertEqual(len(self.assessment["findings"]), 6)
        self.assertEqual(len(self.assessment["context"]), 3)
        self.assertEqual(len(self.assessment["scores"]), 6)
        self.assertTrue(all("provenance" in item for item in self.assessment["findings"]))
        self.assertTrue(all("weights_hash" in item for item in self.assessment["scores"]))

    def test_simulation_uses_the_four_stage_workbench(self):
        for text in (
            "01 / EVIDENCE",
            "02 / CONTEXT",
            "03 / RISK",
            "04 / PRIORITIES",
            "EVIDENCE INSPECTOR",
            "The formation engine",
            "Severity meets exploitation",
            "What deserves attention first?",
        ):
            self.assertIn(text, self.html)
        self.assertEqual(self.html.count('class="stage-panel"'), 4)

    def test_historical_replay_is_not_rendered(self):
        for obsolete in (
            "VulnAssess Pipeline Replay",
            'id="play"',
            'id="restart"',
            'id="stageRail"',
            "const stageRenderers=",
            "Selected finding trace",
        ):
            self.assertNotIn(obsolete, self.html)
        self.assertNotIn("role model:", self.html.lower())

    def test_export_is_self_contained_and_offline(self):
        self.assertTrue(self.bootstrap["offline"])
        self.assertIn("connect-src 'none'", self.html)
        self.assertNotIn('<link rel="stylesheet"', self.html)
        self.assertNotIn('src="/static/', self.html)
        self.assertNotIn(" style=", self.html)
        self.assertIn("Sandbox. Nothing stored changes.", self.html)
        self.assertIn("No persisted expert-evaluation result is attached", self.html)

    def test_same_cve_comparison_keeps_the_golden_divergence(self):
        scores = {
            score["host_ip"]: score
            for score in self.assessment["scores"]
            if score["cve_id"] == "CVE-1999-9001"
        }
        self.assertEqual(scores["172.28.0.12"]["base_score"], 9.8)
        self.assertEqual(scores["172.28.0.10"]["base_score"], 9.8)
        self.assertEqual(scores["172.28.0.12"]["risk"], 100.0)
        self.assertEqual(scores["172.28.0.12"]["band"], "Critical")
        self.assertEqual(scores["172.28.0.10"]["risk"], 79.0)
        self.assertEqual(scores["172.28.0.10"]["band"], "High")

    def test_visualize_command_exports_the_same_interface(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "workbench.html"
            with redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "--db",
                        str(DATABASE),
                        "--config",
                        str(ROOT / "config"),
                        "visualize",
                        "--run-id",
                        "visual-sim",
                        "--out",
                        str(output),
                    ]
                )
            document = output.read_text(encoding="utf-8")
            self.assertEqual(code, 0)
            self.assertEqual(embedded_bootstrap(document)["assessment"], self.assessment)
            self.assertIn("The formation engine", document)
            self.assertNotIn("VulnAssess Pipeline Replay", document)

    def test_ui_export_and_simulation_share_the_renderer(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "ui.html"
            with redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "--db",
                        str(DATABASE),
                        "--config",
                        str(ROOT / "config"),
                        "ui",
                        "--run",
                        "visual-sim",
                        "--export",
                        str(output),
                    ]
                )
            document = output.read_text(encoding="utf-8")
            self.assertEqual(code, 0)
            self.assertEqual(embedded_bootstrap(document)["assessment"], self.assessment)
            for marker in ("stage-evidence", "stage-context", "stage-risk", "stage-priorities"):
                self.assertEqual(marker in document, marker in self.html)

    def test_responsive_and_reduced_motion_rules_are_embedded(self):
        self.assertIn("@media (max-width: 760px)", self.html)
        self.assertIn("prefers-reduced-motion: reduce", self.html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
