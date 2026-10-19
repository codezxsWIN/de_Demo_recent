"""Tie-aware and evidence-gated ranking evaluation tests."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess import evaluate
from vulnassess.errors import ConfigError


class TestResearchEvaluation(unittest.TestCase):
    def test_critical_queue_includes_the_entire_tied_block(self):
        order = ["A", ["B", "C"], "D"]

        self.assertEqual(evaluate.critical_queue_at_full_recall(order, {"B"}), 3)
        self.assertEqual(evaluate.critical_queue_at_full_recall(order, {"A", "B"}), 3)
        self.assertIsNone(evaluate.critical_queue_at_full_recall(order, {"missing"}))

    def test_kendall_w_is_tie_corrected(self):
        tied = ["A", ["B", "C"], "D"]

        self.assertEqual(evaluate.kendall_w([tied, tied]), 1.0)

    def test_degenerate_tau_b_stays_undefined(self):
        all_tied = {"A": 1.5, "B": 1.5}

        self.assertIsNone(evaluate.kendall_tau_b(all_tied, all_tied))

    def test_each_expert_has_an_independent_critical_queue(self):
        truth = {
            "evidence_status": "VERIFIED",
            "experts": [
                {
                    "name": "expert-a",
                    "reviewer": "panel-coordinator",
                    "provenance": "signed ranking A",
                    "ranking": ["A", "B", "C", "D"],
                    "critical": ["A", "C"],
                },
                {
                    "name": "expert-b",
                    "reviewer": "panel-coordinator",
                    "provenance": "signed ranking B",
                    "ranking": ["A", "C", "B", "D"],
                    "critical": ["A", "B"],
                },
            ],
        }
        methods = {
            "ours": ["A", "C", "B", "D"],
            "cvss_only": ["B", "A", "D", "C"],
            "cvss_epss": ["A", "B", "D", "C"],
        }

        result = evaluate.evaluate(methods, truth)

        self.assertEqual(
            result["methods"]["ours"]["critical_queue_by_expert"],
            {"expert-a": 2, "expert-b": 3},
        )
        self.assertEqual(
            result["methods"]["cvss_only"]["critical_queue_by_expert"],
            {"expert-a": 4, "expert-b": 2},
        )
        self.assertEqual(
            result["h3"]["reductions_percent"],
            {"expert-a": 50.0, "expert-b": -50.0},
        )
        self.assertEqual(result["h3"]["mean_reduction_percent"], 0.0)
        self.assertTrue(result["h2"]["eligible"])
        self.assertTrue(result["h3"]["eligible"])

    def test_synthetic_and_unverified_truth_never_claim_hypothesis_passes(self):
        methods = {
            "ours": ["A", "B", "C"],
            "cvss_only": ["C", "B", "A"],
            "cvss_epss": ["C", "A", "B"],
        }
        synthetic = {
            "_comment": "SYNTHETIC arithmetic only",
            "experts": [{"name": "fake", "ranking": ["A", "B", "C"]}],
            "expert_critical": ["A"],
        }
        unverified = {
            "experts": [{"name": "person", "ranking": ["A", "B", "C"]}],
            "expert_critical": ["A"],
        }

        synthetic_result = evaluate.evaluate(methods, synthetic)
        unverified_result = evaluate.evaluate(methods, unverified)

        self.assertEqual(synthetic_result["evidence_status"], "NOT RUN")
        self.assertEqual(synthetic_result["data_kind"], "synthetic")
        self.assertFalse(synthetic_result["h2"]["eligible"])
        self.assertIsNone(synthetic_result["h2"]["passes"]["cvss_only"])
        self.assertIsNone(synthetic_result["h3"]["pass"])
        self.assertEqual(unverified_result["evidence_status"], "NOT RUN")
        self.assertEqual(unverified_result["data_kind"], "human")
        self.assertFalse(unverified_result["h2"]["eligible"])
        self.assertFalse(unverified_result["h3"]["eligible"])

    def test_verified_truth_file_requires_reviewer_and_provenance(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "truth.yaml"
            path.write_text(
                """evidence_status: VERIFIED
experts:
  - name: expert-a
    ranking: [A, B]
    critical: [A]
""",
                encoding="utf-8",
            )

            with self.assertRaises(ConfigError) as caught:
                evaluate.load_truth(path)

        self.assertIn("reviewer and provenance", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
