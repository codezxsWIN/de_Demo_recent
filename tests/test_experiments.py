"""RQ4 ablation and repeated-run stability tests."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess import evaluate, experiments, intel, pipeline
from vulnassess.errors import ConfigError
from vulnassess.settings import Settings
from vulnassess.store import Store

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC = ROOT / "tests" / "synthetic"
SETTINGS = Settings(ROOT / "config")


def prepared_store(directory: str) -> Store:
    store = Store(Path(directory) / "assessment.db")
    run_id = "experiment"
    nmap = SYNTHETIC / "synthetic_nmap_two_machines.xml"
    zap = SYNTHETIC / "synthetic_zap_dvwa.json"
    pipeline.do_import(SETTINGS, store, run_id, "172.28.0.10", nmap)
    pipeline.do_import(SETTINGS, store, run_id, "172.28.0.12", nmap)
    pipeline.do_import(SETTINGS, store, run_id, "172.28.0.11", nmap, zap)
    intel.load_feeds(SYNTHETIC / "feeds", store)
    intel.enrich_run(run_id, store)
    pipeline.do_context(SETTINGS, store, run_id)
    pipeline.do_rank(SETTINGS, store, run_id)
    return store


class TestExperiments(unittest.TestCase):
    def test_all_predeclared_scenarios_run_without_mutating_stored_scores(self):
        with TemporaryDirectory() as directory:
            with prepared_store(directory) as store:
                before = json.dumps(
                    [score.to_json() for score in store.scores("experiment")],
                    sort_keys=True,
                )
                result = experiments.run_ablations(SETTINGS, store, "experiment")
                after = json.dumps(
                    [score.to_json() for score in store.scores("experiment")],
                    sort_keys=True,
                )

        self.assertEqual(set(result["orders"]), set(experiments.SCENARIOS))
        self.assertEqual(before, after)
        self.assertEqual(len(result["experiment_hash"]), 64)
        self.assertFalse(result["config_drift"])

    def test_ablations_report_active_and_inactive_inputs_honestly(self):
        with TemporaryDirectory() as directory:
            with prepared_store(directory) as store:
                result = experiments.run_ablations(SETTINGS, store, "experiment")

        self.assertGreater(result["comparisons"]["no_kev"]["changed_findings"], 0)
        self.assertGreater(result["comparisons"]["no_manual"]["changed_findings"], 0)
        self.assertIn("no_controls", result["inactive_scenarios"])
        self.assertIn("no_role", result["inactive_scenarios"])
        self.assertTrue(result["comparisons"]["no_controls"]["inactive"])

    def test_stability_check_produces_one_score_hash_and_never_rewrites_rows(self):
        with TemporaryDirectory() as directory:
            with prepared_store(directory) as store:
                before = [score.to_json() for score in store.scores("experiment")]
                result = experiments.stability_check(SETTINGS, store, "experiment", 4)
                after = [score.to_json() for score in store.scores("experiment")]

        self.assertTrue(result["deterministic"])
        self.assertEqual(result["unique_score_hashes"], 1)
        self.assertEqual(len(result["score_hashes"]), 4)
        self.assertEqual(before, after)
        self.assertFalse(result["config_drift"])

    def test_expert_metrics_can_be_attached_to_every_experiment_order(self):
        truth = evaluate.load_truth(SYNTHETIC / "synthetic_groundtruth.yaml")
        with TemporaryDirectory() as directory:
            with prepared_store(directory) as store:
                result = experiments.run_ablations(
                    SETTINGS,
                    store,
                    "experiment",
                    scenarios=("full", "no_kev", "no_manual"),
                    truth=truth,
                )

        methods = result["expert_evaluation"]["methods"]
        self.assertEqual(set(methods), {"full", "no_kev", "no_manual"})
        self.assertIn("tau_b_mean", methods["full"])
        self.assertIn("ndcg_at_10_mean", methods["full"])

    def test_expert_metrics_are_filtered_to_the_frozen_cohort(self):
        with TemporaryDirectory() as directory:
            with prepared_store(directory) as store:
                cohort_ids = [item.id for item in store.findings("experiment")[:2]]
                truth = {
                    "_comment": "SYNTHETIC cohort filtering test.",
                    "experts": [
                        {
                            "name": "synthetic-expert",
                            "ranking": list(cohort_ids),
                            "critical": [cohort_ids[0]],
                        }
                    ],
                }
                result = experiments.run_ablations(
                    SETTINGS,
                    store,
                    "experiment",
                    scenarios=("full", "no_kev"),
                    truth=truth,
                    cohort_ids=cohort_ids,
                )

        self.assertEqual(result["evaluation_cohort_ids"], sorted(cohort_ids))
        self.assertEqual(set(result["orders"]["full"]), set(cohort_ids))
        self.assertEqual(len(result["orders"]["full"]), 2)
        self.assertEqual(set(result["expert_evaluation"]["methods"]), {"full", "no_kev"})

    def test_unknown_scenario_and_invalid_repeat_count_fail_closed(self):
        with TemporaryDirectory() as directory:
            with prepared_store(directory) as store:
                with self.assertRaises(ConfigError):
                    experiments.score_scenario(SETTINGS, store, "experiment", "invented")
                with self.assertRaises(ConfigError):
                    experiments.stability_check(SETTINGS, store, "experiment", 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
