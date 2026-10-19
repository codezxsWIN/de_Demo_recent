"""Fail-closed learned-role promotion tests."""

import json
import unittest
from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess import pipeline
from vulnassess.errors import ConfigError
from vulnassess.model_governance import (
    PromotionManifest,
    load_manifest,
    recommend_hybrid_role,
    validate_promotion,
)
from vulnassess.role_model import PREPROCESSING_VERSION, LabelledHost, save_model, train
from vulnassess.schema import Feature, Host, Service
from vulnassess.settings import Settings
from vulnassess.store import Store


def labelled(index: int, role: str, port: int, service: str) -> LabelledHost:
    return LabelledHost(
        host=Host(
            ip=f"192.0.2.{index}",
            services=(
                Service(
                    port=port,
                    protocol="tcp",
                    name=service,
                    banner=f"{port}/tcp {service}",
                ),
            ),
        ),
        label=role,
        group=f"synthetic-train-{index}",
        label_source="synthetic",
    )


class TestModelGovernance(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        rows = [
            labelled(1, "web_frontend", 80, "http"),
            labelled(2, "web_frontend", 443, "https"),
            labelled(3, "web_frontend", 8080, "http-alt"),
            labelled(4, "web_frontend", 8443, "https-alt"),
            labelled(5, "database", 3306, "mysql"),
            labelled(6, "database", 5432, "postgres"),
            labelled(7, "database", 27017, "mongodb"),
            labelled(8, "database", 6379, "redis"),
        ]
        cls.model = train(rows, epochs=200)

    def manifest(self, **changes) -> PromotionManifest:
        values = {
            "model_hash": self.model.model_hash,
            "preprocessing_version": PREPROCESSING_VERSION,
            "test_dataset_hash": "a" * 64,
            "test_evidence_status": "VERIFIED",
            "label_source": "human",
            "groups_disjoint": True,
            "manual_tags_used": False,
            "test_groups": 4,
            "metrics": {
                "role_accuracy": 0.90,
                "coverage": 0.90,
                "expected_calibration_error": 0.05,
            },
            "thresholds": {
                "minimum_role_accuracy": 0.85,
                "minimum_coverage": 0.80,
                "maximum_ece": 0.10,
                "prediction_confidence": 0.55,
                "prediction_margin": 0.10,
            },
            "reviewer": "reviewer-1",
            "approval_id": "approval-1",
            "mentor_approval_id": "mentor-1",
            "issued_on": "2026-09-01",
            "expires_on": "2026-12-31",
        }
        values.update(changes)
        return PromotionManifest(**values)

    def test_valid_manifest_authorizes_only_a_model_candidate(self):
        prediction = self.model.predict(
            Host(
                ip="198.51.100.1",
                services=(Service(80, "tcp", "http", banner="80/tcp http"),),
            )
        )
        rule = Feature("unknown", 0.2, "rule", "none observed")

        recommendation = recommend_hybrid_role(
            rule, prediction, self.model, self.manifest(), as_of=date(2026, 9, 7)
        )

        self.assertEqual(recommendation.action, "model_candidate_requires_context_adr")
        self.assertEqual(recommendation.selected_source, "model_candidate")
        self.assertEqual(recommendation.selected_label, "web_frontend")
        self.assertEqual(rule.value, "unknown")

    def test_synthetic_low_metric_weak_policy_and_leakage_are_denied(self):
        cases = {
            "not verified": self.manifest(test_evidence_status="NOT RUN"),
            "low metric": self.manifest(
                metrics={
                    "role_accuracy": 0.70,
                    "coverage": 0.90,
                    "expected_calibration_error": 0.05,
                }
            ),
            "weak threshold": self.manifest(
                thresholds={
                    "minimum_role_accuracy": 0.50,
                    "minimum_coverage": 0.80,
                    "maximum_ece": 0.10,
                    "prediction_confidence": 0.55,
                    "prediction_margin": 0.10,
                }
            ),
            "same training data": self.manifest(
                test_dataset_hash=self.model.training["dataset_hash"]
            ),
            "overlapping groups": self.manifest(groups_disjoint=False),
            "manual tags": self.manifest(manual_tags_used=True),
        }
        for label, manifest in cases.items():
            with self.subTest(case=label), self.assertRaises(ConfigError):
                validate_promotion(self.model, manifest, as_of=date(2026, 9, 7))

    def test_hash_preprocessing_and_expiry_mismatches_are_denied(self):
        cases = {
            "hash": self.manifest(model_hash="different"),
            "preprocessing": self.manifest(preprocessing_version="other"),
            "expired": self.manifest(expires_on="2026-09-06"),
            "not yet valid": self.manifest(issued_on="2026-09-08"),
        }
        for label, manifest in cases.items():
            with self.subTest(case=label), self.assertRaises(ConfigError):
                validate_promotion(self.model, manifest, as_of=date(2026, 9, 7))

    def test_strong_rule_conflict_is_never_overridden(self):
        prediction = self.model.predict(
            Host(
                ip="198.51.100.1",
                services=(Service(80, "tcp", "http", banner="80/tcp http"),),
            )
        )
        rule = Feature("database", 0.9, "rule", "3306/tcp mysql")

        recommendation = recommend_hybrid_role(
            rule, prediction, self.model, self.manifest(), as_of=date(2026, 9, 7)
        )

        self.assertEqual(recommendation.action, "keep_rule_conflict_requires_review")
        self.assertEqual(recommendation.selected_source, "rule")
        self.assertEqual(recommendation.selected_label, "database")

    def test_model_abstention_keeps_the_rule(self):
        prediction = self.model.predict(Host(ip="198.51.100.2"))
        self.assertTrue(prediction.abstained)
        rule = Feature("unknown", 0.2, "rule", "none observed")

        recommendation = recommend_hybrid_role(
            rule, prediction, self.model, self.manifest(), as_of=date(2026, 9, 7)
        )

        self.assertEqual(recommendation.action, "keep_rule_model_abstained")
        self.assertEqual(recommendation.selected_source, "rule")

    def test_canonical_context_rejects_model_activation_without_context_adr(self) -> None:
        settings = Settings(Path(__file__).resolve().parents[1] / "config")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "synthetic_model.json"
            save_model(self.model, artifact)
            with Store(root / "synthetic_context.db") as store:
                store.start_run("synthetic-context", settings.config_hash())
                store.upsert_host(
                    "synthetic-context",
                    Host(
                        ip="172.28.0.10",
                        services=(Service(80, "tcp", "http", banner="80/tcp http"),),
                    ),
                )
                pipeline.do_context(settings, store, "synthetic-context")
                before = store.profiles("synthetic-context")
                with self.assertRaisesRegex(ConfigError, "context-source ADR"):
                    pipeline.do_context(settings, store, "synthetic-context", str(artifact))
                self.assertEqual(store.profiles("synthetic-context"), before)
                self.assertTrue(all(profile.role.source == "rule" for profile in before))

    def test_manifest_loader_rejects_unknown_and_missing_fields(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            payload = self.manifest().to_json()
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_manifest(path)
            self.assertEqual(loaded, self.manifest())

            payload["invented"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ConfigError) as caught:
                load_manifest(path)
            self.assertIn("unknown key", str(caught.exception))

            path.write_text("{}", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_manifest(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
