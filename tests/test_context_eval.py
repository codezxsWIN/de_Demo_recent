"""RQ1 context-evaluation arithmetic and truth-boundary tests."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess.context_eval import ContextTruth, evaluate_context, load_context_truth
from vulnassess.errors import ConfigError
from vulnassess.schema import ContextProfile, Feature


def feature(value, confidence: float = 0.9, evidence: str = "synthetic evidence") -> Feature:
    return Feature(value, confidence, "rule", evidence)


def profile(
    host_ip: str,
    role: str,
    exposure: str,
    *,
    controls: dict[str, bool] | None = None,
    manual: bool = False,
) -> ContextProfile:
    return ContextProfile(
        host_ip=host_ip,
        role=feature(role, 0.2 if role == "unknown" else 0.9),
        exposure=feature(exposure),
        controls={
            key: feature(value, 0.75 if value else 0.5, "synthetic control evidence")
            for key, value in (controls or {}).items()
        },
        manual=(
            {"environment": Feature("test", 1.0, "manual", "synthetic manual evidence")}
            if manual
            else {}
        ),
    )


def truth(
    host_ip: str,
    role: str,
    exposure: str,
    *,
    controls: dict[str, bool | None] | None = None,
    source: str = "synthetic",
) -> ContextTruth:
    return ContextTruth(
        host_ip=host_ip,
        group=f"group-{host_ip}",
        role=role,
        exposure=exposure,
        controls=controls or {},
        label_source=source,
        reviewer="reviewer" if source == "human" else None,
        provenance="inventory record" if source == "human" else "synthetic case",
    )


class TestContextEvaluation(unittest.TestCase):
    def test_rule_model_and_exposure_metrics_use_the_full_truth_denominator(self):
        profiles = [
            profile("192.0.2.1", "database", "internet_facing"),
            profile("192.0.2.2", "unknown", "internal", manual=True),
        ]
        labels = [
            truth("192.0.2.1", "database", "internet_facing"),
            truth("192.0.2.2", "web_frontend", "internal"),
        ]
        model = {
            "192.0.2.1": {
                "label": "database",
                "confidence": 0.98,
                "abstained": False,
            },
            "192.0.2.2": {
                "label": "web_frontend",
                "confidence": 0.88,
                "abstained": False,
            },
        }

        result = evaluate_context(profiles, labels, model)

        self.assertEqual(result["rule_role"]["accuracy"], 0.5)
        self.assertEqual(result["rule_role"]["coverage"], 0.5)
        self.assertEqual(result["rule_role"]["selective_accuracy"], 1.0)
        self.assertEqual(result["rule_role"]["macro_f1"], 0.5)
        self.assertEqual(result["model_role"]["accuracy"], 1.0)
        self.assertEqual(result["model_role"]["coverage"], 1.0)
        self.assertEqual(result["exposure"]["accuracy"], 1.0)
        self.assertFalse(result["manual_tags_used"])
        self.assertFalse(result["h1"]["eligible"])
        self.assertIn("synthetic", result["h1"]["reason"])

    def test_missing_profile_is_counted_wrong_not_silently_dropped(self):
        labels = [
            truth("192.0.2.1", "database", "internal"),
            truth("192.0.2.2", "web_frontend", "internal"),
        ]

        result = evaluate_context([profile("192.0.2.1", "database", "internal")], labels)

        self.assertEqual(result["missing_profile_hosts"], ["192.0.2.2"])
        self.assertEqual(result["rule_role"]["examples"], 2)
        self.assertEqual(result["rule_role"]["accuracy"], 0.5)
        self.assertEqual(result["rule_role"]["missing_rate"], 0.5)
        self.assertEqual(
            result["rule_role"]["confusion_matrix"]["web_frontend"]["__missing__"],
            1,
        )

    def test_control_truth_uses_only_applicable_labels(self):
        profiles = [
            profile("192.0.2.1", "database", "internal", controls={"waf": True}),
            profile("192.0.2.2", "web_frontend", "internal", controls={"waf": False}),
            profile("192.0.2.3", "mail", "internal", controls={"waf": False}),
        ]
        labels = [
            truth("192.0.2.1", "database", "internal", controls={"waf": True}),
            truth("192.0.2.2", "web_frontend", "internal", controls={"waf": False}),
            truth("192.0.2.3", "mail", "internal", controls={"waf": None}),
        ]

        result = evaluate_context(profiles, labels)

        self.assertEqual(result["controls"]["waf"]["examples"], 2)
        self.assertEqual(result["controls"]["waf"]["accuracy"], 1.0)
        self.assertIsNone(result["controls"]["tls"]["accuracy"])
        self.assertIsNone(result["controls"]["tls"]["macro_f1"])

    def test_unknown_control_abstains_instead_of_counting_as_false(self):
        profiles = [profile("192.0.2.1", "web_frontend", "internal")]
        profiles[0].controls["waf"] = feature(None, 0.0, "none observed")
        labels = [truth("192.0.2.1", "web_frontend", "internal", controls={"waf": False})]

        result = evaluate_context(profiles, labels)

        self.assertEqual(result["controls"]["waf"]["coverage"], 0.0)
        self.assertEqual(result["controls"]["waf"]["accuracy"], 0.0)

        profiles[0].controls["waf"] = feature(False, 0.5, "none observed")
        legacy = evaluate_context(profiles, labels)
        self.assertEqual(legacy["controls"]["waf"]["coverage"], 0.0)

    def test_rule_model_disagreement_retains_rule_evidence(self):
        profiles = [
            profile(
                "192.0.2.1",
                "web_frontend",
                "internal",
            )
        ]
        labels = [truth("192.0.2.1", "database", "internal")]

        result = evaluate_context(
            profiles,
            labels,
            {
                "192.0.2.1": {
                    "label": "database",
                    "confidence": 0.91,
                    "abstained": False,
                }
            },
        )

        self.assertEqual(len(result["rule_model_disagreements"]), 1)
        disagreement = result["rule_model_disagreements"][0]
        self.assertEqual(disagreement["truth"], "database")
        self.assertEqual(disagreement["rule"], "web_frontend")
        self.assertEqual(disagreement["model"], "database")
        self.assertEqual(disagreement["rule_evidence"], "synthetic evidence")

    def test_human_truth_is_h1_eligible_only_when_every_profile_exists(self):
        labels = [truth("192.0.2.1", "database", "internal", source="human")]
        result = evaluate_context([profile("192.0.2.1", "database", "internal")], labels)

        self.assertTrue(result["h1"]["eligible"])
        self.assertTrue(result["h1"]["role_pass"])
        self.assertTrue(result["h1"]["exposure_pass"])
        self.assertEqual(result["status"], "VERIFIED")

    def test_truth_loader_requires_schema_reviewer_and_provenance(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "valid.yaml"
            valid.write_text(
                """version: 1
hosts:
  - host_ip: 192.0.2.1
    group: capture-a
    role: database
    exposure: internal
    controls: {waf: false}
    label_source: human
    reviewer: analyst-1
    provenance: asset inventory row 7
""",
                encoding="utf-8",
            )
            loaded = load_context_truth(valid)
            self.assertEqual(loaded[0].role, "database")

            missing = root / "missing.yaml"
            missing.write_text(
                """version: 1
hosts:
  - host_ip: 192.0.2.1
    group: capture-a
    role: database
    exposure: internal
    label_source: human
""",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError) as caught:
                load_context_truth(missing)
            self.assertIn("reviewer", str(caught.exception))

    def test_truth_loader_rejects_duplicate_hosts_and_unknown_keys(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "truth.yaml"
            path.write_text(
                """version: 1
hosts:
  - &host
    host_ip: 192.0.2.1
    group: synthetic-a
    role: database
    exposure: internal
    label_source: synthetic
    provenance: synthetic
  - *host
""",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError) as caught:
                load_context_truth(path)
            self.assertIn("labelled more than once", str(caught.exception))

            path.write_text("version: 1\nhosts: []\nextra: value\n", encoding="utf-8")
            with self.assertRaises(ConfigError) as caught:
                load_context_truth(path)
            self.assertIn("unknown key", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
