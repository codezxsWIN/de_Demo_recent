"""Tests for the trainable shadow asset-role model.

All labels here are synthetic and prove only the model code path.
"""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess.cli import main
from vulnassess.errors import ConfigError
from vulnassess.role_model import (
    LabelledHost,
    calibrate,
    cross_validate,
    evaluate,
    export_label_template,
    extract_features,
    load_examples,
    load_model,
    save_model,
    train,
)
from vulnassess.schema import Host, Service
from vulnassess.store import Store


def host(role: str, index: int, *, empty: bool = False) -> Host:
    if empty:
        return Host(ip=f"198.51.100.{index}")
    if role == "database":
        services = (
            Service(
                port=3306,
                protocol="tcp",
                name="mysql",
                product="MySQL Server",
                banner="3306/tcp mysql MySQL Server",
            ),
        )
        os_guess = "Linux server"
    else:
        services = (
            Service(
                port=80,
                protocol="tcp",
                name="http",
                product="Apache httpd",
                banner="80/tcp http Apache httpd",
            ),
        )
        os_guess = "Linux server"
    return Host(
        ip=f"198.51.100.{index}",
        hostname=f"synthetic-{role}-{index}",
        os_guess=os_guess,
        services=services,
    )


def examples(prefix: str, per_class: int = 4) -> list[LabelledHost]:
    rows = []
    index = 1
    for label in ("database", "web_frontend"):
        for offset in range(per_class):
            rows.append(
                LabelledHost(
                    host=host(label, index),
                    label=label,
                    group=f"synthetic-{prefix}-{label}-{offset}",
                    label_source="synthetic",
                )
            )
            index += 1
    return rows


class TestRoleModel(unittest.TestCase):
    def test_feature_extraction_is_deterministic_ip_independent_and_evidenced(self):
        first = host("database", 1)
        second = Host(
            ip="203.0.113.99",
            hostname="different-name",
            os_guess=first.os_guess,
            services=first.services,
        )
        values, evidence = extract_features(first)
        repeated, repeated_evidence = extract_features(second)

        self.assertEqual(values, repeated)
        self.assertEqual(evidence, repeated_evidence)
        self.assertIn("port=3306", values)
        self.assertEqual(evidence["port=3306"], "3306/tcp mysql MySQL Server")
        self.assertFalse(any("198.51.100" in feature for feature in values))

    def test_training_learns_separable_roles_and_abstains_without_evidence(self):
        model = train(examples("train"), epochs=250)

        database = model.predict(host("database", 40))
        web = model.predict(host("web_frontend", 41))
        unsupported = model.predict(host("database", 42, empty=True))

        self.assertEqual(database.label, "database")
        self.assertFalse(database.abstained)
        self.assertIn("3306/tcp mysql", database.evidence)
        self.assertEqual(web.label, "web_frontend")
        self.assertFalse(web.abstained)
        self.assertEqual(unsupported.label, "unknown")
        self.assertTrue(unsupported.abstained)
        self.assertEqual(unsupported.evidence, "none observed")

    def test_spoofed_banner_without_structural_support_abstains(self):
        model = train(examples("train"), epochs=250)
        spoofed = Host(
            ip="198.51.100.90",
            os_guess="Novel Appliance OS",
            services=(
                Service(
                    port=22,
                    protocol="tcp",
                    name="ssh",
                    product="MySQL Server",
                    banner="22/tcp ssh MySQL Server mysql database",
                ),
            ),
        )

        prediction = model.predict(spoofed)

        self.assertTrue(prediction.abstained)
        self.assertEqual(prediction.label, "unknown")
        self.assertFalse(prediction.structural_support)
        self.assertGreater(prediction.confidence, 0.5)

    def test_novel_evidence_reports_out_of_vocabulary_features(self):
        model = train(examples("train"), epochs=100)
        novel = Host(
            ip="198.51.100.91",
            os_guess="NeverSeen QuantumOS",
            services=(
                Service(
                    port=9999,
                    protocol="tcp",
                    name="novelproto",
                    product="UniqueProduct",
                    banner="9999/tcp novelproto UniqueProduct",
                ),
            ),
        )

        prediction = model.predict(novel)

        self.assertTrue(prediction.abstained)
        self.assertLess(prediction.feature_coverage, model.minimum_feature_coverage)
        self.assertTrue(prediction.out_of_vocabulary)
        self.assertIn("port=9999", prediction.out_of_vocabulary)

    def test_json_artifact_round_trip_and_tamper_detection(self):
        model = train(examples("train"), epochs=100)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            save_model(model, path)
            loaded = load_model(path)
            self.assertEqual(loaded.to_json(), model.to_json())

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["coefficients"][0][0] += 1
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ConfigError) as caught:
                load_model(path)
            self.assertIn("hash mismatch", str(caught.exception))

    def test_calibration_and_holdout_metrics_are_recorded(self):
        model = train(examples("train"), epochs=200)
        validation = examples("validation", per_class=2)
        calibrated = calibrate(model, validation)
        metrics = evaluate(calibrated, validation)

        self.assertIsInstance(calibrated.training["calibration"], dict)
        self.assertEqual(calibrated.training["calibration"]["validation_examples"], 4)
        self.assertEqual(metrics["examples"], 4)
        self.assertEqual(metrics["groups"], 4)
        self.assertGreaterEqual(metrics["accuracy"], 0.5)
        self.assertIn("confusion_matrix", metrics)
        self.assertIn("expected_calibration_error", metrics)
        self.assertEqual(set(metrics["per_class"]), {"database", "web_frontend"})

    def test_grouped_cross_validation_is_deterministic(self):
        rows = examples("cross-validation", per_class=4)
        first = cross_validate(rows, folds=2, epochs=100)
        second = cross_validate(rows, folds=2, epochs=100)

        self.assertEqual(first, second)
        self.assertEqual(first["folds"], 2)
        self.assertEqual(first["groups"], 8)
        for fold in first["results"]:
            self.assertEqual(len(fold["test_groups"]), 4)

    def test_human_labels_require_a_reviewer_identifier(self):
        payload = {
            "host": host("database", 1).to_json(),
            "label": "database",
            "group": "capture-1",
            "label_source": "human",
            "reviewer": None,
        }
        with TemporaryDirectory() as directory:
            path = Path(directory) / "labels.jsonl"
            path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            with self.assertRaises(ConfigError) as caught:
                load_examples(path)
        self.assertIn("reviewer", str(caught.exception))

    def test_label_template_is_explicitly_unlabeled(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "labels.jsonl"
            export_label_template([host("web_frontend", 2), host("database", 1)], "run-1", path)
            payloads = [json.loads(line) for line in path.read_text().splitlines()]

        self.assertEqual(
            [item["host"]["ip"] for item in payloads],
            [
                "198.51.100.1",
                "198.51.100.2",
            ],
        )
        self.assertTrue(all(item["label"] is None for item in payloads))
        self.assertTrue(all(item["label_source"] is None for item in payloads))

    def test_label_template_requires_an_independently_reviewed_group(self) -> None:
        with TemporaryDirectory() as directory:
            paths = [Path(directory) / f"synthetic_labels_{index}.jsonl" for index in range(2)]
            for index, path in enumerate(paths):
                export_label_template([host("database", 1)], f"repeat-{index}", path)
                row = json.loads(path.read_text(encoding="utf-8"))
                self.assertIsNone(row["group"])
                row.update(label="database", label_source="human", reviewer="synthetic-reviewer")
                path.write_text(json.dumps(row) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ConfigError, "group"):
                    load_examples(path)

    def test_cli_refuses_synthetic_training_without_explicit_opt_in(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "synthetic.jsonl"
            data.write_text(
                "\n".join(json.dumps(item.to_json()) for item in examples("cli")) + "\n",
                encoding="utf-8",
            )
            artifact = root / "model.json"
            errors = io.StringIO()
            with redirect_stderr(errors), redirect_stdout(io.StringIO()):
                refused = main(
                    [
                        "model",
                        "train",
                        "--data",
                        str(data),
                        "--out",
                        str(artifact),
                        "--epochs",
                        "50",
                    ]
                )
            with redirect_stdout(io.StringIO()):
                accepted = main(
                    [
                        "model",
                        "train",
                        "--data",
                        str(data),
                        "--out",
                        str(artifact),
                        "--epochs",
                        "50",
                        "--allow-synthetic",
                    ]
                )

            self.assertEqual(refused, 2)
            self.assertIn("--allow-synthetic", errors.getvalue())
            self.assertFalse("Traceback" in errors.getvalue())
            self.assertEqual(accepted, 0)
            self.assertTrue(artifact.is_file())

    def test_cli_rejects_training_validation_group_leakage(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "synthetic.jsonl"
            data.write_text(
                "\n".join(json.dumps(item.to_json()) for item in examples("same")) + "\n",
                encoding="utf-8",
            )
            errors = io.StringIO()
            with redirect_stderr(errors), redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "model",
                        "train",
                        "--data",
                        str(data),
                        "--validation",
                        str(data),
                        "--out",
                        str(root / "model.json"),
                        "--epochs",
                        "50",
                        "--allow-synthetic",
                    ]
                )

        self.assertEqual(code, 2)
        self.assertIn("group leakage", errors.getvalue())

    def test_shadow_prediction_command_does_not_write_context_or_scores(self):
        model = train(examples("train"), epochs=100)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "model.json"
            database = root / "store.db"
            save_model(model, artifact)
            with Store(database) as store:
                store.start_run("shadow", "config")
                store.upsert_host("shadow", host("database", 1))
                before_profiles = store.profiles("shadow")
                before_scores = store.scores("shadow")

            output = io.StringIO()
            with redirect_stdout(output):
                code = main(
                    [
                        "--db",
                        str(database),
                        "model",
                        "predict",
                        "--run-id",
                        "shadow",
                        "--model",
                        str(artifact),
                    ]
                )

            with Store(database) as store:
                self.assertEqual(store.profiles("shadow"), before_profiles)
                self.assertEqual(store.scores("shadow"), before_scores)
        self.assertEqual(code, 0)
        self.assertIn("SHADOW ONLY", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
