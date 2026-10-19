"""Nested configuration validation tests."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from vulnassess.errors import ConfigError
from vulnassess.settings import CONFIG_FILES, Settings

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"


def config_payloads() -> dict[str, dict]:
    return {
        name: yaml.safe_load((CONFIG / name).read_text(encoding="utf-8")) for name in CONFIG_FILES
    }


def write_config(directory: Path, payloads: dict[str, dict]) -> None:
    for name, payload in payloads.items():
        (directory / name).write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


class TestStrictSettings(unittest.TestCase):
    def mutate(self, mutation) -> str:
        payloads = config_payloads()
        mutation(payloads)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_config(root, payloads)
            with self.assertRaises(ConfigError) as caught:
                Settings(root)
        return str(caught.exception)

    def test_current_configuration_is_valid_and_comment_independent(self):
        original = Settings(CONFIG)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name in CONFIG_FILES:
                text = (CONFIG / name).read_text(encoding="utf-8")
                (root / name).write_text("# another comment\n" + text, encoding="utf-8")
            repeated = Settings(root)

        self.assertEqual(original.config_hash(), repeated.config_hash())

    def test_invalid_environment_and_criticality_name_the_nested_key(self):
        message = self.mutate(
            lambda payloads: payloads["scope.yaml"]["lab_targets"][0]["tags"].update(
                environment="staging"
            )
        )
        self.assertIn("tags.environment", message)

        message = self.mutate(
            lambda payloads: payloads["scope.yaml"]["lab_targets"][1]["tags"].update(
                criticality=True
            )
        )
        self.assertIn("tags.criticality", message)

    def test_duplicate_lab_target_name_or_ip_is_rejected(self):
        def duplicate_name(payloads):
            payloads["scope.yaml"]["lab_targets"][1]["name"] = payloads["scope.yaml"][
                "lab_targets"
            ][0]["name"]

        self.assertIn("names must be unique", self.mutate(duplicate_name))

        def duplicate_ip(payloads):
            payloads["scope.yaml"]["lab_targets"][1]["ip"] = payloads["scope.yaml"]["lab_targets"][
                0
            ]["ip"]

        self.assertIn("IPs must be unique", self.mutate(duplicate_ip))

    def test_invalid_role_and_control_regexes_are_rejected_at_load(self):
        message = self.mutate(
            lambda payloads: payloads["roles.yaml"]["roles"]["database"][1].update(
                regex="[unterminated"
            )
        )
        self.assertIn("roles.database[1].regex", message)
        self.assertIn("invalid regex", message)

        message = self.mutate(
            lambda payloads: payloads["controls.yaml"]["waf"][0].update(regex="(?P<broken")
        )
        self.assertIn("waf[0].regex", message)
        self.assertIn("invalid regex", message)

    def test_every_scoring_role_requires_complete_cia_requirements(self):
        def remove_role(payloads):
            del payloads["weights.yaml"]["environmental"]["role_requirements"]["database"]

        message = self.mutate(remove_role)
        self.assertIn("role_requirements.database", message)

        def remove_metric(payloads):
            del payloads["weights.yaml"]["environmental"]["role_requirements"]["mail"]["AR"]

        message = self.mutate(remove_metric)
        self.assertIn("role_requirements.mail.AR", message)

    def test_threat_settings_must_be_bounded_and_monotonic(self):
        message = self.mutate(
            lambda payloads: payloads["weights.yaml"]["threat"].update(
                base_multiplier=0.8, epss_weight=0.5
            )
        )
        self.assertIn("must be <= 1", message)

        message = self.mutate(
            lambda payloads: payloads["weights.yaml"]["threat"].update(kev_multiplier=0.1)
        )
        self.assertIn("must not be below", message)

    def test_bands_and_native_fallbacks_are_validated(self):
        message = self.mutate(
            lambda payloads: payloads["weights.yaml"]["bands"].update(Critical=50, High=60)
        )
        self.assertIn("Critical > High > Medium", message)

        message = self.mutate(
            lambda payloads: payloads["weights.yaml"]["native_fallback"]["zap"].update(High=101)
        )
        self.assertIn("native_fallback.zap.High", message)

    def test_unknown_nested_keys_are_not_ignored(self):
        message = self.mutate(
            lambda payloads: payloads["weights.yaml"]["threat"].update(kev_boostt=10)
        )
        self.assertIn("threat.kev_boostt", message)

        message = self.mutate(
            lambda payloads: payloads["roles.yaml"]["roles"]["database"][0].update(confidence=0.9)
        )
        self.assertIn("confidence", message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
