"""Invalid configuration cannot widen scope or change canonical scoring silently."""

import copy
from pathlib import Path

import pytest
import yaml

from tests.test_assessment_snapshot import ROOT
from vulnassess.errors import ConfigError
from vulnassess.settings import CONFIG_FILES, Scope, Settings, _read_yaml, load_settings


@pytest.mark.parametrize(
    "patch,reason",
    [
        ({"allowed_cidrs": "192.0.2.0/24"}, "must be a list"),
        ({"allowed_hosts": "192.0.2.1"}, "must be a list"),
        ({"lab_targets": {}}, "must be a list"),
        ({"allowed_hosts": []}, "at least one"),
        ({"vantage": "unknown"}, "vantage"),
        ({"allowed_cidrs": ["bad"]}, "not a CIDR"),
        ({"allowed_hosts": ["bad"]}, "not an IP"),
        ({"canary": {"ip": "192.0.2.250", "allow": True}}, "takes only"),
        ({"lab_targets": ["host"]}, "must be mappings"),
        ({"lab_targets": [{"name": "lab", "ip": "192.0.2.1", "unknown": True}]}, "unknown key"),
        ({"lab_targets": [{"ip": "192.0.2.1"}]}, "name.*required"),
        (
            {"lab_targets": [{"name": "lab", "ip": "192.0.2.1", "tags": "external"}]},
            "must be a mapping",
        ),
        (
            {"lab_targets": [{"name": "lab", "ip": "192.0.2.1", "tags": {"unknown": True}}]},
            "unknown key",
        ),
        (
            {"lab_targets": [{"name": "lab", "ip": "192.0.2.1", "tags": {"vantage": "maybe"}}]},
            "vantage",
        ),
        (
            {"lab_targets": [{"name": "lab", "ip": "192.0.2.1", "tags": {"environment": "maybe"}}]},
            "prod or test",
        ),
        (
            {"lab_targets": [{"name": "lab", "ip": "192.0.2.1", "tags": {"criticality": True}}]},
            "integer 1-5",
        ),
    ],
)
def test_scope_rejects_invalid_configuration(patch, reason):
    with pytest.raises(ConfigError, match=reason):
        Scope({"allowed_hosts": ["192.0.2.1"], **patch}, Path("synthetic-scope.yaml"))


def test_duplicate_addresses_and_invalid_lookup_do_not_authorize():
    data = {
        "allowed_hosts": ["192.0.2.1"],
        "lab_targets": [{"name": name, "ip": "192.0.2.1"} for name in ("one", "two")],
    }
    with pytest.raises(ConfigError, match="IPs must be unique"):
        Scope(data, Path("scope.yaml"))
    scope = Scope(
        {"allowed_hosts": ["192.0.2.1"], "canary": {"ip": "192.0.2.250"}}, Path("scope.yaml")
    )
    assert not scope.contains("192.0.2.250")
    assert not scope.contains("garbage")
    assert scope.segment("garbage") is None
    assert scope.segment("192.0.2.1") is None


@pytest.mark.parametrize(
    "filename,path,value,reason",
    [
        ("weights.yaml", ["bands"], None, "mapping"),
        ("weights.yaml", ["environmental", "min_confidence_to_apply"], True, "numeric"),
        ("weights.yaml", ["environmental", "criticality_step_above"], 6, "integer 1-5"),
        ("weights.yaml", ["environmental", "waf_present"], {}, "required"),
        ("roles.yaml", ["roles"], {}, "must not be empty"),
        ("roles.yaml", ["roles", "database"], [], "non-empty list"),
        ("roles.yaml", ["roles", "database"], [{"match": "bad", "weight": 0.5}], "match.*invalid"),
        (
            "roles.yaml",
            ["roles", "database"],
            [{"match": "port", "weight": 0.5, "any_of": []}],
            "non-empty any_of",
        ),
        (
            "roles.yaml",
            ["roles", "database"],
            [{"match": "port", "weight": 0.5, "any_of": [65536]}],
            "invalid port",
        ),
        (
            "roles.yaml",
            ["roles", "database"],
            [{"match": "banner", "weight": 0.5, "regex": ""}],
            "non-empty regex",
        ),
        ("controls.yaml", ["waf"], [], "non-empty list"),
        ("controls.yaml", ["waf"], [{"regex": "server", "vendor": ""}], "vendor.*required"),
    ],
)
def test_invalid_scoring_and_detection_configuration(tmp_path, filename, path, value, reason):
    for name in CONFIG_FILES:
        data = yaml.safe_load((ROOT / "config" / name).read_text())
        if name == filename:
            parent = data
            for part in path[:-1]:
                parent = parent[part]
            parent[path[-1]] = value
        (tmp_path / name).write_text(yaml.safe_dump(data))
    with pytest.raises(ConfigError, match=reason):
        Settings(tmp_path)


@pytest.mark.parametrize("remove", [["threat"], ["threat", "epss_weight"], ["bands", "High"]])
def test_required_weights_cannot_be_omitted(tmp_path, remove):
    for name in CONFIG_FILES:
        data = copy.deepcopy(yaml.safe_load((ROOT / "config" / name).read_text()))
        if name == "weights.yaml":
            parent = data
            for part in remove[:-1]:
                parent = parent[part]
            del parent[remove[-1]]
        (tmp_path / name).write_text(yaml.safe_dump(data))
    with pytest.raises(ConfigError, match="required"):
        Settings(tmp_path)


def test_yaml_missing_empty_malformed_and_non_mapping(tmp_path):
    path = tmp_path / "test.yaml"
    with pytest.raises(ConfigError, match="MISSING"):
        _read_yaml(path)
    path.write_text("")
    assert _read_yaml(path) == {}
    path.write_text("[]")
    with pytest.raises(ConfigError, match="mapping"):
        _read_yaml(path)
    path.write_text("[broken")
    with pytest.raises(ConfigError, match="unreadable"):
        _read_yaml(path)
    with pytest.raises(ConfigError, match="MISSING: configuration directory"):
        load_settings(tmp_path / "absent")


def test_settings_loader_preserves_config_hash():
    assert load_settings(ROOT / "config").config_hash() == Settings(ROOT / "config").config_hash()
