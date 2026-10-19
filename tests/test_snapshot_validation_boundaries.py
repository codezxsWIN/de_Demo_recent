"""Frozen assessment references must remain internally consistent."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_assessment_snapshot import SETTINGS, prepared_store
from vulnassess import assessment_snapshot as snapshot
from vulnassess.errors import ConfigError


@pytest.mark.parametrize(
    "method,value,message",
    [
        ("run_info", None, "MISSING: run"),
        ("scores", [SimpleNamespace(finding_id="absent")], "score rows without findings"),
        ("profiles", [SimpleNamespace(host_ip="192.0.2.99")], "profiles without hosts"),
        ("rationales", {"absent": {}}, "rationales without findings"),
    ],
)
def test_dangling_database_records_cannot_be_frozen(tmp_path, monkeypatch, method, value, message):
    with prepared_store(str(tmp_path)) as store:
        monkeypatch.setattr(store, method, Mock(return_value=value))
        with pytest.raises(ConfigError, match=message):
            snapshot.build_snapshot(SETTINGS, store, "snapshot")


def test_snapshot_rejects_unknown_schema_missing_fields_and_nonobjects(tmp_path):
    with pytest.raises(ConfigError, match="schema must"):
        snapshot.validate_snapshot({"schema_version": 99})
    payload = {"schema_version": 1}
    payload["snapshot_hash"] = snapshot._digest(payload)
    with pytest.raises(ConfigError, match="missing key"):
        snapshot.validate_snapshot(payload)
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(ConfigError, match="expected an object"):
        snapshot.load_snapshot(path)
