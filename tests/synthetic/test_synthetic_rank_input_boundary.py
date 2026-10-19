"""Synthetic SQLite corruption tests; no scanners, models, feeds or network calls."""

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy

import pytest

from tests.test_assessment_snapshot import ROOT, SETTINGS, prepared_store
from vulnassess import pipeline
from vulnassess.cli import main
from vulnassess.errors import ConfigError


def synthetic_change(store, host_ip, edit):
    row = store.connection.execute(
        "SELECT json FROM context_profiles WHERE run_id = ? AND host_ip = ?", ("snapshot", host_ip)
    ).fetchone()
    payload = json.loads(row["json"])
    changed = edit(deepcopy(payload))
    store.connection.execute(
        "UPDATE context_profiles SET json = ? WHERE run_id = ? AND host_ip = ?",
        (changed if isinstance(changed, str) else json.dumps(changed), "snapshot", host_ip),
    )
    store.connection.commit()


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", "invented"),
        ("exposure", "invented"),
        ("auth_required", "false"),
        ("criticality", "5"),
        ("environment", "production"),
    ],
)
def test_later_invalid_profile_preserves_entire_saved_score_queue(tmp_path, field, value):
    with prepared_store(str(tmp_path)) as store:

        def edit(payload):
            if field in ("role", "exposure"):
                payload[field]["value"] = value
            elif field == "auth_required":
                payload["controls"][field]["value"] = value
            else:
                payload["manual"][field] = dict(
                    value=value, confidence=1.0, source="manual", evidence="synthetic"
                )
            return payload

        synthetic_change(store, "172.28.0.12", edit)
        before = list(store.connection.iterdump())
        scores = store.scores("snapshot")
        assert len(scores) == 6
        with pytest.raises(ConfigError, match=field):
            pipeline.do_rank(SETTINGS, store, "snapshot")
        assert store.scores("snapshot") == scores
        assert list(store.connection.iterdump()) == before
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "--config",
                    str(ROOT / "config"),
                    "--db",
                    str(tmp_path / "assessment.db"),
                    "rank",
                    "--run-id",
                    "snapshot",
                    "--json",
                ]
            )
        assert code == 2
        assert stdout.getvalue() == ""
        assert "ConfigError" in stderr.getvalue() and field in stderr.getvalue()
        assert "Traceback" not in stderr.getvalue()
        assert list(store.connection.iterdump()) == before


@pytest.mark.parametrize("replacement", ["{broken", [], None, {"host_ip": "172.28.0.12"}])
@pytest.mark.parametrize("reader", ["profile", "profiles"])
def test_bad_profile_payload_is_controlled_and_read_only(tmp_path, replacement, reader):
    with prepared_store(str(tmp_path)) as store:
        synthetic_change(store, "172.28.0.12", lambda _: replacement)
        before = list(store.connection.iterdump())
        with pytest.raises(ConfigError, match="context_profiles.*snapshot.*172.28.0.12"):
            if reader == "profile":
                store.profile("snapshot", "172.28.0.12")
            else:
                store.profiles("snapshot")
        assert list(store.connection.iterdump()) == before


@pytest.mark.parametrize(
    "field,value", [("role", []), ("controls", []), ("manual", None), ("host_ip", "172.28.0.10")]
)
def test_bad_profile_shapes_and_foreign_row_ownership_are_cli_errors(tmp_path, field, value):
    with prepared_store(str(tmp_path)) as store:
        synthetic_change(store, "172.28.0.12", lambda payload: {**payload, field: value})
        before = list(store.connection.iterdump())
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "--config",
                    str(ROOT / "config"),
                    "--db",
                    str(tmp_path / "assessment.db"),
                    "rank",
                    "--run-id",
                    "snapshot",
                    "--json",
                ]
            )
        assert code == 2
        assert stdout.getvalue() == ""
        assert field in stderr.getvalue() and "context_profiles" in stderr.getvalue()
        assert "Traceback" not in stderr.getvalue()
        assert list(store.connection.iterdump()) == before


def test_valid_profile_read_and_cli_rank_remain_byte_repeatable(tmp_path):
    with prepared_store(str(tmp_path)) as store:
        assert store.profile("snapshot", "not-present") is None
        before = store.profiles("snapshot")
        outputs = []
        for _ in range(2):
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(
                    [
                        "--config",
                        str(ROOT / "config"),
                        "--db",
                        str(tmp_path / "assessment.db"),
                        "rank",
                        "--run-id",
                        "snapshot",
                        "--json",
                    ]
                )
            assert code == 0 and stderr.getvalue() == ""
            outputs.append(stdout.getvalue())
        assert outputs[0] == outputs[1]
        assert store.profiles("snapshot") == before


@pytest.mark.parametrize("feature", ["role", "exposure", "waf", "criticality"])
@pytest.mark.parametrize("value", [True, 1, [], {}, " "])
def test_malformed_stored_feature_evidence_is_controlled(tmp_path, feature, value):
    with prepared_store(str(tmp_path)) as store:

        def edit(payload):
            if feature in ("role", "exposure"):
                payload[feature]["evidence"] = value
            elif feature == "waf":
                payload["controls"][feature]["evidence"] = value
            else:
                payload["manual"][feature] = dict(
                    value=4, confidence=1.0, source="manual", evidence=value
                )
            return payload

        synthetic_change(store, "172.28.0.12", edit)
        before = list(store.connection.iterdump())
        with pytest.raises(ConfigError):
            store.profile("snapshot", "172.28.0.12")
        with pytest.raises(ConfigError):
            store.profiles("snapshot")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "--config",
                    str(ROOT / "config"),
                    "--db",
                    str(tmp_path / "assessment.db"),
                    "rank",
                    "--run-id",
                    "snapshot",
                    "--json",
                ]
            )
        assert code == 2 and stdout.getvalue() == ""
        assert "context_profiles" in stderr.getvalue() and "Traceback" not in stderr.getvalue()
        assert list(store.connection.iterdump()) == before
