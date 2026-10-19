"""Synthetic snapshot integrity, not proof of genuine capture or correct risk arithmetic."""

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from tempfile import TemporaryDirectory

import pytest

from tests.test_all import make_enrichment, make_finding
from tests.test_assessment_snapshot import ROOT, SETTINGS, prepared_store
from vulnassess import assessment_snapshot
from vulnassess.cli import main
from vulnassess.errors import ConfigError
from vulnassess.schema import (
    Enrichment,
    Feature,
    Finding,
    Provenance,
    Rationale,
    ScoreBreakdown,
    Service,
)


@pytest.fixture(scope="module")
def synthetic_complete_snapshot():
    with TemporaryDirectory() as directory, prepared_store(directory) as store:
        finding_id = store.findings("snapshot")[0].id
        store.upsert_rationale(
            "snapshot", Rationale(finding_id, "SYNTHETIC explanation", "template")
        )
        return assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")


def synthetic_rehash(payload):
    core = {key: value for key, value in payload.items() if key != "snapshot_hash"}
    payload["snapshot_hash"] = assessment_snapshot._digest(core)
    return payload


def synthetic_set(payload, path, value):
    parent = payload
    for part in path[:-1]:
        parent = parent[part]
    parent[path[-1]] = deepcopy(value)


BAD_FIELDS = (
    [(("schema_version",), value) for value in (True, 1.0, "1", 99)]
    + [
        ((key,), value)
        for key in ("hosts", "findings", "profiles", "scores")
        for value in (None, {}, "[]", [None])
    ]
    + [
        ((key,), value)
        for key in ("run", "configuration", "feed_snapshot", "enrichments", "rationales")
        for value in (None, [], "{}")
    ]
    + [
        (("run", "run_id"), 1),
        (("run", "run_id"), ""),
        (("configuration", "drift"), "false"),
        (("configuration", "drift"), True),
        (("configuration", "hash_at_run_start"), "f" * 16),
        (("configuration", "validated"), []),
        (("model_hash",), 1),
        (("model_hash",), ""),
        (("history",), []),
        (("limitations",), "not-a-list"),
        (("evidence_status",), "COMPLETE"),
        (("hosts", 0, "ip"), False),
        (("hosts", 0, "ip"), ""),
        (("hosts", 0, "services"), {}),
        (("hosts", 0, "services", 0, "port"), True),
        (("hosts", 0, "services", 0, "port"), "80"),
        (("hosts", 0, "services", 0, "tls"), "false"),
        (("findings", 0, "id"), 1),
        (("findings", 0, "id"), ""),
        (("findings", 0, "host_ip"), "192.0.2.254"),
        (("findings", 0, "port"), True),
        (("findings", 0, "cve_ids"), "CVE-1999-9001"),
        (("findings", 0, "provenance"), []),
        (("findings", 0, "provenance", "record_index"), True),
        (("profiles", 0, "host_ip"), "192.0.2.254"),
        (("profiles", 0, "role", "confidence"), True),
        (("profiles", 0, "role", "confidence"), "0.9"),
        (("profiles", 0, "role", "source"), "unsupported"),
        (("profiles", 0, "role", "evidence"), ""),
        (("profiles", 0, "role", "value"), "invented-role"),
        (("profiles", 0, "exposure", "value"), "unknown"),
        (("profiles", 0, "controls"), []),
        (("scores", 0, "finding_id"), "SYNTHETIC unknown finding"),
        (("scores", 0, "host_ip"), "192.0.2.254"),
        (("scores", 0, "risk"), True),
        (("scores", 0, "risk"), "90"),
        (("scores", 0, "risk"), 101),
        (("scores", 0, "band"), "Unknown"),
        (("scores", 0, "kev"), "false"),
        (("scores", 0, "inputs"), []),
    ]
)


@pytest.mark.parametrize("path,value", BAD_FIELDS)
def test_rehashed_malformed_snapshot_is_not_verified(synthetic_complete_snapshot, path, value):
    payload = deepcopy(synthetic_complete_snapshot)
    synthetic_set(payload, path, value)
    synthetic_rehash(payload)
    original = deepcopy(payload)
    with pytest.raises(ConfigError, match="assessment snapshot"):
        assessment_snapshot.validate_snapshot(payload)
    assert payload == original


@pytest.mark.parametrize("field", ["hosts", "findings", "profiles", "scores"])
def test_duplicate_identities_cannot_disappear_in_sets(synthetic_complete_snapshot, field):
    payload = deepcopy(synthetic_complete_snapshot)
    payload[field].append(deepcopy(payload[field][0]))
    with pytest.raises(ConfigError, match="assessment snapshot.*duplicate"):
        assessment_snapshot.validate_snapshot(synthetic_rehash(payload))


@pytest.mark.parametrize(
    "case", ["orphan_key", "foreign_owner", "duplicate_cve", "wrong_container"]
)
def test_enrichment_relationships_are_checked(synthetic_complete_snapshot, case):
    payload = deepcopy(synthetic_complete_snapshot)
    key = next(key for key, values in payload["enrichments"].items() if values)
    if case == "orphan_key":
        payload["enrichments"]["SYNTHETIC unknown finding"] = []
    elif case == "foreign_owner":
        payload["enrichments"][key][0]["finding_id"] = "SYNTHETIC another finding"
    elif case == "duplicate_cve":
        payload["enrichments"][key].append(deepcopy(payload["enrichments"][key][0]))
    else:
        payload["enrichments"][key] = {}
    with pytest.raises(ConfigError, match="assessment snapshot.*enrichment"):
        assessment_snapshot.validate_snapshot(synthetic_rehash(payload))


@pytest.mark.parametrize("case", ["orphan_key", "foreign_owner", "wrong_container", "empty_text"])
def test_rationale_relationships_are_checked(synthetic_complete_snapshot, case):
    payload = deepcopy(synthetic_complete_snapshot)
    key = next(iter(payload["rationales"]))
    if case == "orphan_key":
        payload["rationales"]["SYNTHETIC unknown finding"] = deepcopy(payload["rationales"][key])
    elif case == "foreign_owner":
        payload["rationales"][key]["finding_id"] = "SYNTHETIC another finding"
    elif case == "wrong_container":
        payload["rationales"][key] = []
    else:
        payload["rationales"][key]["text"] = ""
    with pytest.raises(ConfigError, match="assessment snapshot.*rationale"):
        assessment_snapshot.validate_snapshot(synthetic_rehash(payload))


@pytest.mark.parametrize("case", ["schema", "duplicate_host", "bad_record", "foreign_owner"])
def test_cli_never_emits_verified_for_malformed_snapshot(
    tmp_path, synthetic_complete_snapshot, case
):
    payload = deepcopy(synthetic_complete_snapshot)
    if case == "schema":
        payload["schema_version"] = True
    elif case == "duplicate_host":
        payload["hosts"].append(deepcopy(payload["hosts"][0]))
    elif case == "bad_record":
        payload["findings"] = [None]
    else:
        payload["scores"][0]["host_ip"] = "192.0.2.254"
    path = tmp_path / "synthetic_bad_snapshot.json"
    path.write_text(json.dumps(synthetic_rehash(payload)), encoding="utf-8")
    before = path.read_bytes()
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(
            [
                "--config",
                str(ROOT / "config"),
                "research",
                "snapshot-verify",
                "--run-id",
                "snapshot",
                "--snapshot",
                str(path),
                "--json",
            ]
        )
    assert code == 2
    assert stdout.getvalue() == ""
    assert "assessment snapshot" in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()
    assert path.read_bytes() == before


def test_valid_round_trip_keeps_original_payload_and_hash(tmp_path, synthetic_complete_snapshot):
    payload = deepcopy(synthetic_complete_snapshot)
    before = deepcopy(payload)
    assert assessment_snapshot.validate_snapshot(payload) is payload
    path = assessment_snapshot.save_snapshot(payload, tmp_path / "synthetic_valid_snapshot.json")
    assert assessment_snapshot.load_snapshot(path) == before
    assert payload == before


def test_partial_assessment_does_not_invent_scores_or_context(synthetic_complete_snapshot):
    payload = deepcopy(synthetic_complete_snapshot)
    payload.update(profiles=[], scores=[], rationales={})
    synthetic_rehash(payload)
    before = deepcopy(payload)
    assert assessment_snapshot.validate_snapshot(payload) is payload
    assert payload == before


def test_original_capture_run_provenance_is_not_rewritten(synthetic_complete_snapshot):
    payload = deepcopy(synthetic_complete_snapshot)
    payload["findings"][0]["provenance"]["run_id"] = "SYNTHETIC original capture run"
    synthetic_rehash(payload)
    before = deepcopy(payload)
    assert assessment_snapshot.validate_snapshot(payload) is payload
    assert payload == before


def test_missing_optional_legacy_metadata_stays_missing(synthetic_complete_snapshot):
    payload = deepcopy(synthetic_complete_snapshot)
    for key in ("model_hash", "history", "limitations", "data_kind", "evidence_status"):
        payload.pop(key, None)
    synthetic_rehash(payload)
    before = deepcopy(payload)
    assert assessment_snapshot.validate_snapshot(payload) is payload
    assert payload == before


@pytest.mark.parametrize(
    "kind,field,value",
    [
        ("service", "port", True),
        ("service", "port", "80"),
        ("service", "port", 80.5),
        ("provenance", "record_index", True),
        ("provenance", "record_index", "1"),
        ("provenance", "record_index", 1.5),
        ("feature", "confidence", True),
        ("feature", "confidence", "0.9"),
        ("enrichment", "match_confidence", True),
        ("enrichment", "match_confidence", "0.9"),
        ("enrichment", "kev", "false"),
        ("enrichment", "kev", 1),
        ("enrichment", "kev", None),
        ("score", "risk", True),
        ("score", "risk", "90"),
        ("score", "kev", "false"),
        ("score", "kev", 1),
        ("score", "kev", None),
        ("finding", "cve_ids", "CVE-1999-9001"),
        ("finding", "cve_ids", {"CVE-1999-9001": True}),
        ("finding", "cwe_ids", {"CWE-79": True}),
        ("finding", "reference_urls", {"https://example.invalid/": True}),
        ("enrichment", "patch_references", {"https://example.invalid/": True}),
        ("enrichment", "feed_dates", [["nvd", "2026-10-18"]]),
        ("enrichment", "feed_dates", {False: "2026-10-18"}),
        ("score", "env_modifications", [["MAV", "A"]]),
        ("rationale", "validation", [["synthetic", True]]),
    ],
)
def test_json_readers_cannot_launder_wrong_types_before_snapshot_validation(
    synthetic_complete_snapshot, kind, field, value
):
    samples = {
        "service": (Service, Service(80, "tcp").to_json()),
        "provenance": (Provenance, make_finding().provenance.to_json()),
        "feature": (Feature, Feature(True, 0.9, "rule", "SYNTHETIC feature").to_json()),
        "enrichment": (Enrichment, make_enrichment().to_json()),
        "score": (ScoreBreakdown, deepcopy(synthetic_complete_snapshot["scores"][0])),
        "finding": (Finding, make_finding().to_json()),
        "rationale": (
            Rationale,
            Rationale("synthetic-finding", "SYNTHETIC explanation", "template").to_json(),
        ),
    }
    model, payload = samples[kind]
    payload[field] = value
    with pytest.raises(ValueError, match=field):
        model.from_json(payload)


@pytest.mark.parametrize("field", ["host_port", "profile_confidence", "score_risk", "finding_ids"])
def test_export_cannot_hide_wrong_stored_types(tmp_path, field):
    with prepared_store(str(tmp_path)) as store:
        if field == "host_port":
            table, identity, identifier = "hosts", "ip", store.hosts("snapshot")[0].ip
            payload = store.hosts("snapshot")[0].to_json()
            payload["services"][0]["port"] = True
        elif field == "profile_confidence":
            table, identity, identifier = (
                "context_profiles",
                "host_ip",
                store.profiles("snapshot")[0].host_ip,
            )
            payload = store.profiles("snapshot")[0].to_json()
            payload["role"]["confidence"] = True
        elif field == "score_risk":
            table, identity, identifier = (
                "scores",
                "finding_id",
                store.scores("snapshot")[0].finding_id,
            )
            payload = store.scores("snapshot")[0].to_json()
            payload["risk"] = "90"
        else:
            table, identity, identifier = (
                "finding_observations",
                "finding_id",
                store.findings("snapshot")[0].id,
            )
            payload = store.findings("snapshot")[0].to_json()
            payload["cve_ids"] = {"CVE-1999-9001": True}
        # Test-owned allowlisted table/column names, never target-controlled SQL.
        changed = store.connection.execute(
            f"UPDATE {table} SET json=? WHERE run_id=? AND {identity}=?",
            (json.dumps(payload), "snapshot", identifier),
        )
        assert changed.rowcount == 1
        store.connection.commit()
        before = tuple(store.connection.iterdump())
        with pytest.raises(ConfigError, match="assessment snapshot"):
            assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        assert tuple(store.connection.iterdump()) == before


def test_valid_numeric_json_normalisation_remains_compatible(synthetic_complete_snapshot):
    feature = Feature(True, 1, "rule", "SYNTHETIC feature").to_json()
    assert Feature.from_json(feature).to_json() == {**feature, "confidence": 1.0}
    score = deepcopy(synthetic_complete_snapshot["scores"][0])
    score["risk"] = 90
    assert ScoreBreakdown.from_json(score).to_json() == {**score, "risk": 90.0}
    enrichment = make_enrichment(match_confidence=1, version_end_inclusive=None).to_json()
    assert Enrichment.from_json(enrichment).to_json() == {**enrichment, "match_confidence": 1.0}


@pytest.mark.parametrize("value", ["false", "true", 0, 1])
def test_imported_snapshot_does_not_accept_mistyped_range_boundary(
    synthetic_complete_snapshot, value
):
    payload = deepcopy(synthetic_complete_snapshot)
    key = next(key for key, entries in payload["enrichments"].items() if entries)
    payload["enrichments"][key][0]["version_end_inclusive"] = value
    synthetic_rehash(payload)
    original = deepcopy(payload)
    with pytest.raises(ConfigError, match="version_end_inclusive"):
        assessment_snapshot.validate_snapshot(payload)
    assert payload == original


@pytest.mark.parametrize("value", ["false", "true", 0, 1])
def test_legacy_stored_range_boundary_retains_unknown_instead_of_guessing(value):
    payload = make_enrichment().to_json()
    payload["version_end_inclusive"] = value
    original = deepcopy(payload)
    loaded = Enrichment.from_json(payload)
    assert loaded.version_end_inclusive is None
    assert payload == original
