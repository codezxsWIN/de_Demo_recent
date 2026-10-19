"""Synthetic contract cases, not real expert approval or scanner evidence."""

import copy
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from vulnassess.cli import main
from vulnassess.cohort import CohortManifest, load_manifest
from vulnassess.errors import ConfigError

ROOT = Path(__file__).resolve().parents[2]


def synthetic_manifest(status="VERIFIED"):
    # Numeric-looking identities and digests expose lossy coercion. All are fake.
    ids = tuple(str(index) for index in range(20))
    return CohortManifest(
        cohort_id="1",
        run_id="1",
        finding_ids=ids,
        item_hashes={identifier: "1" * 64 for identifier in ids},
        snapshot_hash="1" * 64,
        config_hash="1" * 16,
        weights_hash="1" * 64,
        feed_snapshot_hash="1" * 64,
        model_hash=None,
        grouping_map={identifier: (identifier,) for identifier in ids},
        evidence_status=status,
        created_on="2026-10-18",
        reviewer="synthetic-reviewer-not-independent",
        approval_id="synthetic-approval-not-real",
    )


def synthetic_write(tmp_path, payload, *, rehash=False):
    payload = copy.deepcopy(payload)
    if rehash:
        core = {key: value for key, value in payload.items() if key != "manifest_hash"}
        encoded = json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        payload["manifest_hash"] = sha256(encoded.encode("utf-8")).hexdigest()
    path = tmp_path / "synthetic_manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


COERCIONS = (
    [("schema_version", value) for value in (True, 1.0, 1.9, "1")]
    + [("ndcg_k", value) for value in (10.0, 10.9, "10")]
    + [
        ("cohort_id", 1),
        ("run_id", 1),
        ("snapshot_hash", int("1" * 64)),
        ("config_hash", int("1" * 16)),
        ("weights_hash", int("1" * 64)),
        ("feed_snapshot_hash", int("1" * 64)),
        ("finding_ids", list(range(20))),
        ("item_hashes", {str(index): int("1" * 64) for index in range(20)}),
        ("grouping_map", {str(index): [index] for index in range(20)}),
    ]
)


@pytest.mark.parametrize("field,value", COERCIONS)
def test_original_hash_cannot_authorise_coerced_values(tmp_path, field, value):
    payload = synthetic_manifest().to_json()
    payload[field] = value
    path = synthetic_write(tmp_path, payload)
    original = path.read_bytes()
    with pytest.raises(ConfigError, match="invalid cohort manifest"):
        load_manifest(path)
    assert path.read_bytes() == original


BAD_SHAPES = [
    (field, value)
    for field in ("reviewer", "approval_id")
    for value in (1, True, [], {"synthetic": "name"})
] + [
    ("item_hashes", []),
    ("item_hashes", "not-a-map"),
    ("grouping_map", []),
    ("grouping_map", {str(index): str(index) for index in range(20)}),
    ("finding_ids", {str(index): True for index in range(20)}),
    ("finding_ids", "0123456789"),
    ("metrics", {name: True for name in synthetic_manifest().metrics}),
    ("created_on", 20261018),
    ("model_hash", 123),
    ("cohort_id", None),
    ("run_id", True),
]


@pytest.mark.parametrize("status", ["VERIFIED", "NOT RUN"])
@pytest.mark.parametrize("field,value", BAD_SHAPES)
def test_rehashing_malformed_values_does_not_make_them_valid(tmp_path, status, field, value):
    payload = synthetic_manifest(status).to_json()
    payload[field] = value
    path = synthetic_write(tmp_path, payload, rehash=True)
    with pytest.raises(ConfigError, match="invalid cohort manifest"):
        load_manifest(path)


@pytest.mark.parametrize("field,value", COERCIONS[:13] + BAD_SHAPES)
def test_direct_constructor_rejects_wrong_declared_types(field, value):
    with pytest.raises(ValueError):
        replace(synthetic_manifest(), **{field: value})


@pytest.mark.parametrize("field,value", [("reviewer", 1), ("approval_id", {"name": "fake"})])
def test_cli_malformed_approval_is_controlled_and_has_no_partial_success(tmp_path, field, value):
    payload = synthetic_manifest().to_json()
    payload[field] = value
    manifest_path = synthetic_write(tmp_path, payload, rehash=True)
    evidence = tmp_path / "synthetic_unused_evidence.json"
    evidence.write_text("do not read after invalid manifest", encoding="utf-8")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(
            [
                "--config",
                str(ROOT / "config"),
                "--db",
                str(tmp_path / "synthetic_unused.db"),
                "research",
                "cohort-verify",
                "--run-id",
                "1",
                "--manifest",
                str(manifest_path),
                "--evidence",
                str(evidence),
                "--json",
            ]
        )
    assert code == 2
    assert stdout.getvalue() == ""
    assert "invalid cohort manifest" in stderr.getvalue()
    assert str(manifest_path) in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize("status", ["VERIFIED", "NOT RUN"])
def test_valid_typed_manifest_round_trips_without_content_changes(tmp_path, status):
    expected = synthetic_manifest(status)
    path = synthetic_write(tmp_path, expected.to_json())
    before = path.read_bytes()
    actual = load_manifest(path)
    assert actual == expected
    assert actual.to_json() == expected.to_json()
    assert path.read_bytes() == before


def test_optional_metadata_may_remain_absent_on_non_confirmatory_cohort(tmp_path):
    expected = replace(synthetic_manifest("NOT RUN"), reviewer=None, approval_id=None)
    path = synthetic_write(tmp_path, expected.to_json())
    assert load_manifest(path) == expected
