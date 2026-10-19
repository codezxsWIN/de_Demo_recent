"""Audit attachments must retain explicit evidence quality and integrity."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from vulnassess import audit
from vulnassess.errors import ConfigError


@pytest.mark.parametrize(
    "kind,body,expected",
    [
        ("scan", {"executed": True, "notice": "synthetic", "successful_tools": 1}, "success=1"),
        (
            "scan",
            {"executed": False, "notice": "synthetic", "missing": ["nikto"]},
            "missing binaries: nikto",
        ),
        (
            "ranking",
            {"methods": {"ours": {"tau_b_mean": 0.5}}, "h2": {}, "h3": {}},
            "mean tau-b=0.5",
        ),
        ("ablation", {"scenarios": ["baseline"], "comparisons": [], "orders": []}, "1 scenarios"),
        (
            "stability",
            {
                "deterministic": True,
                "score_hashes": ["a" * 64] * 2,
                "unique_score_hashes": 1,
                "repeats": 2,
            },
            "deterministic=True",
        ),
        (
            "rescan",
            {"outcomes": [], "counts": {"still_open": 1}, "interpretation": "synthetic"},
            "still_open=1",
        ),
    ],
)
def test_artifact_kinds_preserve_verified_hash_and_summary(tmp_path, kind, body, expected):
    hash_field, run_field, _ = audit.ARTIFACT_SPECS[kind]
    payload = {**body, run_field: "test", "evidence_status": "TESTED WITH MOCKS"}
    payload[hash_field] = audit._digest(payload)
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = audit.load_artifact(kind, path, "test")
    assert expected in result.summary
    assert result.artifact_hash == payload[hash_field]
    assert result.row()["evidence_status"] == "TESTED WITH MOCKS"


@pytest.mark.parametrize(
    "payload,message",
    [
        ([], "expected an object"),
        ({}, "missing key"),
        (
            {
                "run_id": "elsewhere",
                "evidence_status": "NOT RUN",
                "summary_hash": "x",
                "executed": False,
                "notice": "test",
            },
            "belongs to run",
        ),
        (
            {
                "run_id": "test",
                "evidence_status": "done",
                "summary_hash": "x",
                "executed": False,
                "notice": "test",
            },
            "unsupported evidence_status",
        ),
    ],
)
def test_invalid_artifact_metadata_rejected(tmp_path, payload, message):
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        audit.load_artifact("scan", path, "test")


def test_valid_hash_cannot_hide_invalid_summary_structure(tmp_path):
    payload = {
        "run_id": "test",
        "evidence_status": "NOT RUN",
        "rule_role": [],
        "exposure": {},
        "h1": {},
    }
    payload["evaluation_hash"] = audit._digest(payload)
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid context audit artifact"):
        audit.load_artifact("context", path, "test")
    with pytest.raises(ConfigError, match="unknown audit artifact kind"):
        audit.load_artifact("unregistered", path, "test")


@pytest.mark.parametrize(
    "limit,content,message",
    [
        ("MAX_ARTIFACT_DEPTH", "[[[0]]]", "depth"),
        ("MAX_ARTIFACT_NODES", "[0,1,2,3]", "nodes"),
    ],
)
def test_artifact_structure_budget_enforced(tmp_path, monkeypatch, limit, content, message):
    monkeypatch.setattr(audit, limit, 2)
    path = tmp_path / "artifact.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        audit.load_json_payload(path, "test")


def test_artifact_path_size_and_read_errors(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="network-share"):
        audit.load_json_payload("//server/share/test.json", "test")
    path = tmp_path / "artifact.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ConfigError, match="exceeds 1 bytes"):
        audit.load_json_payload(path, "test", max_bytes=1)
    monkeypatch.setattr(Path, "open", Mock(side_effect=PermissionError("denied")))
    with pytest.raises(ConfigError, match="invalid test"):
        audit.load_json_payload(path, "test")


def test_report_requires_run_and_paired_cohort_files():
    store = Mock()
    store.run_info.return_value = None
    with pytest.raises(ConfigError, match="MISSING: run"):
        audit.collect_report_audit(Mock(), store, "missing")
    store.run_info.return_value = {"run_id": "test"}
    with pytest.raises(ConfigError, match="together"):
        audit.collect_report_audit(Mock(), store, "test", cohort_manifest_path="test.json")


@pytest.mark.parametrize(
    "mode,message",
    [
        ("run", "snapshot belongs to run"),
        ("status", "unsupported evidence_status"),
        ("state", "no longer matches"),
        ("artifact", "artifact does not match"),
    ],
)
def test_report_attachment_binding_mismatch_fails_closed(tmp_path, monkeypatch, mode, message):
    from tests.test_assessment_snapshot import SETTINGS, prepared_store
    from vulnassess import assessment_snapshot

    with prepared_store(str(tmp_path)) as store:
        frozen = assessment_snapshot.build_snapshot(SETTINGS, store, "snapshot")
        if mode == "run":
            frozen["run"]["run_id"] = "other"
        elif mode == "status":
            frozen["evidence_status"] = "claimed-complete"
        elif mode == "state":
            frozen["snapshot_hash"] = "stale"
        # Simulate independently validated attachments to exercise cross-file binding.
        monkeypatch.setattr(assessment_snapshot, "load_snapshot", Mock(return_value=frozen))
        monkeypatch.setattr(
            audit,
            "load_artifact",
            Mock(
                return_value=audit.AuditArtifact(
                    "scan", "synthetic.json", "hash", "NOT RUN", "test", {"snapshot_hash": "other"}
                )
            ),
        )
        with pytest.raises(ConfigError, match=message):
            audit.collect_report_audit(
                SETTINGS,
                store,
                "snapshot",
                snapshot_path="synthetic.json",
                artifact_paths={"scan": "synthetic.json"},
            )


def test_report_accepts_bound_artifact_without_claiming_live_execution(tmp_path):
    from tests.test_assessment_snapshot import SETTINGS, prepared_store

    payload = {
        "run_id": "snapshot",
        "evidence_status": "TESTED WITH MOCKS",
        "executed": False,
        "notice": "synthetic",
    }
    payload["summary_hash"] = audit._digest(payload)
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with prepared_store(str(tmp_path)) as store:
        result = audit.collect_report_audit(
            SETTINGS, store, "snapshot", artifact_paths={"scan": path}
        )
    assert result["artifacts"]["scan"] == payload
    assert (
        next(row for row in result["rows"] if row["component"] == "scan")["evidence_status"]
        == "TESTED WITH MOCKS"
    )
