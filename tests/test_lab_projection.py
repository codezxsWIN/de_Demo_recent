"""Synthetic retained-evidence publication: no scans, feeds or AI calls."""

import copy
import json
import shutil
import struct
from pathlib import Path

import pytest

from vulnassess import capture_history
from vulnassess.errors import ConfigError
from vulnassess.lab_assessment import ACTIONS
from vulnassess.lab_live import LiveLab
from vulnassess.lab_projection import project, publish
from vulnassess.network_service_policy import load
from vulnassess.schema import Enrichment
from vulnassess.settings import Settings
from vulnassess.store import Store
from vulnassess.ui import assessment_report, vulnerability_findings

ROOT = Path(__file__).resolve().parents[1]


class Traffic:
    def collect(self, *_args):
        return {"packet_ids": [], "packets": [], "causal_validation": False}, struct.pack(
            "<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1
        )


class Console:
    def __init__(self, root):
        self.root = root

    def endpoint(self, _environment, port):
        settings = Settings(self.root / "config")
        policy = load(settings.config_dir, settings.scope, "127.0.0.2")
        return "127.0.0.2", next(e for e in policy["endpoints"] if e["port"] == port)

    def action(self, _name):
        return {
            "proof": {
                "protocol_confirmed": True,
                "anonymous_accepted": True,
                "response": "230 Synthetic accepted login",
            },
            "decision": {"violations": ["Authentication policy violation"], "inconclusive": False},
        }


@pytest.fixture
def lab_suite(tmp_path):
    shutil.copytree(ROOT / "config", tmp_path / "config")
    lab = LiveLab(tmp_path, traffic=Traffic(), console=Console(tmp_path), control=object())
    case = lab._operation("office", "ftp-anonymous", kind="full_assessment")
    checks = [
        {
            "action": action,
            "port": endpoint[0],
            "transport": endpoint[1],
            "state": "complete" if action == case["action"] else "skipped",
            "case_id": case["id"] if action == case["action"] else None,
        }
        for action, endpoint in ACTIONS["office"].items()
    ]
    suite = {
        "schema_version": 1,
        "id": "full-" + "a" * 32,
        "environment": "office",
        "target": "127.0.0.2",
        "status": "partial",
        "started_at": case["started_at"],
        "finished_at": case["finished_at"],
        "checks": checks,
        "cases": [lab.assessments._compact(case)],
        "coverage": {
            "attempted_endpoints": 1,
            "declared_endpoints": 7,
            "known_conditions": 8,
            "tested_conditions": 1,
            "untested_conditions": 7,
        },
        "ground_truth": {
            "status": "unverified",
            "profile": "synthetic",
            "issues": ["Synthetic runtime; no Docker inspection"],
        },
    }
    lab.assessments._save(suite)
    return lab, suite, case


def test_one_snapshot_reaches_database_findings_and_normal_report_without_new_scan(lab_suite):
    lab, suite, case = lab_suite
    saved = lab.publish_assessment(suite["id"])
    linked = saved["main_assessment"]
    assert linked["status"] == "saved"
    record = capture_history.load(lab.root / "data/live/raw", linked["capture_id"])
    assert record["result"]["scan_status"] == "partial"
    assert record["result"]["ai_status"] == "not_attempted"
    assert record["payload"]["enrichments"] == []
    assert record["payload"]["scanner_coverage"]["nmap"].startswith("not run")
    with Store(lab.database) as db:
        assert db.findings(linked["run_id"])[0].to_json() == case["findings"][0]["finding"]
        assert db.scores(linked["run_id"])[0].to_json() == case["findings"][0]["score"]
        assert db.feeds_meta(run_id=linked["run_id"]) == {}
    dashboard = vulnerability_findings.selected(lab.root / "data/live/raw", linked["capture_id"])
    assert "Authentication" in json.dumps(dashboard) or "Unauthenticated" in json.dumps(dashboard)
    html = assessment_report.render(record)
    assert "Live network assessment" in html
    assert case["id"] in html and "Synthetic accepted login" in html
    assert "no web-scanner coverage" in html
    assert "remain inconclusive" in html
    assert "Partial scan — requested checks failed." not in html


def test_republication_is_idempotent_and_does_not_depend_on_current_settings(
    lab_suite, monkeypatch
):
    lab, suite, _case = lab_suite
    first = publish(lab, suite, lab.database)
    raw = (lab.root / "data/live/raw" / first["capture_id"] / "case.json").read_bytes()
    monkeypatch.setattr(
        "vulnassess.settings.Settings",
        lambda *_: pytest.fail("Publishing retained evidence must not read current settings"),
    )
    second = publish(lab, suite, lab.database)
    assert second == first
    with Store(lab.database) as db:
        assert db.connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
        assert len(db.findings(first["run_id"])) == 1
    assert (lab.root / "data/live/raw" / first["capture_id"] / "case.json").read_bytes() == raw


def test_unrelated_current_intelligence_cannot_leak_into_native_lab_report(lab_suite):
    lab, suite, case = lab_suite
    finding_id = case["findings"][0]["finding"]["id"]
    with Store(lab.database) as db:
        db.upsert_enrichment(
            Enrichment(finding_id, "CVE-2099-99999", "synthetic", 0.1, epss=0.99, kev=True)
        )
        db.connection.execute(
            "INSERT INTO feeds_meta VALUES (?, ?, ?, ?, ?, ?)",
            ("epss", "synthetic.csv", "f" * 64, "2099-01-01", 1, "2099-01-01"),
        )
        db.connection.commit()
    linked = publish(lab, suite, lab.database)
    with Store(lab.database) as db:
        assert db.enrichments(finding_id)  # global data really exists
        assert db.enrichments(finding_id, run_id=linked["run_id"]) == []
        assert db.feeds_meta(run_id=linked["run_id"]) == {}
    record = capture_history.load(lab.root / "data/live/raw", linked["capture_id"])
    assert "CVE-2099-99999" not in assessment_report.render(record)
    assert record["payload"]["scores"] == [case["findings"][0]["score"]]


def test_configuration_identity_is_not_the_run_evidence_identity(lab_suite):
    lab, suite, _case = lab_suite
    first = publish(lab, suite, lab.database)
    repeat = copy.deepcopy(suite)
    repeat["id"] = "full-" + "b" * 32
    second = publish(lab, repeat, lab.database)
    before = capture_history.load(lab.root / "data/live/raw", first["capture_id"])
    after = capture_history.load(lab.root / "data/live/raw", second["capture_id"])
    assert first["source_sha256"] != second["source_sha256"]
    assert before["configuration_hash"] == after["configuration_hash"]
    assert before["snapshot_hash"] != after["snapshot_hash"]


@pytest.mark.parametrize("change", ["missing_priority", "wrong_priority_host", "duplicate_context"])
def test_invalid_native_projection_cannot_leave_database_rows(lab_suite, change):
    lab, suite, _case = lab_suite
    payload = project(lab, suite)
    if change == "missing_priority":
        payload["scores"] = []
    elif change == "wrong_priority_host":
        payload["scores"][0]["host_ip"] = "192.0.2.1"
    else:
        payload["context"].append(copy.deepcopy(payload["context"][0]))
    with Store(lab.database) as db:
        with pytest.raises(ConfigError, match="unbound native evidence"):
            db.import_frozen_network_run(
                "synthetic-invalid", "a" * 64, suite["finished_at"], payload, {}
            )
        assert db.connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0


def test_ai_bookkeeping_does_not_change_collection_binding_but_protocol_edits_do(lab_suite):
    lab, suite, case = lab_suite
    original = project(lab, suite)
    case["ai"] = {"status": "not_requested", "note": "Synthetic later bookkeeping"}
    case["ai_attempts"] = [{"status": "failed", "stage": "generate"}]
    lab._save(case)
    assert project(lab, suite) == original
    case["result"]["proof"]["anonymous_accepted"] = False
    lab._save(case)
    with pytest.raises(ConfigError, match="Collection evidence changed"):
        project(lab, suite)


def test_database_failure_rolls_back_every_run_row_and_retry_preserves_report(lab_suite):
    lab, suite, _case = lab_suite
    with Store(lab.database) as db:
        db.connection.execute(
            "CREATE TRIGGER synthetic_failure BEFORE INSERT ON scores BEGIN SELECT RAISE(ABORT, 'synthetic database failure'); END"
        )
        db.connection.commit()
    with pytest.raises(ConfigError, match="database publication failed"):
        publish(lab, suite, lab.database)
    with Store(lab.database) as db:
        for table in ("runs", "hosts", "finding_runs", "context_profiles", "scores"):
            assert db.connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] == 0
        db.connection.execute("DROP TRIGGER synthetic_failure")
        db.connection.commit()
    linked = publish(lab, suite, lab.database)
    assert capture_history.load(lab.root / "data/live/raw", linked["capture_id"])
    assert linked["status"] == "saved"


def test_changed_publication_is_never_overwritten(lab_suite):
    lab, suite, _case = lab_suite
    linked = publish(lab, suite, lab.database)
    path = lab.root / "data/live/raw" / linked["capture_id"] / "case.json"
    path.write_bytes(b"synthetic changed content")
    with pytest.raises(ConfigError, match="nothing was overwritten"):
        publish(lab, suite, lab.database)
    assert path.read_bytes() == b"synthetic changed content"


def test_unrelated_case_and_unsupported_database_never_publish(lab_suite):
    lab, suite, _case = lab_suite
    unrelated = copy.deepcopy(suite)
    unrelated["checks"][0]["action"] = "ssh-credential"
    with pytest.raises(ConfigError):
        project(lab, unrelated)
    with pytest.raises(ConfigError, match="SQLite"):
        publish(lab, suite, "postgres://synthetic.invalid/database")
    assert not (lab.root / "data/live/raw").exists()


def test_protocol_text_and_untrusted_identifiers_cannot_create_report_markup():
    html = assessment_report._network_lab_evidence(
        {
            "network_lab": {
                "environment": "iot",
                "checks": [
                    {
                        "case_id": "live-<script>alert(1)</script>",
                        "port": 1161,
                        "transport": "udp",
                        "action": '<img src=x onerror="alert(1)">',
                        "proof": {"response": "<script>alert(2)</script>"},
                    }
                ],
            }
        }
    )
    assert "<script>" not in html and "<img " not in html
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html
    assert "/api/network-live/evidence/" not in html
