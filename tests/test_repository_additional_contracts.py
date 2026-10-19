"""Additional persistence contracts use real temporary SQLite databases."""

import sqlite3

import pytest

from tests.test_assessment_store import _populate
from vulnassess.errors import ConfigError
from vulnassess.repository import AssessmentRepository


def test_extended_evidence_links_round_trip(tmp_path):
    with AssessmentRepository(tmp_path / "assessment.db") as repo:
        ids = _populate(repo)
        repo.connection.execute(
            "insert into findings (id, run_id, host_ip, tool, first_seen, last_seen, severity, lifecycle_status) values ('f1', 'run-1', '172.28.0.10', 'nmap', '2026-01-01', '2026-01-02', 'high', 'open')"
        )
        repo.connection.commit()
        repo.link_finding_cve("f1", "CVE-2021-44228", "nmap", 0.8)
        repo.link_finding_cwe("f1", "CWE-78")
        repo.link_finding_asset("f1", ids["asset"])
        repo.put_vuln_intel(
            {
                "cve_id": "CVE-2021-44228",
                "feed_source": "synthetic",
                "epss_score": 0.5,
                "in_kev": True,
            }
        )
        peer = repo.record_asset(
            {"target_id": ids["target"], "run_id": "run-1", "address": "172.28.0.11"}
        )
        repo.relate_assets(ids["asset"], peer, "connects_to", {"source": "test"})
        prediction = repo.record_role_prediction(
            {
                "run_id": "run-1",
                "host_ip": "172.28.0.10",
                "predicted_role": "web_frontend",
                "confidence": 0.8,
                "model_version": "synthetic",
                "model_hash": "test",
            }
        )
        signal = repo.record_context_signal(
            {
                "run_id": "run-1",
                "host_ip": "172.28.0.10",
                "signal_kind": "control",
                "value": True,
                "source": "scanner",
            }
        )
        comment = repo.add_comment(
            {"finding_id": "f1", "author": "synthetic", "body": "Review evidence before confirming"}
        )
        assert prediction and signal and comment
        detail = repo.finding_evidence("f1")
        assert detail["cves"][0]["cve_id"] == "CVE-2021-44228"
        assert detail["cves"][0]["in_kev"] == 1
        assert detail["cwes"][0]["cwe_id"] == "CWE-78"
        assert repo.asset_details(ids["asset"])["relationships"][0]["evidence"] == {
            "source": "test"
        }
        assert len(repo.asset_inventory()) == 2
        assert len(repo.asset_inventory("run-1")) == 2
        assert repo.asset_inventory("other") == []
        assert len(repo.findings_queue(status="open", severity="high", run_id="run-1")) == 1
        assert repo.findings_queue(status="closed") == []
        assert repo.findings_queue(decision="accepted") == []
        assert len(repo.scope_entries(ids["engagement"])) == 2
        assert repo.connection.execute("select count(*) from finding_assets").fetchone()[0] == 1
        assert (
            repo.connection.execute(
                "select predicted_role from role_predictions where id=?", (prediction,)
            ).fetchone()[0]
            == "web_frontend"
        )
        assert (
            repo.connection.execute("select body from comments where id=?", (comment,)).fetchone()[
                0
            ]
            == "Review evidence before confirming"
        )
        assert (
            repo.connection.execute(
                "select value from context_signals where id=?", (signal,)
            ).fetchone()[0]
            == "true"
        )


@pytest.mark.parametrize("method", ["asset_details", "finding_evidence", "finding_score_history"])
def test_missing_records_are_not_empty_success(tmp_path, method):
    with AssessmentRepository(tmp_path / "assessment.db") as repo:
        with pytest.raises(ConfigError, match="MISSING"):
            getattr(repo, method)("missing")


def test_readonly_repository_missing_and_failed_connect(tmp_path, monkeypatch):
    path = tmp_path / "missing.db"
    with pytest.raises(ConfigError, match="MISSING"):
        AssessmentRepository(path, read_only=True)
    path.touch()

    def connect(*args, **kwargs):
        raise sqlite3.OperationalError("locked")

    monkeypatch.setattr(sqlite3, "connect", connect)
    with pytest.raises(ConfigError, match="cannot open read-only"):
        AssessmentRepository(path, read_only=True)
