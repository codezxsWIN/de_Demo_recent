"""Synthetic cross-run isolation through the real store and report readers."""

import json
import shutil
import sqlite3
import subprocess
from dataclasses import replace

import pytest

from tests.test_all import make_finding, make_profile
from tests.test_intel_trace import SETTINGS, SYNTHETIC, apache
from vulnassess import audit, intel, pipeline, run_history
from vulnassess.assessment_snapshot import build_snapshot
from vulnassess.errors import ConfigError
from vulnassess.schema import Host
from vulnassess.store import SCHEMA, Store
from vulnassess.ui.reader import ReadOnlyStore


def record_run(store, run_id, finding):
    store.start_run(run_id, SETTINGS.config_hash())
    store.upsert_host(run_id, Host(ip=finding.host_ip, services=(apache("2.4.49"),)))
    store.upsert_findings(run_id, [finding])
    store.upsert_profile(run_id, make_profile(host_ip=finding.host_ip))
    intel.enrich_run(run_id, store)
    pipeline.do_rank(SETTINGS, store, run_id)


def test_second_run_keeps_its_own_observation(tmp_path):
    first = make_finding()
    first = replace(
        first, provenance=replace(first.provenance, run_id="a", raw_path="synthetic/a.xml")
    )
    second = replace(
        first,
        evidence="SYNTHETIC second observation",
        last_seen="2026-10-07",
        provenance=replace(first.provenance, run_id="b", raw_path="synthetic/b.xml"),
    )
    with Store(tmp_path / "synthetic.db") as store:
        store.start_run("a", "config")
        store.start_run("b", "config")
        store.upsert_findings("a", [first])
        store.upsert_findings("b", [second])
        assert store.findings("b") == [second]
        assert store.findings("a") == [first]


def test_later_intelligence_cannot_change_prior_snapshot_report_or_viewer(tmp_path):
    database = tmp_path / "synthetic.db"
    with Store(database) as store:
        intel.load_feeds(SYNTHETIC / "feeds", store)
        first = make_finding()
        record_run(store, "a", first)
        before = build_snapshot(SETTINGS, store, "a")
        audit_before = audit.collect_report_audit(SETTINGS, store, "a")
        report = pipeline.do_report(SETTINGS, store, "a", tmp_path / "before.html").read_bytes()
        with ReadOnlyStore(database) as viewer:
            payload = viewer.run("a")
        store.put_epss([("CVE-1999-9001", 0.01, 0.02, "2026-10-07")])
        store.put_feed_meta("epss", "synthetic-next-feed", "next-hash", "2026-10-07", 1)
        record_run(store, "b", replace(first, evidence="SYNTHETIC later raw evidence"))
        assert build_snapshot(SETTINGS, store, "a") == before
        assert audit.collect_report_audit(SETTINGS, store, "a") == audit_before
        assert (
            pipeline.do_report(SETTINGS, store, "a", tmp_path / "after.html").read_bytes() == report
        )
    with ReadOnlyStore(database) as viewer:
        assert viewer.run("a") == payload
        assert viewer.run("b")["findings"][0]["evidence"] == "SYNTHETIC later raw evidence"


def test_unenriched_and_zero_match_runs_do_not_inherit_cached_cves(tmp_path):
    with Store(tmp_path / "synthetic.db") as store:
        intel.load_feeds(SYNTHETIC / "feeds", store)
        first = make_finding()
        record_run(store, "a", first)
        store.start_run("b", "config")
        store.upsert_findings("b", [replace(first, cve_ids=())])
        assert store.enrichments(first.id, run_id="b") == []
        assert store.feeds_meta(run_id="b") == {}
        intel.enrich_run("b", store)
        assert store.enrichments(first.id, run_id="b") == []
        assert store.enrichments(first.id, run_id="a")
        assert store.feeds_meta(run_id="b")


def test_explicit_refresh_appends_and_identical_refresh_is_idempotent(tmp_path):
    with Store(tmp_path / "synthetic.db") as store:
        intel.load_feeds(SYNTHETIC / "feeds", store)
        record_run(store, "a", make_finding())
        previous = store.history_status("a")
        old_rows = store.connection.execute("SELECT * FROM run_intelligence").fetchall()
        intel.enrich_run("a", store)
        assert store.history_status("a") == previous
        store.put_epss([("CVE-1999-9001", 0.01, 0.02, "2026-10-07")])
        intel.enrich_run("a", store)
        assert (
            store.history_status("a")["intelligence_revision"]
            == previous["intelligence_revision"] + 1
        )
        assert (
            store.connection.execute("SELECT * FROM run_intelligence ORDER BY revision").fetchall()[
                : len(old_rows)
            ]
            == old_rows
        )


def legacy_database(path):
    observation = make_finding()
    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA)
        connection.execute("INSERT INTO runs VALUES ('legacy', '2026-09-05', 'config', '{}')")
        connection.execute(
            "INSERT INTO findings VALUES (?, 'legacy', ?, ?, ?, ?, ?)",
            (
                observation.id,
                observation.host_ip,
                observation.tool,
                json.dumps(observation.to_json()),
                observation.first_seen,
                observation.last_seen,
            ),
        )
        connection.execute(
            "INSERT INTO finding_runs VALUES ('legacy', ?, ?)",
            (observation.id, observation.last_seen),
        )
    return observation


def test_legacy_read_is_nonmutating_and_migration_preserves_rows_and_labels(tmp_path):
    database = tmp_path / "legacy.db"
    observation = legacy_database(database)
    with ReadOnlyStore(database) as viewer:
        original = viewer.run("legacy")
        assert "not frozen" in original["history"]["limitations"][0]
        assert not run_history.exists(viewer.connection, "run_intelligence")
    with Store(database) as store:
        saved = store.history_status("legacy")
        assert "at migration" in saved["limitations"][0]
        assert store.findings("legacy") == [observation]
        # Old-code reads remain valid against the additive schema (application rollback).
        assert (
            json.loads(store.connection.execute("SELECT json FROM findings").fetchone()[0])
            == observation.to_json()
        )
        store.connection.execute(
            "UPDATE findings SET json = ?",
            (json.dumps(replace(observation, evidence="SYNTHETIC cache changed").to_json()),),
        )
        store.connection.commit()
    with Store(database) as reopened:
        assert reopened.history_status("legacy") == saved
        assert reopened.findings("legacy") == [observation]


def test_failed_migration_rolls_back_all_history_and_preserves_legacy(tmp_path, monkeypatch):
    database = tmp_path / "legacy.db"
    observation = legacy_database(database)
    append = run_history.append_snapshot

    def fail_after_write(*args, **kwargs):
        append(*args, **kwargs)
        raise RuntimeError("SYNTHETIC migration failure")

    monkeypatch.setattr(run_history, "append_snapshot", fail_after_write)
    with pytest.raises(RuntimeError, match="migration failure"):
        Store(database)
    with sqlite3.connect(database) as connection:
        assert not run_history.exists(connection, "run_intelligence")
        assert not run_history.exists(connection, "finding_observations")
        assert (
            json.loads(connection.execute("SELECT json FROM findings").fetchone()[0])
            == observation.to_json()
        )


def test_failed_observation_batch_rolls_back_membership_and_payload(tmp_path):
    def broken_batch():
        yield make_finding()
        raise RuntimeError("SYNTHETIC parse failure")

    with Store(tmp_path / "synthetic.db") as store:
        store.start_run("a", "config")
        with pytest.raises(RuntimeError, match="parse failure"):
            store.upsert_findings("a", broken_batch())
        assert store.findings("a") == []
        assert (
            store.connection.execute("SELECT COUNT(*) FROM finding_observations").fetchone()[0] == 0
        )
        assert store.connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_failed_intelligence_cache_write_rolls_back_new_revision(tmp_path):
    with Store(tmp_path / "synthetic.db") as store:
        intel.load_feeds(SYNTHETIC / "feeds", store)
        record_run(store, "a", make_finding())
        before = store.history_status("a")
        store.put_epss([("CVE-1999-9001", 0.01, 0.02, "2026-10-07")])
        store.connection.execute(
            "CREATE TRIGGER reject_update BEFORE UPDATE ON enrichments "
            "BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="write failure"):
            intel.enrich_run("a", store)
        assert store.history_status("a") == before


def test_tampered_history_is_rejected_by_store_and_viewer(tmp_path):
    database = tmp_path / "synthetic.db"
    with Store(database) as store:
        store.start_run("a", "config")
        store.connection.execute("UPDATE run_intelligence SET json = '{}' WHERE run_id = 'a'")
        store.connection.commit()
        with pytest.raises(ConfigError, match="hash mismatch"):
            store.feeds_meta(run_id="a")
    with ReadOnlyStore(database) as viewer, pytest.raises(ConfigError, match="hash mismatch"):
        viewer.run("a")


def test_postgres_export_refuses_to_drop_run_history(tmp_path):
    from scripts.export_sqlite_seed import export

    database = tmp_path / "synthetic.db"
    with Store(database) as store:
        store.start_run("a", "config")
    with pytest.raises(ConfigError, match="cannot preserve SQLite run history"):
        export(database)


def test_missing_isolated_observation_cannot_fall_back_to_global_record(tmp_path):
    database = tmp_path / "synthetic.db"
    with Store(database) as store:
        store.start_run("a", "config")
        store.upsert_findings("a", [make_finding()])
        store.connection.execute("DELETE FROM finding_observations WHERE run_id = 'a'")
        store.connection.commit()
        with pytest.raises(ConfigError, match="missing run observation"):
            store.findings("a")
    with (
        ReadOnlyStore(database) as viewer,
        pytest.raises(ConfigError, match="missing run observation"),
    ):
        viewer.run("a")


def test_feed_inspector_distinguishes_recorded_legacy_and_missing_metadata():
    from pathlib import Path

    node = shutil.which("node")
    assert node is not None, "Node is required for the existing UI runtime checks"
    source = (
        Path(__file__).resolve().parents[1] / "vulnassess/ui/static/workflow-data.js"
    ).read_text(encoding="utf-8")
    script = (
        source
        + """
const assessment = {run:{summary:{}},hosts:[],findings:[],context:[],scores:[],enrichments:[],rationales:[],
  feeds_meta:[{feed:'nvd',path:'publisher-cache'}], feeds_meta_scope:'run_snapshot',history:{limitations:[]}};
const message = () => nodeDetails('nvd', assessment, null, null).message;
if (!message().includes('recorded for this assessment run')) throw Error('native scope missing');
assessment.history.limitations = ['Legacy state was frozen at migration'];
if (!message().includes('frozen at migration')) throw Error('legacy disclosure missing');
assessment.feeds_meta = [];
if (!message().includes('No feed metadata')) throw Error('empty state misleading');
assessment.feeds_meta_scope = 'current_store_not_frozen_per_run';
if (!message().includes('current store state')) throw Error('unmigrated scope missing');
"""
    )
    checked = subprocess.run(
        [node, "--input-type=module"],
        input=script,
        encoding="utf-8",
        capture_output=True,
        timeout=15,
    )
    assert checked.returncode == 0, checked.stderr
