"""Schema constraints, repository queries, provenance, and no-browser-write."""

import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from tests.test_ui import request
from vulnassess.errors import ConfigError
from vulnassess.repository import ENV_VAR, AssessmentRepository, resolve_backend

MIGRATIONS = Path(__file__).resolve().parents[1] / "db" / "migrations"


def _populate(repo: AssessmentRepository) -> dict[str, str]:
    """Create one coherent synthetic assessment; return the record ids."""
    ids: dict[str, str] = {}
    ids["engagement"] = repo.add_engagement(
        {
            "name": "College lab assessment",
            "owner_name": "lab lead",
            "authorisation_ref": "AUTH-TEST-001",
            "authorised_from": "2026-01-01",
            "authorised_until": "2026-12-31",
            "permitted_tools": ["nmap", "zap"],
        }
    )
    ids["target"] = repo.add_scope_entry(
        ids["engagement"],
        {
            "label": "Lab web",
            "target_kind": "ip",
            "target_value": "172.28.0.10",
            "authorization_ref": "AUTH-TEST-001",
        },
    )
    ids["canary"] = repo.add_scope_entry(
        ids["engagement"],
        {
            "label": "Canary",
            "target_kind": "ip",
            "target_value": "10.255.255.9",
            "authorization_ref": "AUTH-TEST-001",
            "entry_kind": "canary",
        },
    )
    ids["snapshot"] = repo.record_scope_snapshot(
        ids["engagement"], "run-1", {"targets": ["172.28.0.10"]}, "scopehash1"
    )
    ids["scan"] = repo.request_scan(
        {
            "target_id": ids["target"],
            "run_id": "run-1",
            "tool": "nmap",
            "command_summary": "nmap -sV 172.28.0.10",
            "operator": "student-analyst",
            "scope_snapshot_id": ids["snapshot"],
        }
    )
    repo.complete_scan(ids["scan"], "completed", {"hosts": 1}, "hashscan1")
    ids["asset"] = repo.record_asset(
        {
            "target_id": ids["target"],
            "run_id": "run-1",
            "address": "172.28.0.10",
            "hostname": "web.lab.invalid",
            "asset_role": "web_frontend",
            "environment": "prod",
            "criticality": "high",
        }
    )
    repo.observe_service(
        {
            "asset_id": ids["asset"],
            "scan_job_id": ids["scan"],
            "port": 443,
            "tls": True,
            "product": "synthetic-web",
            "evidence_source": "nmap",
        }
    )
    return ids


class MigrationSqlChecks(unittest.TestCase):
    """Static checks that the PostgreSQL migrations keep their guarantees."""

    def test_every_table_is_in_private_schema(self):
        for path in sorted(MIGRATIONS.glob("*.sql")):
            for match in re.finditer(
                r"create table if not exists\s+(\S+)", path.read_text(encoding="utf-8"), re.I
            ):
                self.assertTrue(match.group(1).startswith("vulnassess."), path.name)

    def test_every_new_table_enables_rls_and_revokes_roles(self):
        blanket = (MIGRATIONS / "009_retention_security.sql").read_text(encoding="utf-8")
        self.assertIn("enable row level security", blanket.lower())
        self.assertIn(
            "revoke all on all tables in schema vulnassess from anon, authenticated",
            blanket.lower(),
        )
        for path in sorted(MIGRATIONS.glob("*.sql")):
            if path.name in (
                "001_vulnassess_schema.sql",
                "002_assessment_evidence.sql",
                "009_retention_security.sql",
            ):
                continue
            sql = path.read_text(encoding="utf-8").lower()
            tables = re.findall(r"create table if not exists\s+vulnassess\.(\w+)", sql)
            for table in tables:
                self.assertIn(
                    f"vulnassess.{table} enable row level security",
                    sql,
                    f"{path.name}: missing RLS for {table}",
                )
                self.assertIn(
                    f"revoke all on vulnassess.{table} from anon, authenticated",
                    sql,
                    f"{path.name}: missing revoke for {table}",
                )

    def test_canary_scan_refusal_trigger_exists(self):
        sql = (MIGRATIONS / "003_governance_scope.sql").read_text(encoding="utf-8")
        self.assertIn("block_non_target_scan_jobs", sql)
        self.assertIn("entry_kind <> 'target'", sql)

    def test_analyst_suggestions_are_advisory_only(self):
        sql = (MIGRATIONS / "006_scoring_explainability.sql").read_text(encoding="utf-8")
        self.assertIn("check (is_advisory)", sql)

    def test_score_history_is_append_only_shape(self):
        sql = (MIGRATIONS / "006_scoring_explainability.sql").read_text(encoding="utf-8")
        self.assertIn("weights_hash", sql)
        self.assertIn("calculated_at", sql)

    def test_migrations_declare_idempotent_writes(self):
        seed = Path(__file__).resolve().parents[1] / "db" / "seeds" / "synthetic_assessment.sql"
        sql = seed.read_text(encoding="utf-8")
        inserts = re.findall(r"insert into\s+vulnassess\.(\w+)", sql, re.I)
        self.assertGreater(len(inserts), 20, "seed should cover the expanded schema")
        self.assertNotIn("delete from", sql.lower())


class BackendResolution(unittest.TestCase):
    def test_unset_value_prefers_env_var(self):
        original = os.environ.get(ENV_VAR)
        os.environ[ENV_VAR] = "postgresql://synthetic:placeholder@localhost:5432/postgres"
        try:
            backend = resolve_backend(None)
        finally:
            if original is None:
                os.environ.pop(ENV_VAR, None)
            else:
                os.environ[ENV_VAR] = original
        self.assertEqual(backend, "postgresql://synthetic:placeholder@localhost:5432/postgres")

    def test_explicit_sqlite_path_stays_sqlite_even_with_env_var(self):
        original = os.environ.get(ENV_VAR)
        os.environ[ENV_VAR] = "postgresql://synthetic:placeholder@localhost:5432/postgres"
        try:
            backend = resolve_backend("data/vulnassess.db")
        finally:
            if original is None:
                os.environ.pop(ENV_VAR, None)
            else:
                os.environ[ENV_VAR] = original
        self.assertEqual(str(backend), str(Path("data/vulnassess.db")))

    def test_missing_env_var_falls_back_to_sqlite(self):
        original = os.environ.pop(ENV_VAR, None)
        try:
            backend = resolve_backend(None)
        finally:
            if original is not None:
                os.environ[ENV_VAR] = original
        self.assertEqual(str(backend), str(Path("data/vulnassess.db")))


class RepositoryConstraints(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = AssessmentRepository(Path(self.tmp.name) / "assess.db")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def test_canary_target_cannot_be_scanned(self):
        ids = _populate(self.repo)
        with self.assertRaises(ConfigError):
            self.repo.request_scan(
                {"target_id": ids["canary"], "tool": "nmap", "command_summary": "nmap -sV canary"}
            )

    def test_scan_lifecycle_and_evidence_provenance(self):
        ids = _populate(self.repo)
        self.repo.connection.execute(
            "insert into findings (id, run_id, host_ip, tool, first_seen, last_seen) "
            "values ('f1', 'run-1', '172.28.0.10', 'nmap', '2026-01-01', '2026-01-02')"
        )
        self.repo.connection.commit()
        evidence_id = self.repo.add_evidence(
            ids["scan"],
            "f1",
            "nmap-excerpt",
            "443/tcp open",
            "source-hash-1",
            {"parser": "nmap", "raw_file": "not retained by policy"},
        )
        detail = self.repo.finding_evidence("f1")
        self.assertEqual(detail["evidence"][0]["id"], evidence_id)
        self.assertEqual(detail["evidence"][0]["source_sha256"], "source-hash-1")
        self.assertEqual(detail["evidence"][0]["tool"], "nmap")
        self.assertEqual(detail["evidence"][0]["provenance"]["raw_file"], "not retained by policy")

    def test_service_history_is_append_only(self):
        ids = _populate(self.repo)
        for version in ("1.0", "1.1"):
            self.repo.observe_service(
                {
                    "asset_id": ids["asset"],
                    "port": 443,
                    "tls": True,
                    "product": "synthetic-web",
                    "version": version,
                    "evidence_source": "nmap",
                }
            )
        history = self.repo.asset_details(ids["asset"])["service_history"]
        self.assertEqual(len(history), 3)
        versions = {row["version"] for row in history}
        self.assertEqual(versions, {None, "1.0", "1.1"})

    def test_score_history_preserves_band_transitions(self):
        _populate(self.repo)
        self.repo.connection.execute(
            "insert into findings (id, run_id, host_ip, tool, first_seen, last_seen) "
            "values ('f1', 'run-1', '172.28.0.10', 'nmap', '2026-01-01', '2026-01-02')"
        )
        self.repo.connection.commit()
        self.repo.record_score(
            {
                "run_id": "run-1",
                "finding_id": "f1",
                "weights_hash": "w1",
                "risk": 55,
                "band": "Medium",
                "explanation": "internal only",
            }
        )
        self.repo.record_score(
            {
                "run_id": "run-1",
                "finding_id": "f1",
                "weights_hash": "w2",
                "risk": 84,
                "band": "High",
                "explanation": "KEV and exposed",
            }
        )
        history = self.repo.finding_score_history("f1")
        self.assertEqual([row["band"] for row in history["history"]], ["Medium", "High"])
        self.assertEqual(history["band_transitions"][0]["from_band"], "Medium")
        self.assertEqual(history["band_transitions"][0]["to_band"], "High")

    def test_review_decision_rejects_unknown_value(self):
        _populate(self.repo)
        self.repo.connection.execute(
            "insert into findings (id, run_id, host_ip, tool, first_seen, last_seen) "
            "values ('f1', 'run-1', '172.28.0.10', 'nmap', '2026-01-01', '2026-01-02')"
        )
        self.repo.connection.commit()
        self.repo.add_review_decision(
            {
                "finding_id": "f1",
                "reviewer": "lab lead",
                "decision": "needs_investigation",
                "justification": "check evidence",
            }
        )
        with self.assertRaises(ConfigError):
            self.repo.add_review_decision(
                {
                    "finding_id": "f1",
                    "reviewer": "lab lead",
                    "decision": "delete_it",
                    "justification": "invalid",
                }
            )

    def test_finding_cwe_requires_cwe_prefix(self):
        with self.assertRaises(ConfigError):
            self.repo.link_finding_cwe("f1", "not-a-cwe")

    def test_analyst_suggestion_stored_as_advisory(self):
        _populate(self.repo)
        self.repo.add_analyst_suggestion(
            {
                "run_id": "run-1",
                "finding_id": None,
                "host_ip": "172.28.0.10",
                "model": "local-demo",
                "suggestion": "advisory only",
                "cited_evidence": ["scopehash1"],
            }
        )
        row = self.repo._one("select is_advisory from analyst_suggestions limit 1")
        self.assertEqual(row["is_advisory"], 1)

    def test_remediation_requires_evidence_before_verified(self):
        _populate(self.repo)
        self.repo.connection.execute(
            "insert into findings (id, run_id, host_ip, tool, first_seen, last_seen) "
            "values ('f1', 'run-1', '172.28.0.10', 'nmap', '2026-01-01', '2026-01-02')"
        )
        self.repo.connection.commit()
        self.repo.set_remediation_status("f1", "pending_verification")
        self.repo.set_remediation_status(
            "f1",
            "verified",
            verification_run_id="run-2",
            evidence={"verification": "rescan shows service gone"},
        )
        row = self.repo._one("select status, verification_run_id from remediation_tracking")
        self.assertEqual(row["status"], "verified")
        self.assertEqual(row["verification_run_id"], "run-2")

    def test_research_records_are_hash_pinned(self):
        dataset = self.repo.add_dataset(
            {
                "name": "synthetic-lab",
                "version": "1",
                "source": "generator",
                "data_kind": "synthetic",
                "quality": "approved",
                "config_hash": "cfg1",
                "content_sha256": "datahash1",
                "row_count": 10,
            }
        )
        self.repo.add_ground_truth(dataset, "host_role", "172.28.0.10", "web_frontend", "annot")
        self.repo.add_role_model_run(
            {
                "dataset_id": dataset,
                "model_name": "demo",
                "model_hash": "mhash1",
                "label_set": ["web_frontend"],
                "split": {"seed": 42},
                "accuracy": 0.9,
                "macro_f1": 0.88,
                "confusion": {"web_frontend": {"web_frontend": 9}},
                "abstention_rate": 0.1,
                "coverage": 1.0,
            }
        )
        self.repo.add_ablation(
            {
                "dataset_id": dataset,
                "variant": "full_context",
                "config_hash": "abl1",
                "metrics": {"ndcg": 0.88},
            }
        )
        evaluations = self.repo.model_evaluations()
        self.assertEqual(evaluations["role_model_runs"][0]["model_hash"], "mhash1")
        self.assertEqual(evaluations["role_model_runs"][0]["dataset_version"], "1")
        ablations = self.repo.ablation_summaries()
        self.assertEqual(ablations[0]["variant"], "full_context")

    def test_audit_trail_records_lifecycle(self):
        _populate(self.repo)
        events = self.repo._rows("select event_type from audit_events order by occurred_at")
        recorded = [row["event_type"] for row in events]
        self.assertIn("engagement.created", recorded)
        self.assertIn("scope.entry_added", recorded)
        self.assertIn("scan.requested", recorded)
        self.assertIn("scan.completed", recorded)


class NoBrowserWriteAccess(unittest.TestCase):
    """The dashboard stays GET-only and the store is opened read-only."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "assess.db"
        with AssessmentRepository(self.db_path) as repo:
            _populate(repo)
        from vulnassess.ui.server import UiApplication

        self.application = UiApplication(self.db_path, Path("config"))

    def tearDown(self):
        self.tmp.cleanup()

    def _get(self, route: str) -> dict:
        status, _, body = request(self.application, f"/{route}")
        self.assertEqual(status, 200)
        return json.loads(body)

    def test_assessment_routes_are_readable(self):
        runs = self._get("api/assessment-runs")
        self.assertEqual(runs["runs"][0]["authorisation_ref"], "AUTH-TEST-001")
        findings = self._get("api/findings")
        self.assertIsInstance(findings["findings"], list)

    def test_filters_narrow_the_findings_queue(self):
        matched = self._get("api/findings?severity=critical")["findings"]
        self.assertEqual(matched, [])

    def test_write_verbs_are_refused(self):
        for method in ("POST", "PUT", "DELETE"):
            status, _, _ = request(
                self.application,
                "/api/findings",
                method=method,
                body=b"{}" if method != "DELETE" else b"",
            )
            self.assertEqual(status, 405, method)

    def test_database_url_is_never_served(self):
        for route in ("api/assessment-runs", "api/findings", "api/ablations"):
            body = json.dumps(self._get(route))
            self.assertNotIn("postgresql://", body)
            self.assertNotIn("postgres://", body)
            self.assertNotIn(ENV_VAR, body)

    def test_read_only_repository_refuses_writes(self):
        with AssessmentRepository(self.db_path, read_only=True) as repo:
            with self.assertRaises(ConfigError):
                repo.audit("should.not.write")


if __name__ == "__main__":
    unittest.main()
