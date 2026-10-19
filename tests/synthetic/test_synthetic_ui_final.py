"""Offline UI outcomes using real SQLite/registries and controlled I/O boundaries."""

import copy
import io
import json
import shutil
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from tests.test_assessment_snapshot import ROOT, SETTINGS, prepared_store
from tests.test_assessment_store import _populate
from tests.test_scan_plan_ui import baseline
from tests.test_server_failure_contracts import handler
from tests.test_ui import MemoryConnection
from vulnassess import evidence_requests, scan_plans, self_defence
from vulnassess.errors import ConfigError, NeedsReview
from vulnassess.repository import AssessmentRepository
from vulnassess.schema import Host
from vulnassess.store import Store
from vulnassess.ui import reader, server


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.delenv(server.ENV_VAR, raising=False)
    with prepared_store(str(tmp_path)):
        pass
    config = tmp_path / "config"
    shutil.copytree(ROOT / "config", config)
    value = server.UiApplication(tmp_path / "assessment.db", config, "snapshot")
    value.scan_plans = scan_plans.PlanRegistry(tmp_path / "synthetic_plan_audit.jsonl")
    value.evidence_requests = evidence_requests.EvidenceRequests(tmp_path / "synthetic_evidence")
    monkeypatch.setattr(
        server.live_assessment, "nmap_probe", lambda: ("synthetic-nmap", "available")
    )
    monkeypatch.setattr(
        server.live_assessment, "run", Mock(side_effect=AssertionError("scanner forbidden"))
    )
    monkeypatch.setattr(
        server.analyst, "provider_client", Mock(side_effect=AssertionError("provider forbidden"))
    )
    return value


def test_selected_run_query_renders_that_runs_records(app):
    response = app.get("/?run=snapshot")
    assert response.status == 200
    assert b"172.28.0.10" in response.body and b"snapshot" in response.body
    assert app.get("/?run=missing").status == 409


def test_assessment_routes_return_persisted_assets_evidence_and_scores(app):
    with AssessmentRepository(app.database) as repo:
        ids = _populate(repo)
        finding_id = repo.connection.execute("select id from findings limit 1").fetchone()[0]
        repo.add_evidence(ids["scan"], finding_id, "banner", "SYNTHETIC banner", "synthetic-hash")
        # The legacy prepared store already owns the finding; append the research history.
        repo.connection.execute(
            "insert into score_history (finding_id, run_id, weights_hash, formula_version, "
            "cvss_inputs, environmental, risk, band, explanation, recommendation, calculated_at) "
            "values (?, 'snapshot', 'synthetic-weights', 'v1', '{}', '{}', 40, 'Medium', "
            "'SYNTHETIC explanation', 'Review', '2026-01-01')",
            (finding_id,),
        )
        repo.connection.commit()
    assets = json.loads(app.get("/api/assets?run=run-1").body)["assets"]
    assert [asset["id"] for asset in assets] == [ids["asset"]]
    assert json.loads(app.get("/api/assets?run=missing").body) == {"assets": []}
    detail = json.loads(app.get(f"/api/asset/{ids['asset']}").body)
    assert detail["asset"]["address"] == "172.28.0.10"
    assert detail["service_history"][0]["port"] == 443
    evidence = json.loads(app.get(f"/api/finding/{finding_id}").body)
    assert evidence["finding"]["id"] == finding_id
    assert evidence["evidence"][0]["excerpt"] == "SYNTHETIC banner"
    history = json.loads(app.get(f"/api/finding/{finding_id}/score-history").body)
    assert history["latest"]["risk"] == 40 and history["band_transitions"] == []
    assert json.loads(app.get("/api/findings?limit=invalid").body) == json.loads(
        app.get("/api/findings?limit=200").body
    )
    evaluations = app.get("/api/model-evaluations")
    assert evaluations.status == 200
    assert json.loads(evaluations.body) == {"role_model_runs": [], "legacy_model_evaluations": []}


def test_scanner_status_reports_unavailability_and_import_only_tool(app, monkeypatch):
    monkeypatch.setattr(server.live_assessment, "nmap_probe", lambda: (None, "SYNTHETIC absent"))
    monkeypatch.setattr(
        server.orchestrator,
        "scanner_status",
        lambda _: {"status": "unavailable", "detail": "SYNTHETIC absent"},
    )
    response = app.get("/api/scanner-status")
    assert response.status == 200
    status = json.loads(response.body)
    assert status["nmap"] == {"status": "unavailable", "detail": "SYNTHETIC absent"}
    assert status["nikto"]["status"] == "unavailable"
    assert status["nessus"]["status"] == "import-only"


@pytest.mark.parametrize("action,body", [("delete", {}), ("approve", {}), ("edit", {})])
def test_malformed_plan_actions_do_not_create_authority(app, action, body):
    with pytest.raises(ConfigError, match="Invalid plan edit or approval"):
        app.scan_plan_action(action, body)
    assert not app.scan_plans.audit_path.exists()


@pytest.mark.parametrize(
    "action,body",
    [
        ("delete", {}),
        ("approve", {}),
        ("reject", {"request_id": 1, "request_hash": "hash", "reason": "no"}),
    ],
)
def test_malformed_evidence_actions_do_not_create_authority(app, action, body):
    with pytest.raises(ConfigError, match="Invalid evidence approval or rejection"):
        app.evidence_request_action(action, body)
    assert not app.evidence_requests.audit_path.exists()


@pytest.mark.parametrize("recent", [False, True])
def test_reanalysis_requires_approved_supplemental_evidence(app, recent):
    if recent:
        with reader.ReadOnlyStore(app.database) as store:
            payload = store.run("snapshot")
        app._recent_live_cases["172.28.0.10"] = (time.monotonic(), {"payload": payload})
    with pytest.raises(ConfigError, match="No approved follow-up evidence"):
        app.evidence_request_action(
            "analyze",
            {
                "target": "172.28.0.10",
                "run_id": "snapshot",
                "provider": "ollama",
                "share_evidence": False,
            },
        )
    if recent:
        assert "supplemental_evidence" not in payload
    assert not app.evidence_requests.audit_path.exists()


def test_planning_keeps_requested_old_run_and_bounds_matching_histories(app):
    with Store(app.database) as store:
        for index in range(11):
            identity = f"synthetic-new-{index:02d}"
            store.start_run(identity, SETTINGS.config_hash())
            store.upsert_host(identity, Host(ip="172.28.0.10", hostname=identity))
    context = app.plan_context("172.28.0.10", "snapshot")
    assert context["history_count"] == context["history_limit"] == 3
    assert any("Prior observation" in item["text"] for item in context["evidence"])
    assert context["probe_options"]


def test_plan_revalidates_scope_after_target_resolution(app, monkeypatch):
    # Configuration can change on disk after DNS/target classification and before planning.
    original = app.target_check

    def classify_then_revoke(target):
        result = original(target)
        path = app.config_dir / "scope.yaml"
        scope = yaml.safe_load(path.read_text())
        scope["allowed_cidrs"].remove("172.28.0.10/32")
        scope["lab_targets"] = [row for row in scope["lab_targets"] if row["ip"] != "172.28.0.10"]
        path.write_text(yaml.safe_dump(scope), encoding="utf-8")
        return result

    monkeypatch.setattr(app, "target_check", classify_then_revoke)
    with pytest.raises(ConfigError, match="Planner target is outside"):
        app.plan_context("172.28.0.10", "snapshot")
    assert not app.scan_plans.audit_path.exists()


@pytest.mark.parametrize(
    "options",
    [
        {"plan_id": "missing"},
        {"plan_hash": "missing"},
        {"plan_id": "missing", "plan_hash": "missing", "reuse_recent": True},
    ],
)
def test_incomplete_or_reused_plan_rejected_before_scan(app, options):
    with pytest.raises(ConfigError, match="both approval fields and a new scan"):
        app.live_report("172.28.0.10", "ollama", lambda *args: None, **options)
    assert app._last_live_scan == {}


def test_blocked_live_target_does_not_enter_cooldown(app):
    with pytest.raises(ConfigError, match="Canary address"):
        app.live_report("172.28.0.250", "ollama", lambda *args: None)
    assert app._last_live_scan == {}


def test_reuse_without_recent_capture_does_not_start_new_scan(app):
    with pytest.raises(ConfigError, match="No recent scan"):
        app.live_report("172.28.0.10", "ollama", lambda *args: None, reuse_recent=True)
    assert app._last_live_scan == {}


def test_self_defence_dispatches_only_literal_loopback(app, monkeypatch):
    def synthetic_dispatch(target, check, config_dir, **options):
        assert target == "127.0.0.1" and check["resolved_ips"] == ["127.0.0.1"]
        assert options["self_defence"] is True
        return {"scan_status": "complete", "target": "self", "ai_status": "not_attempted"}

    monkeypatch.setattr(server.live_assessment, "run", synthetic_dispatch)
    result = app.live_report("self", "ollama", lambda *args: None)
    assert result["target"] == "self" and result["ai_status"] == "not_attempted"
    assert set(app._last_live_scan) == {"127.0.0.1"}


def test_approved_plan_cannot_be_used_for_different_target(app):
    context = app.plan_context("172.28.0.10", "snapshot")
    draft = app.scan_plans.create(baseline(context), context)
    app.scan_plans.approve(draft["plan_id"], draft["plan_hash"])
    with pytest.raises(ConfigError, match="Approved plan target changed"):
        app.live_report(
            "172.28.0.12",
            "ollama",
            lambda *args: None,
            plan_id=draft["plan_id"],
            plan_hash=draft["plan_hash"],
        )
    assert app.scan_plans.claim(draft["plan_id"], draft["plan_hash"], context)
    assert app._last_live_scan == {}


@pytest.mark.parametrize("failure", ["scanner", "endpoint_scan", "nikto", "exception"])
def test_planned_execution_failure_requires_fresh_approval(app, monkeypatch, failure):
    context = app.plan_context("172.28.0.10", "snapshot")
    plan = baseline(context)
    endpoint_id = next(iter(context["endpoints"]))
    observation = next(item for item in context["evidence"] if item["id"] == endpoint_id)
    plan["steps"].append(
        {
            "tool": "nikto",
            "profile": "nikto_web_bounded",
            "timeout_seconds": 60,
            "endpoint_evidence_id": endpoint_id,
            "reason": "Review observed web service",
            "confidence": 0.8,
        }
    )
    claim = copy.deepcopy(plan["claims"][0])
    claim.update(
        path="steps[1].reason",
        evidence_ids=[endpoint_id],
        quotes=[{"evidence_id": endpoint_id, "text": observation["text"]}],
    )
    plan["claims"].append(claim)
    draft = app.scan_plans.create(plan, context)
    app.scan_plans.approve(draft["plan_id"], draft["plan_hash"])
    events = []

    def synthetic_dispatch(target, check, config_dir, **options):
        assert check["endpoint"] == context["endpoints"][endpoint_id]
        execution = options["plan_execution"]
        execution.before("nmap", target, context["scope_hash"])
        execution.before("nikto", target, context["scope_hash"])
        options["on_progress"]("scope", "complete", "SYNTHETIC accepted")
        if failure == "exception":
            raise OSError("SYNTHETIC scanner failure")
        options["on_progress"](failure, "error", "SYNTHETIC unavailable")
        return {"scan_status": "partial"}

    monkeypatch.setattr(server.live_assessment, "run", synthetic_dispatch)

    def run():
        return app.live_report(
            "172.28.0.10",
            "ollama",
            lambda *event: events.append(event),
            plan_id=draft["plan_id"],
            plan_hash=draft["plan_hash"],
        )

    if failure == "exception":
        with pytest.raises(OSError, match="SYNTHETIC scanner failure"):
            run()
    else:
        result = run()
        assert result["scan_plan"]["state"] == "needs_reapproval"
        assert (failure, "error", "SYNTHETIC unavailable") in events
    audit = [json.loads(line) for line in app.scan_plans.audit_path.read_text().splitlines()]
    assert audit[-1]["decision"] == "finish" and audit[-1]["outcome"] == "needs_reapproval"
    with pytest.raises(ConfigError, match="approval"):
        app.scan_plans.claim(draft["plan_id"], draft["plan_hash"], context)


def test_analyst_http_review_failure_is_not_a_success(app, monkeypatch):
    monkeypatch.setattr(
        server.analyst,
        "analyze_target",
        Mock(side_effect=NeedsReview("SYNTHETIC unsupported claim")),
    )
    response = app.get("/api/analyst/snapshot/172.28.0.10")
    assert response.status == 422
    assert json.loads(response.body)["error"]["message"] == "SYNTHETIC unsupported claim"


def post_handler(app, route, action, raw=b"{}", **headers):
    incoming = handler(app)
    incoming.path = route
    incoming.headers = {
        "Origin": "http://127.0.0.1:9999",
        "X-VulnAssess-Action": action,
        "Content-Type": "application/json",
        "Content-Length": str(len(raw)),
        **headers,
    }
    incoming.rfile = io.BytesIO(raw)
    return incoming


@pytest.mark.parametrize(
    "route,action",
    [
        ("/api/device-recheck", "device-recheck"),
        ("/api/analyst/snapshot/172.28.0.10", "cloud-analyst"),
    ],
)
def test_invalid_content_type_refuses_request_before_execution(app, route, action):
    incoming = post_handler(app, route, action, **{"Content-Type": "text/plain"})
    incoming.do_POST()
    assert incoming._reply.call_args.args[0].status == 400
    assert incoming.rfile.tell() == 0


def test_busy_device_recheck_returns_conflict_without_probing(app, monkeypatch):
    collector = Mock(side_effect=AssertionError("device probe forbidden"))
    monkeypatch.setattr(self_defence, "collect", collector)
    incoming = post_handler(app, "/api/device-recheck", "device-recheck", b'{"check":"SMB1"}')
    with app._live_lock:
        incoming.do_POST()
        assert app._live_lock.locked()
    assert incoming._reply.call_args.args[0].status == 409
    collector.assert_not_called()
    assert not (app.config_dir.parent / "data/device-rechecks").exists()


@pytest.mark.parametrize(
    "content_type,body", [("text/plain", b"<xml/>"), ("application/xml", b"<broken")]
)
def test_nessus_request_errors_do_not_import_partial_findings(app, content_type, body):
    with reader.ReadOnlyStore(app.database) as store:
        before = store.run("snapshot")
    incoming = post_handler(
        app,
        "/api/nessus-import",
        "nessus-import",
        body,
        **{
            "Content-Type": content_type,
            "X-VulnAssess-Run": "snapshot",
            "X-VulnAssess-Target": "172.28.0.10",
        },
    )
    incoming.do_POST()
    assert incoming._reply.call_args.args[0].status == 400
    with reader.ReadOnlyStore(app.database) as store:
        assert store.run("snapshot") == before


def test_malformed_http_version_gets_json_error_without_dispatch(app):
    connection = MemoryConnection(b"GET / HTTP/not-a-version\r\nHost: 127.0.0.1:8765\r\n\r\n")
    server.UiRequestHandler(connection, ("127.0.0.1", 1), SimpleNamespace(application=app))
    # Invalid versions are answered using HTTP/0.9 body semantics by the standard parser.
    body = bytes(connection.output)
    assert b"Invalid UI request" not in body
    assert json.loads(body)["error"]["message"].startswith("Bad request version")


def test_loopback_bind_records_os_assigned_port_without_dns(monkeypatch):
    listener = object.__new__(server.UiServer)
    listener.server_address = ("127.0.0.1", 0)
    listener.socket = Mock()
    listener.socket.getsockname.return_value = ("127.0.0.1", 43210)
    listener.server_bind()
    assert listener.server_address == ("127.0.0.1", 43210)
    assert listener.server_name == "127.0.0.1" and listener.server_port == 43210
    listener.socket.bind.assert_called_once_with(("127.0.0.1", 0))


def test_resolved_network_path_is_refused_before_file_access(monkeypatch):
    monkeypatch.setattr(Path, "resolve", lambda _: Path("//synthetic.invalid/share/store.db"))
    with pytest.raises(ConfigError, match="not a network share"):
        reader.local_path("synthetic-link.db")


def test_failed_sqlite_snapshot_closes_connection(app, monkeypatch):
    connect = sqlite3.connect
    connection = connect(app.database)
    connection.set_authorizer(
        lambda action, *_: (
            sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION else sqlite3.SQLITE_OK
        )
    )
    monkeypatch.setattr(sqlite3, "connect", lambda *args, **kwargs: connection)
    with pytest.raises(ConfigError, match="cannot begin read-only snapshot"):
        reader.ReadOnlyStore(app.database)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("select 1")


def test_inconsistent_stored_score_is_refused_instead_of_displayed(app):
    with sqlite3.connect(app.database) as connection:
        connection.execute("update scores set risk = risk + 1 where run_id = 'snapshot'")
    with reader.ReadOnlyStore(app.database) as store:
        with pytest.raises(ConfigError, match="inconsistent stored score"):
            store.run("snapshot")
    response = app.get("/api/run/snapshot")
    assert response.status == 409
    assert "inconsistent stored score" in json.loads(response.body)["error"]["message"]
