"""Planning HTTP contracts run through the in-memory UI harness, never a socket."""

import json
import shutil
import subprocess
import time
from unittest.mock import patch

import pytest

from tests.test_ui import DATABASE, ROOT, request
from vulnassess import scan_plans
from vulnassess.errors import ConfigError
from vulnassess.ui.server import UiApplication


@pytest.fixture
def application(tmp_path):
    app = UiApplication(DATABASE, ROOT / "config", "demo")
    app.scan_plans = scan_plans.PlanRegistry(tmp_path / "audit.jsonl")
    return app


def post(app, action, body, *, trusted=True):
    wire = json.dumps(body).encode()
    headers = f"Content-Type: application/json\r\nContent-Length: {len(wire)}\r\n"
    if trusted:
        headers += "Origin: http://127.0.0.1:8765\r\nX-VulnAssess-Action: scan-plan\r\n"
    return request(app, "/api/scan-plans/" + action, "POST", extra_headers=headers, body=wire)


def baseline(context, *args):
    evidence = context["evidence"][0]
    return {
        "schema_version": "scan_plan.v1",
        "target_ip": context["target_ip"],
        "steps": [
            {
                "tool": "nmap",
                "profile": "nmap_light",
                "timeout_seconds": 180,
                "endpoint_evidence_id": None,
                "reason": "Refresh observed services",
                "confidence": 0.8,
            }
        ],
        "claims": [
            {
                "path": "steps[0].reason",
                "label": "inferred",
                "evidence_ids": [evidence["id"]],
                "quotes": [{"evidence_id": evidence["id"], "text": evidence["text"]}],
                "finding_ids": [],
                "confidence": 0.8,
                "verification_action": None,
                "score": None,
            }
        ],
    }


def accepted_check(*args):
    return {
        "target": "172.28.0.12",
        "submitted": "172.28.0.12",
        "resolved_ips": ["172.28.0.12"],
        "status": "ready",
        "missing": [],
        "endpoint": None,
    }


def test_propose_edit_and_approve_have_no_scanner_side_effect(application):
    with (
        patch.object(application, "target_check", side_effect=accepted_check),
        patch("vulnassess.scan_plans.propose", side_effect=baseline),
        patch("vulnassess.analyst.provider_client"),
        patch("subprocess.run", side_effect=AssertionError("scanner forbidden")),
    ):
        status, _, wire = post(
            application,
            "propose",
            {
                "target": "172.28.0.12",
                "run_id": "demo",
                "hints": "",
                "provider": "ollama",
                "share_evidence": False,
            },
        )
        assert status == 200
        draft = json.loads(wire)
        assert draft["state"] == "draft"
        plan = draft["plan"]
        plan["steps"][0]["timeout_seconds"] = 90
        status, _, wire = post(
            application,
            "edit",
            {"plan_id": draft["plan_id"], "plan_hash": draft["plan_hash"], "plan": plan},
        )
        assert status == 200
        edited = json.loads(wire)
        assert edited["plan_hash"] != draft["plan_hash"]
        status, _, wire = post(
            application, "approve", {"plan_id": edited["plan_id"], "plan_hash": edited["plan_hash"]}
        )
        assert status == 200 and json.loads(wire)["state"] == "approved"


@pytest.mark.parametrize("body", [None, {}, {"target": "172.28.0.12", "approved": True}])
def test_invalid_plan_http_requests_are_rejected_without_generation(application, body):
    with patch("vulnassess.scan_plans.propose") as model:
        status, _, _ = post(application, "propose", body)
        assert status == 400 and not model.called


def test_plan_posts_require_explicit_same_origin_action(application):
    status, _, _ = post(
        application, "approve", {"plan_id": "invented", "plan_hash": "invented"}, trusted=False
    )
    assert status == 403


def test_get_plan_route_never_generates_or_launches(application):
    with patch("vulnassess.scan_plans.propose") as model:
        status, _, _ = request(application, "/api/scan-plans/propose")
        assert status == 404 and not model.called


def test_blocked_target_does_not_reach_model(application):
    with (
        patch.object(
            application,
            "target_check",
            return_value={"status": "blocked", "reason": "outside scope"},
        ),
        patch("vulnassess.analyst.provider_client") as model,
    ):
        status, _, _ = post(
            application,
            "propose",
            {
                "target": "172.28.0.250",
                "run_id": "demo",
                "hints": "",
                "provider": "ollama",
                "share_evidence": False,
            },
        )
        assert status == 400 and not model.called


def test_planned_run_refuses_unapproved_hash_before_scanner(application):
    with patch.object(application, "target_check", side_effect=accepted_check):
        context = application.plan_context("172.28.0.12", "demo")
        draft = application.scan_plans.create(baseline(context), context)
        with (
            patch("vulnassess.live_assessment.run") as scanner,
            pytest.raises(ConfigError, match="approval"),
        ):
            application.live_report(
                "172.28.0.12",
                "ollama",
                lambda *args: None,
                plan_id=draft["plan_id"],
                plan_hash=draft["plan_hash"],
            )
        assert not scanner.called
        assert application._last_live_scan == {}


def test_planned_run_consumes_approval_and_uses_exact_pinned_tool(application):
    with patch.object(application, "target_check", side_effect=accepted_check):
        context = application.plan_context("172.28.0.12", "demo")
        draft = application.scan_plans.create(baseline(context), context)
        application.scan_plans.approve(draft["plan_id"], draft["plan_hash"])

        def scanner(target, check, config_dir, **options):
            assert target == "172.28.0.12" and check["resolved_ips"] == ["172.28.0.12"]
            assert (
                options["plan_execution"].before("nmap", "172.28.0.12", context["scope_hash"])
                == 180
            )
            return {"scan_status": "complete", "ai_status": "unavailable"}

        with patch("vulnassess.live_assessment.run", side_effect=scanner):
            result = application.live_report(
                "172.28.0.12",
                "ollama",
                lambda *args: None,
                plan_id=draft["plan_id"],
                plan_hash=draft["plan_hash"],
            )
        assert result["scan_plan"]["state"] == "completed" and result["ai_status"] == "unavailable"
        with pytest.raises(ConfigError, match="approval"):
            application.scan_plans.claim(draft["plan_id"], draft["plan_hash"], context)


def test_concurrent_scan_does_not_consume_approved_plan(application):
    with patch.object(application, "target_check", side_effect=accepted_check):
        context = application.plan_context("172.28.0.12", "demo")
        draft = application.scan_plans.create(baseline(context), context)
        application.scan_plans.approve(draft["plan_id"], draft["plan_hash"])
        application._last_live_scan["172.28.0.12"] = time.monotonic()
        with (
            patch("vulnassess.live_assessment.run") as scanner,
            pytest.raises(ConfigError, match="already running"),
        ):
            application.live_report(
                "172.28.0.12",
                "ollama",
                lambda *args: None,
                plan_id=draft["plan_id"],
                plan_hash=draft["plan_hash"],
            )
        assert not scanner.called
        assert application.scan_plans.claim(draft["plan_id"], draft["plan_hash"], context)


def test_prior_web_observations_become_cited_endpoints_not_guesses(application):
    # Synthetic canonical records exercise selection, not scanners or real evidence.
    payload = {
        "run": {"started_at": "2026-10-01T00:00:00Z"},
        "hosts": [
            {
                "ip": "127.0.0.1",
                "services": [
                    {"port": 443, "protocol": "tcp", "name": "https", "tls": True},
                    {"port": 22, "protocol": "tcp", "name": "ssh"},
                ],
                "features": [{"key": "role", "value": "web_frontend"}],
            }
        ],
    }
    application._recent_live_cases["127.0.0.1"] = (time.monotonic(), {"payload": payload})
    check = {"status": "ready", "resolved_ips": ["127.0.0.1"], "endpoint": None}
    with patch.object(application, "target_check", return_value=check):
        context = application.plan_context("127.0.0.1", "demo", "Verify HTTPS")
    assert context["endpoints"] == {
        "E2": {"host": "127.0.0.1", "scheme": "https", "port": 443, "path": "/"}
    }
    assert "2026-10-01" in context["evidence"][1]["text"]
    assert "not an observation" in context["evidence"][-1]["text"]
    assert context["history_count"] == 1
    application._recent_live_cases.clear()
    with patch.object(application, "target_check", return_value=check):
        context = application.plan_context("127.0.0.1", "demo", "Scan my web portal")
    assert context["endpoints"] == {}  # A hint is not an observed service.


def test_plan_client_validates_server_binding_and_edits_without_fabricating_fields():
    node = shutil.which("node")
    assert node, "MISSING: node for plan client checks"
    source_path = ROOT / "vulnassess/ui/static/scan-plan-client.js"
    assert source_path.is_file(), "MISSING: scan plan review client"
    script = """
import assert from 'node:assert/strict';
let source = ''; for await (const chunk of process.stdin) source += chunk;
const client = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const record = {plan_id:'a'.repeat(32), plan_hash:'b'.repeat(64), state:'draft', evidence:[{id:'E1',text:'baseline'}],
 plan:{schema_version:'scan_plan.v1',target_ip:'172.28.0.12',steps:[{tool:'nmap',profile:'nmap_light',timeout_seconds:180,reason:'refresh',confidence:.8,endpoint_evidence_id:null}],claims:[]}};
assert.equal(client.validatePlanRecord(record).state, 'draft');
assert.throws(() => client.validatePlanRecord({...record,plan_hash:'fake'}));
assert.throws(() => client.validatePlanRecord({...record,state:'invented'}));
const edited = client.editedPlan(record, [90], false);
assert.equal(edited.steps[0].timeout_seconds,90);
assert.equal(record.plan.steps[0].timeout_seconds,180);
assert.throws(() => client.editedPlan(record, [0], false));
assert.throws(() => client.editedPlan(record, [NaN], false));
console.log('Plan client binding/edit checks passed');
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=source_path.read_text(encoding="utf-8"),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "binding/edit checks passed" in result.stdout
