"""Offline HTTP and analyst integration for the bounded follow-up loop."""

import copy
import json
import shutil
import subprocess
from unittest.mock import patch

import pytest

from tests.adversarial.test_evidence_requests import context, proposal
from tests.test_analyst import demo_payload
from tests.test_ui import DATABASE, ROOT, request
from vulnassess import analyst, evidence_requests
from vulnassess.errors import LLMUnavailable
from vulnassess.ui.server import UiApplication


@pytest.fixture
def app(tmp_path):
    value = UiApplication(DATABASE, ROOT / "config", "demo")
    value.evidence_requests = evidence_requests.EvidenceRequests(tmp_path)
    return value


def post(app, action, body, trusted=True):
    raw = json.dumps(body).encode()
    headers = f"Content-Type: application/json\r\nContent-Length: {len(raw)}\r\n"
    if trusted:
        headers += "Origin: http://127.0.0.1:8765\r\nX-VulnAssess-Action: evidence-request\r\n"
    status, _, response = request(
        app, f"/api/evidence-requests/{action}", "POST", extra_headers=headers, body=raw
    )
    return status, json.loads(response)


def test_http_proposal_approval_and_reanalysis_use_saved_evidence(app):
    body = {
        "target": "172.28.0.10",
        "run_id": "demo",
        "provider": "ollama",
        "share_evidence": False,
    }
    with (
        patch.object(app, "plan_context", return_value=context()),
        patch("vulnassess.evidence_requests.propose", return_value=proposal()),
        patch("vulnassess.analyst.provider_client"),
    ):
        status, record = post(app, "propose", body)
    assert status == 200
    binding = {key: record[key] for key in ("request_id", "request_hash")}
    with patch(
        "vulnassess.evidence_requests.probe",
        return_value={"raw_hex": "", "observation": "HTTP/1.0 200 OK"},
    ) as transport:
        status, completed = post(app, "approve", binding)
        assert status == 200 and completed["state"] == "complete"
        assert post(app, "approve", binding)[0] == 422
    transport.assert_called_once()
    with (
        patch.object(app, "plan_context", return_value=context()),
        patch(
            "vulnassess.analyst.analyze_target", return_value={"analysis": {"summary": "validated"}}
        ) as analyze,
    ):
        assert post(app, "analyze", body)[0] == 200
    payload = analyze.call_args.args[0]
    assert payload["supplemental_evidence"][0]["origin"] == "ai_request"
    assert payload["supplemental_evidence"][0]["target_ip"] == "172.28.0.10"


def test_http_rejection_and_origin_fence(app):
    record = app.evidence_requests.create(proposal(), context())
    body = {key: record[key] for key in ("request_id", "request_hash")}
    assert post(app, "approve", body, trusted=False)[0] == 403
    assert post(app, "reject", body | {"reason": "Not during business hours"})[0] == 200
    with patch("vulnassess.evidence_requests.probe") as transport:
        assert post(app, "approve", body)[0] == 422
    transport.assert_not_called()


def test_model_outage_returns_json_without_losing_follow_up_evidence(app):
    record = app.evidence_requests.create(proposal(), context())
    binding = {key: record[key] for key in ("request_id", "request_hash")}
    with patch(
        "vulnassess.evidence_requests.probe",
        return_value={"raw_hex": "", "observation": "connected"},
    ):
        assert post(app, "approve", binding)[0] == 200
    body = {
        "target": "172.28.0.10",
        "run_id": "demo",
        "provider": "ollama",
        "share_evidence": False,
    }
    with (
        patch.object(app, "plan_context", return_value=context()),
        patch("vulnassess.analyst.analyze_target", side_effect=LLMUnavailable("Model unavailable")),
    ):
        status, result = post(app, "analyze", body)
    assert status == 503 and "Model unavailable" in result["error"]["message"]
    assert len(app.evidence_requests.evidence("demo", "172.28.0.10")) == 1


@pytest.mark.parametrize(
    "body",
    [
        [],
        {},
        {"target": "172.28.0.10", "run_id": "demo", "provider": "google", "share_evidence": False},
    ],
)
def test_invalid_http_proposals_never_call_model(app, body):
    with patch("vulnassess.analyst.provider_client") as provider:
        assert post(app, "propose", body)[0] == 400
    provider.assert_not_called()


def test_scope_fence_rejects_unlisted_target_before_transport(app):
    source = context() | {"target_ip": "8.8.8.8"}
    record = app.evidence_requests.create(proposal() | {"target_ip": "8.8.8.8"}, source)
    with patch("vulnassess.evidence_requests.probe") as transport:
        assert (
            post(app, "approve", {key: record[key] for key in ("request_id", "request_hash")})[0]
            == 400
        )
    transport.assert_not_called()


def test_supplementary_observations_are_cited_without_mutating_scores():
    payload = demo_payload()
    original = copy.deepcopy(payload)
    payload["supplemental_evidence"] = [
        {
            "target_ip": "172.28.0.12",
            "origin": "ai_request",
            "id": "capture-id",
            "observation": "HTTP/1.1 401 Unauthorized",
            "kind": "http_head",
            "port": 80,
            "captured_at": "2026-10-02T00:00:00Z",
            "raw_sha256": "0" * 64,
        }
    ]
    case, evidence, _ = analyst.build_case(payload, "172.28.0.12")
    supplemental = case["supplemental_observations"][0]
    assert any(
        item["id"] == supplemental["evidence_id"] and item["text"] == "HTTP/1.1 401 Unauthorized"
        for item in evidence
    )
    assert payload["scores"] == original["scores"]
    assert payload["context"] == original["context"]
    assert payload["findings"] == original["findings"]
    assert "Point-in-time" in supplemental["limitation"]


def test_browser_client_blocks_repeat_execution_and_ignores_stale_results():
    node = shutil.which("node")
    assert node, "MISSING: node for evidence client checks"
    script = r"""
import assert from 'node:assert/strict';
let source = ''; for await (const chunk of process.stdin) source += chunk;
const {mountEvidenceRequests} = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
class Element {
  constructor() { this.handlers = {}; this.children = []; this.value = ''; this.textContent = ''; }
  addEventListener(name, callback) { this.handlers[name] = callback; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; }
}
const elements = new Map();
const el = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
globalThis.document = {getElementById:el, createElement:() => new Element()};
let target = '172.28.0.10', resolveRequest;
globalThis.fetch = async () => new Promise(resolve => {resolveRequest = resolve;});
mountEvidenceRequests({getTarget:()=>target,getRunId:()=>'demo',getProvider:()=>'ollama',canShare:()=>false});
const record = {request_id:'id',request_hash:'hash',state:'proposed',request:{kind:'http_head',target_ip:target,port:80,timeout_seconds:3,reason:'inspect',expected_information_gain:'headers',claims:[]}};
let pending = el('propose-evidence-request').handlers.click();
target = '172.28.0.11'; el('new-target').handlers.input();
resolveRequest({ok:true,json:async()=>record}); await pending;
assert.equal(el('approve-evidence-request').disabled,true);
assert.equal(el('evidence-request-review').hidden,true);
pending = el('propose-evidence-request').handlers.click();
resolveRequest({ok:true,json:async()=>record}); await pending;
assert.equal(el('approve-evidence-request').disabled,false);
pending = el('approve-evidence-request').handlers.click();
resolveRequest({ok:false,json:async()=>({error:{message:'Needs review: timeout'}})}); await pending;
assert.equal(el('approve-evidence-request').disabled,true);
assert.equal(el('analyze-follow-up').disabled,true);
assert.match(el('evidence-request-status').textContent,/timeout/);
console.log('Evidence client stale response and one-use UI checks passed');
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=(ROOT / "vulnassess/ui/static/evidence-request-client.js").read_text(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
