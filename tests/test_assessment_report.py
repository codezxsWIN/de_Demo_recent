"""Reports are derived from immutable receipts, never browser claims or fresh probes."""

import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from tests.test_capture_history import capture
from vulnassess import capture_history, live_assessment
from vulnassess.ai_boundary import INJECTION_SENTINEL, SCHEMA_VERSION
from vulnassess.store import Store
from vulnassess.ui import assessment_report, capture_review
from vulnassess.ui.server import UiApplication


def setup_report(tmp_path, *, device=False, ai=True):
    config = tmp_path / "config"
    shutil.copytree(Path(__file__).resolve().parents[1] / "config", config)
    database = tmp_path / "synthetic.db"
    with Store(database):
        pass
    root = tmp_path / "data/live/raw"
    root.mkdir(parents=True)
    directory, result = capture(root)
    payload = json.loads((directory / "case.json").read_text())
    payload["scanner_coverage"] = {"nmap": "SYNTHETIC loopback only", "nessus": "Not imported"}
    result["assessment_summary"]["coverage_gaps"] = ["SYNTHETIC bounded check only"]
    if device:
        payload["self_defence"] = {
            "checked_at": "2026-10-20T10:00:00+00:00",
            "boundary": "SYNTHETIC: computer running VulnAssess, not the remote browser.",
            "active_profiles": ["Public"],
            "antivirus_providers": [],
            "last_recorded_update": "unknown",
            "listeners": [
                {"port": 8765, "application": "SYNTHETIC app", "binding": "this device only"}
            ],
            "checks": [
                {
                    "id": "Public",
                    "title": "Public firewall",
                    "state": "unknown",
                    "attention": "verify",
                    "observation": "SYNTHETIC firewall not established",
                    "precaution": "Review Windows Security; do not disable protection.",
                }
            ],
            "action_queue": [
                {
                    "title": "Review your firewall",
                    "kind": "verification",
                    "reason": "SYNTHETIC status unknown",
                    "action": "Read the active profile",
                    "basis": ["Public"],
                }
            ],
            "limitations": "SYNTHETIC malware was not checked.",
        }
    if ai:
        claim = {
            "path": "summary",
            "label": "observed",
            "confidence": 0.8,
            "finding_ids": [],
            "evidence_ids": ["E1"],
            "quotes": [{"evidence_id": "E1", "text": "SYNTHETIC loopback"}],
            "verification_action": None,
            "score": None,
        }
        result.update(
            ai_status="validated",
            analyst={
                "model": "SYNTHETIC model, not called",
                "evidence": [{"id": "E1", "text": "SYNTHETIC loopback evidence"}],
                "analysis": {
                    "schema_version": SCHEMA_VERSION,
                    "summary": "SYNTHETIC observed loopback service.",
                    "context_effect": {"explanation": "SYNTHETIC reachability remains unverified."},
                    "recommended_actions": [],
                    "correlations": [],
                    "investigations": [],
                    "uncertainties": [],
                    "claims": [
                        claim,
                        {
                            **copy.deepcopy(claim),
                            "path": "context_effect.explanation",
                            "label": "inferred",
                        },
                    ],
                },
            },
        )
    raw = json.dumps(payload).encode()
    (directory / "case.json").write_bytes(raw)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"]["case.json"] = hashlib.sha256(raw).hexdigest()
    (directory / "manifest.json").write_text(json.dumps(manifest))
    capture_history.save(directory, result, config_hash="SYNTHETIC config")
    return UiApplication(database, config), directory


def test_validated_essentials_precede_detail_and_keep_audit_expandable(tmp_path):
    app, directory = setup_report(tmp_path)
    document = app.get(f"/captures/{directory.name}/report").body.decode()
    assert 'aria-label="Assessment essentials"' in document
    assert "READ THIS FIRST" in document
    assert "WHY IT MATTERS" in document
    assert "DO NEXT" in document
    assert "STILL UNKNOWN" in document
    assert document.index("assessment-highlights") < document.index('id="brief"')
    assert document.index("assessment-highlights") < document.index('id="ai-details"')
    assert '<details id="ai-details" class="report-audit">' in document
    assert '<details id="ai-details" class="report-audit" open' not in document
    assert "SYNTHETIC observed loopback service." in document
    assert "not a safety certificate" in document


def test_decisions_are_visible_without_ai_and_premises_are_traceable(tmp_path):
    app, directory = setup_report(tmp_path, ai=False)
    original = {p.name: p.read_bytes() for p in directory.iterdir()}
    document = app.get(f"/captures/{directory.name}/report").body.decode()
    assert 'id="decisions"' in document
    assert "What we can conclude" in document
    assert "not a secure verdict" in document
    assert "Supporting observations" in document
    assert "Expected outcome" in document
    assert "If the check fails" in document
    assert "What would change this conclusion?" in document
    assert "no validated AI focus selection retained" in document
    assert "AI next-verification focus" not in document
    assert original == {p.name: p.read_bytes() for p in directory.iterdir()}


def test_valid_optional_focus_is_shown_but_tampered_focus_cannot_hide_report(tmp_path):
    from vulnassess.ai_boundary import digest
    from vulnassess.assessment_derivations import derive
    from vulnassess.decision_focus import VERSION, save_saved

    app, directory = setup_report(tmp_path, ai=False)
    record = capture_history.load(directory.parent, directory.name)
    cards = derive(record)
    card, action = cards[0], cards[0]["actions"][0]
    focus = {
        "schema_version": VERSION,
        "source_snapshot_hash": record["snapshot_hash"],
        "input_hash": digest(cards),
        "model": "synthetic-focus",
        "plan": {
            "next_decisions": [
                {
                    "derivation_id": card["id"],
                    "action_id": action["id"],
                    "premise_ids": action["premise_ids"],
                }
            ]
        },
    }
    focus["document_hash"] = digest(focus)
    save_saved(directory, record, focus)
    for suffix in ("report", "report/download"):
        response = app.get(f"/captures/{directory.name}/{suffix}")
        assert response.status == 200
        assert b"AI next-verification focus 1" in response.body
        assert b"did not author the underlying evidence" in response.body
    (directory / "decision-focus.json").write_text('{"model":"forged"}')
    response = app.get(f"/captures/{directory.name}/report")
    assert response.status == 200
    assert b"AI focus could not be verified" in response.body
    assert b"What we can conclude" in response.body
    assert b"AI next-verification focus 1" not in response.body


def test_report_reopens_without_scanner_model_or_authority(tmp_path, monkeypatch):
    app, directory = setup_report(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("Report read may not launch scanner or model")

    monkeypatch.setattr(live_assessment.subprocess, "run", forbidden)
    monkeypatch.setattr(live_assessment.analyst, "analyze_optional", forbidden)
    original = {path.name: path.read_bytes() for path in directory.iterdir()}
    response = app.get(f"/captures/{directory.name}/report")
    assert response.status == 200
    assert response.content_type == "text/html; charset=utf-8"
    document = response.body.decode()
    assert "SYNTHETIC observed loopback service." in document
    assert "observed · model confidence 0.8 · batch 1 · citations: E1" in document
    assert "SYNTHETIC loopback</blockquote>" in document
    assert "not a measured probability" in document
    retained = capture_history.load(directory.parent, directory.name)
    assert f"Captured at</dt><dd>{retained['captured_at']}" in document
    assert "No vulnerability findings were recorded" in document
    assert original == {path.name: path.read_bytes() for path in directory.iterdir()}
    assert app.scan_plans._plans == {}
    assert app.evidence_requests._records == {}
    assert b"Open readable assessment report" in app.get(f"/captures/{directory.name}").body


def test_device_report_is_readable_not_a_json_disclosure(tmp_path):
    app, directory = setup_report(tmp_path, device=True, ai=False)
    document = app.get(f"/captures/{directory.name}/report").body.decode()
    for value in (
        "Your device security report",
        "What to do first",
        "Review your firewall",
        "SYNTHETIC firewall not established",
        "Review Windows Security",
        "SYNTHETIC app",
        "TCP/8765",
        "computer running VulnAssess",
        "malware was not checked",
        "Evidence-only report",
    ):
        assert value in document
    assert "<pre>" not in document
    assert "AI explanation and verification plan" in document
    assert "not proof of internet reachability" in document


def test_web_report_turns_scanner_observations_into_bounded_verification_plan(tmp_path):
    _, directory = setup_report(tmp_path, ai=False)
    record = capture_history.load(directory.parent, directory.name)
    record["result"]["scan_status"] = "complete"
    record["payload"]["findings"] = [
        {
            "id": "synthetic-header",
            "tool": "nikto",
            "host_ip": "127.0.0.1",
            "port": 4280,
            "protocol": "tcp",
            "cve_ids": [],
            "title": "Suggested security header missing: content-security-policy.",
            "evidence": "SYNTHETIC header observation",
            "provenance": {},
        },
        {
            "id": "synthetic-method",
            "tool": "nikto",
            "host_ip": "127.0.0.1",
            "port": 4280,
            "protocol": "tcp",
            "cve_ids": [],
            "title": "Web Server returns a valid response with junk HTTP methods which may cause false positives.",
            "evidence": "SYNTHETIC method observation",
            "provenance": {},
        },
    ]
    document = assessment_report.render(record)
    assert 'href="#practical"' in document
    assert "Scanner observations</span>" in document
    assert "Response-header hardening · 1" in document
    assert "HTTP method behavior · 1" in document
    assert "starting with report-only" in document
    assert "scanner itself warns this may be a false positive" in document
    assert "No scanner-named CVE was retained" in document
    assert 'href="#finding-1"' in document
    assert "not confirmed exploitation" in document


@pytest.mark.parametrize("filename", ["case.json", "manifest.json", "review-evidence.json"])
@pytest.mark.parametrize("suffix", ["report", "report/download"])
def test_report_refuses_tampered_or_legacy_receipts(tmp_path, filename, suffix):
    app, directory = setup_report(tmp_path)
    (directory / filename).write_text("{}")
    response = app.get(f"/captures/{directory.name}/{suffix}")
    assert response.status == 409
    assert b"SYNTHETIC observed loopback service" not in response.body


def test_legacy_report_does_not_promote_unverified_history(tmp_path):
    app, directory = setup_report(tmp_path)
    (directory / "review-evidence.json").unlink()
    assert app.get(f"/captures/{directory.name}").status == 200
    assert app.get(f"/captures/{directory.name}/report").status == 409


@pytest.mark.parametrize(
    "mutation",
    [
        "quote",
        "id",
        "score",
        "schema",
        "metadata",
        "missing-action-claim",
        "hypothesis",
        "sentinel",
        "duplicate-evidence",
    ],
)
def test_invalid_ai_cannot_leak_partial_prose_into_report(tmp_path, mutation):
    _, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    analyst = record["result"]["analyst"]
    analysis = analyst["analysis"]
    claim = analysis["claims"][0]
    if mutation == "quote":
        claim["quotes"][0]["text"] = "Fabricated quote"
    elif mutation == "id":
        claim["finding_ids"] = ["invented-finding"]
    elif mutation == "score":
        claim["score"] = 100
    elif mutation == "schema":
        analysis["schema_version"] = "unknown"
    elif mutation == "metadata":
        analysis["claims"] = []
    elif mutation == "missing-action-claim":
        analysis["recommended_actions"] = [
            {"action": "HIDDEN UNSUPPORTED action", "reason": "HIDDEN UNSUPPORTED reason"}
        ]
    elif mutation == "hypothesis":
        claim["label"] = "hypothesis"
    elif mutation == "duplicate-evidence":
        analyst["evidence"].append({"id": "E1", "text": "Duplicated"})
    else:
        analysis["summary"] = INJECTION_SENTINEL
    document = assessment_report.render(record)
    assert "Needs review: retained AI claim metadata" in document
    assert "SYNTHETIC observed loopback service." not in document
    assert "HIDDEN UNSUPPORTED" not in document
    assert 'aria-label="Assessment essentials"' not in document
    assert "No vulnerability findings were recorded" in document


def test_batches_keep_same_evidence_id_separate_and_fail_all_if_one_invalid(tmp_path):
    _, directory = setup_report(tmp_path)
    record = capture_history.load(directory.parent, directory.name)
    analyst = record["result"]["analyst"]
    second = copy.deepcopy(analyst)
    second["evidence"][0]["text"] = "SYNTHETIC second batch"
    for claim in second["analysis"]["claims"]:
        claim["quotes"][0]["text"] = "SYNTHETIC second batch"
    analyst["batches"] = [copy.deepcopy(analyst), second]
    document = assessment_report.render(record)
    assert "Batch 1 · E1" in document and "Batch 2 · E1" in document
    second["analysis"]["claims"][0]["quotes"][0]["text"] = "fabricated"
    document = assessment_report.render(record)
    assert "SYNTHETIC observed loopback service." not in document
    assert "Needs review" in document


def test_download_is_self_contained_and_inert(tmp_path):
    app, directory = setup_report(tmp_path)
    response = app.get(f"/captures/{directory.name}/report/download")
    assert response.status == 200
    assert response.content_type == "application/octet-stream"
    document = response.body.decode()
    assert 'http-equiv="Content-Security-Policy"' in document
    css = document.split("<style>", 1)[1].split("</style>", 1)[0]
    import base64

    integrity = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
    assert "sha256-" + integrity in document
    assert "@media print" in css and "break-inside: avoid" in css
    assert "<script" not in document and "<link" not in document
    assert "src=" not in document and 'href="/' not in document
    assert 'href="#ai"' in document
    assert "default-src &#x27;none&#x27;" in document


def test_hostile_text_is_literal_and_unknown_ai_never_displayed(tmp_path):
    _, directory = setup_report(tmp_path, device=True)
    record = capture_history.load(directory.parent, directory.name)
    hostile = '<script>window.BAD=1</script><img src="https://bad.invalid/track">'
    record["result"]["target"] = hostile
    record["payload"]["self_defence"]["checks"][0]["precaution"] = hostile
    record["result"]["analyst"]["analysis"]["summary"] = hostile
    document = assessment_report.render(record, standalone=True)
    assert "<script>" not in document and '<img src="https://' not in document
    assert "&lt;script&gt;" in document
    record["result"]["ai_status"] = "needs_review"
    document = assessment_report.render(record)
    assert "SYNTHETIC reachability remains unverified." not in document
    assert "Evidence-only report" in document


@pytest.mark.parametrize(
    "route",
    [
        "/api/captures/assessment-synthetic/report",
        "/captures/assessment-synthetic/report?score=100",
        "/captures/assessment-synthetic/report/other",
    ],
)
def test_report_endpoint_accepts_only_saved_identity(tmp_path, route):
    app, _ = setup_report(tmp_path)
    assert app.get(route).status == 400


def test_ui_exposes_reports_in_both_summary_and_self_defence():
    static = Path(assessment_report.__file__).with_name("static")
    for name in ("workflow.js", "self-defence.js"):
        script = (static / name).read_text(encoding="utf-8")
        assert "encodeURIComponent(summary.saved_capture_id)}/report" in script
    assert "Open readable assessment report" in capture_review.review(
        {
            "result": {"assessment_summary": {}},
            "payload": {},
            "capture_id": "assessment-synthetic",
            "captured_at": None,
            "intelligence_recorded_at": None,
            "analysis_attempted_at": None,
            "configuration_hash": "",
            "evidence_hash": "",
            "intelligence_hash": "",
            "snapshot_hash": "",
        }
    )
