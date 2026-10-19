"""A retained baseline is useful, but cannot certify failed requested coverage."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_capture_history import capture
from vulnassess import capture_history, live_assessment
from vulnassess.errors import AdapterError, ConfigError
from vulnassess.schema import Host, Service
from vulnassess.ui import capture_review

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "failure",
    ["endpoint-exit", "endpoint-timeout", "endpoint-parse", "nikto-exit", "nikto-missing", "redis"],
)
@pytest.mark.parametrize("ai_status", ["unavailable", "needs_review"])
def test_partial_scan_is_not_upgraded_by_reporting_or_checkpoints(
    tmp_path, monkeypatch, failure, ai_status
):
    config = tmp_path / "config"
    shutil.copytree(ROOT / "config", config)
    calls = []
    events, captures, cases = [], [], []
    baseline = Host("127.0.0.1", services=(Service(80, "tcp", name="http"),))
    endpoint = Host(
        baseline.ip,
        services=(Service(7001, "tcp", name="redis" if failure == "redis" else "http"),),
    )

    def process(argv, **kwargs):
        calls.append(argv)
        requested = "-p" in argv
        web = "-output" in argv
        if requested and failure == "endpoint-timeout":
            raise subprocess.TimeoutExpired("synthetic-nmap", 90)
        if (requested and failure == "endpoint-exit") or (web and failure == "nikto-exit"):
            return subprocess.CompletedProcess(argv, 1, "", "SYNTHETIC failed tool")
        flag = "-output" if web else "-oX"
        Path(argv[argv.index(flag) + 1]).write_text("SYNTHETIC boundary, no scanner launched")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def parse(path, run_id):
        if Path(path).name != "nmap.xml" and failure == "endpoint-parse":
            raise AdapterError("SYNTHETIC invalid endpoint capture")
        return ([baseline if Path(path).name == "nmap.xml" else endpoint], [])

    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "synthetic-nmap")
    monkeypatch.setattr(live_assessment.subprocess, "run", process)
    monkeypatch.setattr(live_assessment, "parse_nmap_xml", parse)
    monkeypatch.setattr(live_assessment.orchestrator, "scanner_argv", lambda _: ["synthetic-nikto"])
    monkeypatch.setattr(
        live_assessment.orchestrator,
        "scanner_status",
        lambda _: (
            {"status": "missing", "detail": "SYNTHETIC missing tool"}
            if failure == "nikto-missing"
            else {"status": "available"}
        ),
    )

    def redis(*args):
        raise TimeoutError("SYNTHETIC unavailable Redis")

    monkeypatch.setattr(live_assessment.redis_probe, "run", redis)
    monkeypatch.setattr(
        live_assessment.analyst,
        "analyze_optional",
        lambda *args, **kwargs: {"analyst": None, "ai_status": ai_status, "ai_attempts": []},
    )
    result = live_assessment.run(
        "http://synthetic.invalid:7001/",
        {
            "status": "ready",
            "resolved_ips": [baseline.ip],
            "endpoint": {"host": "synthetic.invalid", "scheme": "http", "port": 7001, "path": "/"},
        },
        config,
        provider="ollama",
        on_progress=lambda *event: events.append(event),
        on_capture=captures.append,
        on_case=cases.append,
    )
    assert result["scan_status"] == "partial"
    assert result["assessment_summary"]["scan_status"] == "partial"
    assert result["assessment_summary"]["collection_failures"]
    assert result["ai_status"] == ai_status and result["analyst"] is None
    assert result["services"][0]["port"] == 80
    assert any(state == "error" for _, state, _ in events)
    assert events[-1][:2] == ("report", "complete")
    assert "partial scan" in events[-1][2].lower()
    assert "scan complete" not in events[-1][2].lower()
    assert captures[-1]["scan_status"] == cases[-1]["scan_status"] == "partial"
    assert cases[-1]["payload"]["scan_status"] == "partial"
    assert result["saved_assessment"]["status"] == "saved"
    directory = Path(result["evidence_directory"])
    for filename in ("review-evidence.json", "review-final.json"):
        receipt = json.loads((directory / filename).read_text())
        assert receipt["result"]["scan_status"] == "partial"
    reopened = capture_history.load(directory.parent, directory.name)
    assert reopened["result"]["scan_status"] == reopened["payload"]["scan_status"] == "partial"
    listing = capture_history.listing(directory.parent)
    assert listing["captures"][0]["scan_status"] == "partial"
    assert "Partial scan" in capture_review.index(listing)
    assert "Partial scan" in capture_review.review(reopened)
    assert "Collection completed" not in capture_review.review(reopened)


@pytest.mark.parametrize("initial,final", [("partial", "complete"), ("complete", "partial")])
def test_final_ai_receipt_cannot_change_collection_status(tmp_path, initial, final):
    directory, result = capture(tmp_path)
    result["scan_status"] = initial
    capture_history.save(directory, result, config_hash="SYNTHETIC config")
    with pytest.raises(ConfigError, match="collection|evidence checkpoint"):
        capture_history.save(directory, {**result, "scan_status": final}, final=True)
    assert not (directory / "review-final.json").exists()
    assert capture_history.load(tmp_path, directory.name)["result"]["scan_status"] == initial


def test_rehashed_final_receipt_cannot_upgrade_partial_collection(tmp_path):
    directory, result = capture(tmp_path)
    result["scan_status"] = "partial"
    baseline = capture_history.save(directory, result, config_hash="SYNTHETIC config")
    final = {key: value for key, value in baseline.items() if key != "snapshot_hash"} | {
        "parent_hash": baseline["snapshot_hash"],
        "result": {**result, "scan_status": "complete"},
    }
    (directory / "review-final.json").write_text(
        json.dumps({**final, "snapshot_hash": capture_history._hash(final)})
    )
    with pytest.raises(ConfigError, match="collection"):
        capture_history.load(tmp_path, directory.name)


@pytest.mark.parametrize("status", ["failed", "not_attempted", True, "", None, [], {}])
def test_unknown_collection_outcome_cannot_publish_a_receipt(tmp_path, status):
    directory, result = capture(tmp_path)
    with pytest.raises(ConfigError, match="collection status"):
        capture_history.save(directory, {**result, "scan_status": status}, config_hash="SYNTHETIC")
    assert not (directory / "review-evidence.json").exists()


def test_initial_receipt_cannot_contradict_the_collected_payload(tmp_path):
    directory, result = capture(tmp_path)
    payload = json.loads((directory / "case.json").read_text())
    raw = json.dumps({**payload, "scan_status": "partial"}).encode()
    (directory / "case.json").write_bytes(raw)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"]["case.json"] = hashlib.sha256(raw).hexdigest()
    (directory / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ConfigError, match="collection status"):
        capture_history.save(directory, result, config_hash="SYNTHETIC")
    assert not (directory / "review-evidence.json").exists()


def test_partial_result_ui_contract_and_labels():
    node = shutil.which("node")
    assert node, "MISSING: node for the pure live-result contract check"
    script = r"""
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source = readFileSync('vulnassess/ui/static/workflow-data.js', 'utf8');
const helpers = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
for (const status of ['complete', 'partial']) {
  const result = {scan_status: status, analyst: null, assessment_summary: {}};
  assert.equal(helpers.isLiveAssessmentResult(result), true);
}
for (const result of [null, {}, {analyst: {}}, {scan_status: 'complete'},
  {scan_status: 'failed', analyst: {}, assessment_summary: {}},
  {scan_status: 'partial', assessment_summary: []}]) {
  assert.equal(helpers.isLiveAssessmentResult(result), false);
}
assert.equal(helpers.scanCompletionLabel({scan_status: 'partial'}), 'Partial scan');
assert.equal(helpers.scanCompletionLabel({scan_status: 'complete'}), 'Scan complete');
assert.equal(helpers.scanCompletionLabel({scan_status: 'partial'}, true), 'Saved-evidence review: partial scan');
assert.equal(helpers.scanCompletionLabel({}), 'Scan outcome unavailable');
assert.equal(helpers.scanCompletionLabel(null, true), 'Saved-evidence review: outcome unavailable');
const client = readFileSync('vulnassess/ui/static/workflow.js', 'utf8');
assert.match(client, /isLiveAssessmentResult\(event.result\)/);
assert.match(client, /scanCompletionLabel\(liveState.result/);
assert.doesNotMatch(client, /scan_status === 'complete'/);
const insights = await import(`data:text/javascript;base64,${Buffer.from(readFileSync('vulnassess/ui/static/workflow-insights.js', 'utf8')).toString('base64')}`);
const overview = await import(`data:text/javascript;base64,${Buffer.from(readFileSync('vulnassess/ui/static/workflow-overview.js', 'utf8')).toString('base64')}`);
const brief = insights.buildInsightBrief({assessment: {}, live: {active: true,
  result: {scan_status: 'partial', ai_status: 'needs_review', analyst: null,
    assessment_summary: {scan_status: 'partial', finding_count: 0, service_count: 1,
      collection_failures: [{stage: 'nikto', detail: 'SYNTHETIC failed check'}],
      coverage_gaps: ['SYNTHETIC requested Nikto failed']}}}});
assert.equal(brief.scanStatus, 'partial');
class Element {
  constructor() { this.children = []; this.textContent = ''; }
  append(...children) { this.children.push(...children); }
  replaceChildren() { this.children = []; }
  addEventListener() {}
  setAttribute() {}
}
globalThis.document = {createElement: () => new Element()};
const content = item => [item.textContent, ...item.children.map(content)].join(' ');
for (const render of [overview.renderAssessmentOverview, insights.renderInsightBrief]) {
  const holder = new Element();
  render(holder, brief, () => {});
  assert.match(content(holder), /Partial scan/);
  assert.match(content(holder), /coverage is incomplete/);
}
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
