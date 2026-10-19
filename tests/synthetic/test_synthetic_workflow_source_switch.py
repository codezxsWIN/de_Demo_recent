"""Pure browser-state regressions; no browser, scanner, provider or network calls."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARNESS = r"""
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source = readFileSync('vulnassess/ui/static/workflow.js', 'utf8');
const loader = source.slice(source.indexOf('async function loadWorkflow()'),
  source.indexOf("document.getElementById('refresh-workflow').addEventListener"));
const nodes = new Map();
const node = name => {
  if (!nodes.has(name)) nodes.set(name, {
    hidden: false, disabled: false, textContent: '', children: [],
    querySelector: selector => node(name + '/' + selector),
    replaceChildren(...children) { this.children = children; },
  });
  return nodes.get(name);
};
const result = {marker: 'synthetic previous result'};
const originalStages = new Map([['scanner', {state: 'complete'}]]);
const state = {
  active: true, busy: false, previewState: 'complete', previewScenario: {steps: []},
  target: 'synthetic previous target', provider: 'synthetic provider',
  reuseRecent: true, savedCapture: true, stages: originalStages,
  scan: result, result, error: 'synthetic previous error', needsReview: true,
};
const priorAssessment = {run: {run_id: 'synthetic prior run'}};
const assessment = {
  run: {run_id: 'synthetic stored run', config_hash: 'synthetic hash'},
  hosts: [{ip: '192.0.2.10'}], findings: [], scores: [],
};
const storedBefore = JSON.stringify(assessment);
const requests = [];
const rendered = [];
let getRecord = async path => {
  requests.push(path);
  if (path === '/api/runs') return {runs: [{run_id: assessment.run.run_id}]};
  if (path.startsWith('/api/run/')) return assessment;
  return {};
};
const context = {
  URLSearchParams, Map, Set, Promise,
  liveState: state,
  runState: {busy: false, selected: new Set()},
  view: {load: 0, assessment: priorAssessment, node: 'synthetic node'},
  previewSequence: 41, briefSignature: 'synthetic stale signature',
  document: {getElementById: node},
  location: {search: '', hash: ''},
  message: node('loading-state'), graph: node('graph'), inspector: node('inspector'),
  runSelect: node('run-select'), hostSelect: node('host-select'),
  findingSelect: node('finding-select'),
  getRecord: path => getRecord(path),
  element: (_tag, _class, value) => ({textContent: value}),
  evidenceKind: () => 'STORED ASSESSMENT', buildNodes: () => [],
  renderLiveProgress: () => rendered.push(['progress', state.active]),
  renderLiveExecution: () => { node('live-execution').hidden = !state.active; },
  renderLiveResult: () => { node('live-result').hidden = !(state.scan || state.result || state.error); },
  renderGraph: () => rendered.push(['graph', state.active]),
  populateSelection() {}, renderRunTargets() {}, updateProjectLink() {}, fit() {},
  refreshIntelStatus() {}, selectNode() {},
};
vm.createContext(context);
vm.runInContext(loader, context);
const resetVerified = () => {
  assert.equal(state.active, false);
  assert.equal(state.busy, false);
  assert.equal(state.previewState, 'idle');
  assert.equal(state.previewScenario, null);
  assert.equal(state.scan, null); assert.equal(state.result, null);
  assert.equal(state.error, ''); assert.equal(state.needsReview, false);
  assert.equal(state.target, ''); assert.equal(state.provider, '');
  assert.equal(state.reuseRecent, false); assert.equal(state.savedCapture, false);
  assert.equal(state.stages.size, 0);
  assert.notEqual(state.stages, originalStages);
  assert.equal(originalStages.size, 1, 'retained stage object must not be destroyed');
  assert.equal(node('live-execution').hidden, true);
  assert.equal(node('live-result').hidden, true);
  assert.equal(context.previewSequence, 42);
  assert.equal(JSON.stringify(assessment), storedBefore);
};
"""


@pytest.mark.parametrize(
    "scenario",
    [
        "complete",
        "running",
        "stopped",
        "blocked",
        "completed_live",
        "failure",
        "busy_live",
        "busy_batch",
    ],
)
def test_source_switch_does_not_mix_simulation_live_and_stored_results(scenario: str) -> None:
    node = shutil.which("node")
    assert node is not None, "MISSING: node for workflow source-switch regression"
    script = (
        HARNESS
        + f"\nconst scenario = {scenario!r};\n"
        + r"""
if (scenario.startsWith('busy_')) {
  state.previewState = 'idle';
  if (scenario === 'busy_live') state.busy = true;
  else context.runState.busy = true;
  await context.loadWorkflow();
  assert.deepEqual(requests, []);
  assert.equal(state.result, result);
  assert.equal(state.active, true);
  assert.equal(state.stages, originalStages);
  assert.equal(context.view.assessment, priorAssessment);
  assert.equal(context.previewSequence, 41);
  assert.equal(context.view.load, 0);
  assert.match(node('workflow-announcement').textContent, /running/);
} else {
  if (scenario === 'completed_live') state.previewState = 'idle';
  else if (scenario !== 'failure') state.previewState = scenario;
  state.busy = scenario === 'running';
  if (scenario === 'failure') getRecord = async path => {
    requests.push(path); throw new Error('Synthetic unavailable records');
  };
  await context.loadWorkflow();
  resetVerified();
  if (scenario === 'failure') {
    assert.equal(context.view.assessment, null);
    assert.equal(context.graph.hidden, true);
    assert.equal(node('data-kind').textContent, 'RECORDS UNAVAILABLE');
    assert.match(node('assessment-overview').textContent, /Synthetic unavailable records/);
  } else {
    assert.equal(context.view.assessment, assessment);
    assert.equal(node('data-kind').textContent, 'STORED ASSESSMENT');
    assert.equal(context.graph.hidden, false);
    assert.ok(rendered.some(([kind, active]) => kind === 'graph' && active === false));
  }
}
console.log('Synthetic source switch passed: ' + scenario);
"""
    )
    completed = subprocess.run(
        [node, "--input-type=module", "-"],
        input=script,
        cwd=ROOT,
        capture_output=True,
        encoding="utf-8",
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
