"""Synthetic presentation regressions; no scanner, transport, model or browser runs."""

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = r"""
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const load = async name => import(`data:text/javascript;base64,${Buffer.from(
  readFileSync(`vulnassess/ui/static/${name}.js`, 'utf8')).toString('base64')}`);
const insights = await load('workflow-insights');
const overview = await load('workflow-overview');
globalThis.fetch = () => { throw new Error('Network forbidden in synthetic UI tests'); };
class Element {
  constructor(tag = 'div') {
    this.tag = tag; this.children = []; this.textContent = ''; this.listeners = {};
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener(name, handler) { this.listeners[name] = handler; }
  setAttribute() {}
  set innerHTML(_value) { throw new Error('Untrusted content must remain text'); }
}
globalThis.document = {createElement: tag => new Element(tag)};
const flatten = item => [item, ...item.children.flatMap(flatten)];
const content = item => flatten(item).map(child => child.textContent).join('\n');
const freeze = item => {
  if (item && typeof item === 'object') {
    Object.values(item).forEach(freeze); Object.freeze(item);
  }
  return item;
};
const finding = (id, host = 'synthetic-host-a') => ({
  id, title: `Synthetic finding ${id}`, host_ip: host,
});
const assessment = {
  hosts: [{ip: 'synthetic-host-a', services: []}, {ip: 'synthetic-host-b', services: []}],
  findings: [], scores: [], context: [],
};
const liveBrief = summary => insights.buildInsightBrief({assessment, live: {
  active: true, previewState: 'idle', result: {assessment_summary: summary},
}});
const renders = [insights.renderInsightBrief, overview.renderAssessmentOverview];
"""


def run_node(script: str) -> None:
    node = shutil.which("node")
    assert node is not None, "MISSING: node for synthetic unscored UI regressions"
    result = subprocess.run(
        [node, "--input-type=module", "-"],
        input=HARNESS + script,
        cwd=ROOT,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_stored_unscored_findings_keep_reasons_and_selection_without_mutation() -> None:
    run_node(r"""
const payload = freeze({...assessment,
  findings: [finding('scored'), finding('explicit'), finding('missing'), finding('zero'),
    finding('other', 'synthetic-host-b')],
  scores: [{finding_id: 'scored', risk: 70, band: 'High'},
    {finding_id: 'zero', risk: 0, band: 'Low', base_score: 0, env_score: 0,
      native_fallback: null, base_vector: 'SYNTHETIC vector basis'}],
  unscored_findings: [{finding_id: 'explicit', title: 'Synthetic explicit title',
    reason: 'Synthetic missing severity evidence'},
    {finding_id: 'other', title: 'Synthetic other host', reason: 'Synthetic other reason'}],
});
const before = JSON.stringify(payload);
const brief = insights.buildInsightBrief({assessment: payload, host: 'synthetic-host-a'});
assert.equal(brief.findingCount, 4);
assert.deepEqual(brief.priorities.map(item => item.finding_id), ['scored', 'zero']);
assert.deepEqual(brief.unscoredFindings.map(item => item.finding_id), ['explicit', 'missing']);
assert.equal(brief.unscoredFindings[0].reason, 'Synthetic missing severity evidence');
assert.equal(brief.unscoredFindings[0].title, 'Synthetic explicit title');
assert.match(brief.unscoredFindings[1].reason, /No canonical score/);
const selected = insights.buildInsightBrief({assessment: payload,
  host: 'synthetic-host-a', finding: 'missing'});
assert.equal(selected.findingCount, 1);
assert.equal(selected.priorities.length, 0);
assert.deepEqual(selected.unscoredFindings.map(item => item.finding_id), ['missing']);
const empty = insights.buildInsightBrief({assessment: payload, host: 'synthetic-absent'});
assert.equal(empty.findingCount, 0);
assert.equal(empty.unscoredFindings.length, 0);
assert.equal(empty.priorities.length, 0);
assert.deepEqual(insights.buildInsightBrief({assessment: payload,
  finding: 'other'}).unscoredFindings.map(item => item.finding_id), ['other']);
assert.equal(JSON.stringify(payload), before);
""")


def test_explicitly_empty_historical_basis_is_flagged_but_supported_zero_is_preserved() -> None:
    run_node(r"""
const legacy = freeze({finding_id: 'legacy', risk: 0, band: 'Low', base_score: null,
  env_score: null, native_fallback: null, base_vector: null, env_vector: null});
assert.equal(insights.lacksSeverityBasis(legacy), true);
assert.equal(insights.lacksSeverityBasis({...legacy, risk: 90, band: 'Critical'}), true);
const valid = [
  {finding_id: 'minimal', risk: 0, band: 'Low'},
  {...legacy, finding_id: 'base-zero', base_score: 0},
  {...legacy, finding_id: 'env-zero', env_score: 0},
  {...legacy, finding_id: 'native', native_fallback: 'Synthetic native severity basis'},
  {...legacy, finding_id: 'base-vector', base_vector: 'SYNTHETIC base vector'},
  {...legacy, finding_id: 'env-vector', env_vector: 'SYNTHETIC environmental vector'},
];
for (const key of ['base_score', 'env_score', 'native_fallback']) {
  const omitted = {...legacy, finding_id: `omitted-${key}`};
  delete omitted[key]; valid.push(omitted);
}
for (const score of valid) {
  assert.equal(insights.lacksSeverityBasis(score), false, score.finding_id);
}
const payload = freeze({...assessment,
  findings: [finding('legacy'), ...valid.map(item => finding(item.finding_id))],
  scores: [legacy, ...valid],
});
const before = JSON.stringify(payload);
const brief = insights.buildInsightBrief({assessment: payload});
assert.deepEqual(brief.priorities.map(item => item.finding_id), valid.map(item => item.finding_id));
assert.equal(brief.unscoredFindings.length, 1);
assert.equal(brief.unscoredFindings[0].storedScore.risk, 0);
assert.equal(brief.unscoredFindings[0].storedScore.band, 'Low');
assert.match(brief.unscoredFindings[0].reason, /lacks a severity basis/);
for (const render of renders) {
  const holder = new Element(); render(holder, brief, () => {});
  assert.match(content(holder), /Stored values for audit only: risk 0 \/ band Low/);
  assert.match(content(holder), /lacks a severity basis/);
}
const legacyOnly = insights.buildInsightBrief({assessment: {...assessment,
  findings: [finding('legacy')], scores: [legacy]}});
for (const render of renders) {
  const holder = new Element(); render(holder, legacyOnly, () => {});
  assert.doesNotMatch(content(holder), /highest priority Low|PRIORITY 1/);
  const labels = flatten(holder).filter(item =>
    item.className === 'brief-band' || item.className === 'overview-score');
  assert.ok(labels.some(item => /Unscored/.test(content(item))));
}
for (const risk of [null, undefined]) {
  const missing = insights.reviewFindingPriorities([{finding_id: 'missing-risk', risk, band: 'Low'}]);
  assert.equal(missing.priorities.length, 0);
  assert.equal(missing.unscoredFindings[0].finding_id, 'missing-risk');
}
assert.equal(JSON.stringify(payload), before);
""")


def test_live_summary_frame_and_preview_keep_unscored_evidence_isolated() -> None:
    run_node(r"""
const entries = freeze([{finding_id: 'live-unscored', title: '<script>Synthetic title</script>',
  reason: '<img src=x onerror=synthetic> Synthetic severity unavailable'}]);
const summary = freeze({finding_count: 2, service_count: 1,
  priorities: [{finding_id: 'live-scored', title: 'Synthetic live priority', risk: 70, band: 'High'}],
  unscored_findings: entries});
const before = JSON.stringify(summary);
const payload = {...assessment, findings: [finding('stale')],
  unscored_findings: [{finding_id: 'stale', title: 'STALE', reason: 'STALE'}]};
for (const live of [
  {result: {assessment_summary: summary}},
  {scan: {assessment_summary: summary}},
  {result: {decision_frame: {priorities: summary.priorities, unscored_findings: entries}}},
]) {
  const brief = insights.buildInsightBrief({assessment: payload,
    live: {...live, active: true, previewState: 'idle', error: 'Synthetic rejected model'}});
  assert.equal(brief.unscoredFindings.length, 1);
  assert.equal(brief.unscoredFindings[0].reason, entries[0].reason);
  assert.equal(brief.priorities[0].risk, 70);
  for (const render of renders) {
    const holder = new Element(); render(holder, brief, () => {});
    assert.match(content(holder), /<script>Synthetic title<\/script>/);
    assert.match(content(holder), /Synthetic severity unavailable/);
    assert.doesNotMatch(content(holder), /STALE/);
    assert.equal(flatten(holder).some(item => ['script', 'img'].includes(item.tag)), false);
  }
}
const preview = insights.buildInsightBrief({assessment: payload, live: {active: true,
  previewState: 'running', result: {assessment_summary: summary}}});
assert.deepEqual(preview.unscoredFindings, []);
assert.deepEqual(preview.priorities, []);
for (const render of renders) {
  const holder = new Element(); render(holder, preview, () => {});
  assert.doesNotMatch(content(holder), /Synthetic title|Synthetic severity unavailable|STALE/);
}
assert.equal(JSON.stringify(summary), before);
""")


def test_every_unscored_finding_renders_and_actions_only_navigate() -> None:
    run_node(r"""
const entries = Array.from({length: 7}, (_, index) => ({finding_id: `synthetic-${index}`,
  title: `Synthetic unscored title ${index}`, reason: `Synthetic missing basis ${index}`}));
const brief = liveBrief({finding_count: 7, service_count: 1, priorities: [], unscored_findings: entries});
for (const render of renders) {
  const holder = new Element(); const selected = [];
  render(holder, brief, id => selected.push(id));
  for (const entry of entries) {
    assert.ok(flatten(holder).some(item => item.textContent === entry.title));
    assert.ok(flatten(holder).some(item => item.textContent === entry.reason));
    assert.ok(flatten(holder).some(item => item.textContent === entry.finding_id));
  }
  assert.match(content(holder), /Unscored findings/);
  assert.doesNotMatch(content(holder), /highest priority Low|PRIORITY 1|No findings recorded/);
  flatten(holder).find(item => item.tag === 'button' &&
    item.textContent.startsWith('Inspect unscored findings')).listeners.click();
  assert.deepEqual(selected, ['queue']);
}
const holder = new Element(); const selected = [];
insights.renderInsightHighlights(holder, brief, id => selected.push(id));
assert.match(content(holder), /7 unscored findings/);
assert.doesNotMatch(content(holder), /Services are verification candidates/);
flatten(holder).find(item => item.className === 'highlight highlight-priority').listeners.click();
assert.deepEqual(selected, ['queue']);
""")


def test_historical_capture_dates_never_use_refresh_time_as_capture_time() -> None:
    run_node(r"""
for (const captured_at of [null, undefined, '2020-01-02T03:04:05Z']) {
  for (const intelligence_refreshed_at of [null, '2026-10-17T12:34:56Z']) {
    const summary = freeze({historical_capture: true, captured_at, intelligence_refreshed_at,
      capture_time_source: captured_at ? 'review_receipt' : 'unknown',
      capture_time_warning: captured_at ? '' : 'Synthetic capture time was not recorded.',
      finding_count: 0, service_count: 1, priorities: []});
    const before = JSON.stringify(summary);
    const brief = liveBrief(summary);
    assert.equal(brief.source, 'Retained capture');
    for (const render of renders) {
      const holder = new Element(); render(holder, brief, () => {});
      const output = content(holder);
      assert.doesNotMatch(output, /\bnull\b|\bundefined\b/);
      assert.match(output, /not a new scan/i);
      if (captured_at) {
        assert.match(output, /Captured 2020-01-02T03:04:05Z/);
        assert.match(output, /Capture time source: review receipt/);
      } else {
        assert.match(output, /Capture date unknown/);
        assert.match(output, /Synthetic capture time was not recorded/);
        assert.match(output, /Capture time source: unknown/);
      }
      if (intelligence_refreshed_at) {
        assert.match(output, /Intelligence refreshed 2026-10-17T12:34:56Z/);
        assert.match(output, /refresh time, not the capture date/);
        assert.doesNotMatch(output, /Captured 2026-10-17/);
      }
    }
    assert.equal(JSON.stringify(summary), before);
  }
}
const bare = liveBrief({historical_capture: true, captured_at: null});
assert.ok(bare.captureDetails.some(line => line.startsWith('Capture date unknown')));
assert.equal(bare.captureDetails.some(line => line.startsWith('Capture time source:')), false);
""")


def test_workflow_summary_and_decision_frame_render_unscored_reasons_offline() -> None:
    run_node(r"""
const source = readFileSync('vulnassess/ui/static/workflow.js', 'utf8');
// Exercise the actual presentation functions without booting the interactive app.
const helpers = source.slice(source.indexOf('function appendUnscoredFindings('),
  source.indexOf('function appendModelContextEffect('));
const summaryRenderer = source.slice(source.indexOf('function appendLiveSummary('),
  source.indexOf('function appendBatchReview('));
const liveState = {busy: false, error: ''};
const element = (tag, className = '', value = '') => {
  const item = new Element(tag); item.className = className; item.textContent = String(value);
  return item;
};
const build = new Function('element', 'liveState', 'reviewFindingPriorities',
  'captureProvenanceLines', helpers + summaryRenderer +
  '\nreturn {appendLiveSummary, appendDecisionFrame};');
const renderers = build(element, liveState, insights.reviewFindingPriorities,
  insights.captureProvenanceLines);
const unscored = [{finding_id: 'synthetic-unscored', title: '<script>Synthetic finding</script>',
  reason: 'Synthetic severity not established'}];
const legacy = {finding_id: 'synthetic-legacy', title: 'Synthetic retained score', risk: 0,
  band: 'Low', base_score: null, env_score: null, native_fallback: null};
const summary = freeze({historical_capture: true, captured_at: null,
  intelligence_refreshed_at: '2026-10-17T12:34:56Z', capture_time_source: 'unknown',
  capture_time_warning: 'Synthetic capture time not recorded',
  finding_count: 2, service_count: 1, priorities: [legacy], unscored_findings: unscored,
  cve_evidence: [{finding_id: legacy.finding_id, cve_id: 'SYNTHETIC-CVE',
    title: 'Synthetic retained CVE', tool: 'synthetic', priority: {risk: 0, band: 'Low'}}]});
const before = JSON.stringify(summary);
const holder = new Element(); renderers.appendLiveSummary(holder, summary);
assert.match(content(holder), /Capture date unknown/);
assert.match(content(holder), /Capture time source: unknown/);
assert.match(content(holder), /Synthetic capture time not recorded/);
assert.match(content(holder), /Intelligence refreshed 2026-10-17T12:34:56Z/);
assert.match(content(holder), /0 deterministic priorities · 2 unscored findings/);
assert.match(content(holder), /Synthetic severity not established/);
assert.match(content(holder), /lacks a severity basis/);
assert.match(content(holder), /Stored values for audit only: risk 0 \/ band Low/);
assert.match(content(holder), /Deterministic priority: Unscored/);
assert.doesNotMatch(content(holder), /Deterministic priority: 0 \/ Low|\bnull\b|\bundefined\b/);
assert.equal(flatten(holder).some(item => item.tag === 'script'), false);
assert.equal(JSON.stringify(summary), before);
const frameHolder = new Element();
renderers.appendDecisionFrame(frameHolder, {mode: 'scored_findings', priorities: [legacy],
  unscored_findings: unscored});
assert.match(content(frameHolder), /Synthetic severity not established/);
assert.match(content(frameHolder), /lacks a severity basis/);
assert.doesNotMatch(content(frameHolder), /\bnull\b|\bundefined\b/);
assert.equal(flatten(frameHolder).find(item => item.tag === 'ol').children.length, 0,
  'unscored findings must not acquire ranked list positions');
const zero = {finding_id: 'synthetic-zero', title: 'Synthetic supported zero', risk: 0,
  band: 'Low', base_score: 0, env_score: 0, native_fallback: null};
const zeroHolder = new Element();
renderers.appendLiveSummary(zeroHolder, {finding_count: 1, service_count: 1, priorities: [zero],
  cve_evidence: [{finding_id: zero.finding_id, cve_id: 'SYNTHETIC-ZERO',
    title: zero.title, tool: 'synthetic', priority: {risk: 0, band: 'Low'}}]});
assert.match(content(zeroHolder), /Deterministic priority: 0 \/ Low/);
assert.doesNotMatch(content(zeroHolder), /severity review required|lacks a severity basis/);
""")
