import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source = readFileSync('vulnassess/ui/static/workflow-insights.js', 'utf8');
const {buildInsightBrief, renderInsightBrief, renderInsightHighlights} = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const profile = {
  host_ip: '192.0.2.10',
  role: {value: 'database', evidence: '6379/tcp redis', source: 'rule', confidence: .9},
  exposure: {value: 'internet_facing', evidence: 'approved external vantage', source: 'manual', confidence: 1},
  controls: {auth_required: {value: false, evidence: 'none observed', source: 'rule'}, tls: {value: true, evidence: 'TLS on 443', source: 'rule'}},
};
const assessment = {
  run: {run_id: 'fixture', summary: {}},
  hosts: [{ip: '192.0.2.10', services: [{port: 6379, protocol: 'tcp', name: 'redis'}]}],
  context: [profile],
  findings: [{id: 'f1', host_ip: '192.0.2.10', title: '<script>finding</script>', cve_ids: ['CVE-2022-0543']}],
  scores: [{finding_id: 'f1', host_ip: '192.0.2.10', risk: 100, band: 'Critical', reason: 'KEV floor and environmental inputs'}],
  enrichments: [], feeds_meta: [],
};
const original = JSON.stringify(assessment);
const stored = buildInsightBrief({assessment});
assert.equal(stored.target, '192.0.2.10');
assert.equal(stored.source, 'Stored assessment');
assert.equal(stored.role.value, 'database');
assert.equal(stored.controls.find(item => item.name === 'auth_required').value, null, 'legacy none-observed is unknown');
assert.equal(stored.priorities[0].risk, 100);
assert.equal(stored.priorities[0].reason, assessment.scores[0].reason);
assert.equal(stored.ai.status, 'Not requested');
assert.equal(JSON.stringify(assessment), original);
const synthetic = buildInsightBrief({assessment: {...assessment, findings: [{...assessment.findings[0], provenance: {raw_path: 'tests/synthetic/nmap.xml'}}]}});
assert.equal(synthetic.source, 'Synthetic stored inputs', 'demo evidence must remain explicitly labeled');

const multiple = {...assessment, hosts: [...assessment.hosts, {ip: '192.0.2.11', services: []}], context: [...assessment.context, {...profile, host_ip: '192.0.2.11', role: {value: 'web_frontend'}}]};
assert.equal(buildInsightBrief({assessment: multiple}).role.value, 'unknown', 'do not borrow a single host context for overview');
assert.equal(buildInsightBrief({assessment: multiple, host: '192.0.2.11'}).priorities.length, 0);
assert.equal(buildInsightBrief({assessment: multiple, host: '192.0.2.99'}).serviceCount, 0);

const failed = buildInsightBrief({assessment, live: {active: true, previewState: 'idle', target: '192.0.2.11', error: 'Needs review', result: {analyst: {analysis: {summary: 'REJECTED PROSE'}}}}});
assert.equal(failed.role.value, 'unknown');
assert.equal(failed.priorities.length, 0, 'live failure must not borrow stored priorities');
assert.equal(failed.ai.summary, '', 'rejected output stays hidden');
assert.equal(failed.ai.status, 'Needs review');
assert.equal(failed.serviceCount, null, 'missing collection cannot be displayed as zero observed services');
assert.match(failed.conclusion, /No assessment conclusion/);

const result = {
  assessment_summary: {historical_capture: true, captured_at: '2026-09-28', conclusion: 'Historical finding, not a new scan', service_count: 1, finding_count: 1, priorities: [{finding_id: 'f1', title: 'Redis', risk: 100, band: 'Critical', reason: 'Recorded formula'}], coverage_gaps: ['No Nessus report'], context: {role: 'database', exposure: 'internet_facing'}},
  analyst: {model: 'test-model', analysis: {summary: 'Validated analysis', confidence: 'low', context_effect: {explanation: 'Exposure changes verification urgency', evidence_ids: ['E4']}, recommended_actions: [{action: 'Verify access', reason: 'Unknown auth', evidence_ids: ['E1']}], uncertainties: ['Auth unknown']}},
};
const live = buildInsightBrief({assessment, live: {active: true, previewState: 'idle', target: '192.0.2.11', result}});
assert.equal(live.source, 'Retained capture');
assert.equal(live.ai.status, 'Validated');
assert.equal(live.ai.confidence, 'low');
assert.deepEqual(live.ai.citations, ['E4']);
assert.equal(live.actions[0].action, 'Verify access');
assert.equal(live.capturedAt, '2026-09-28');

const zero = buildInsightBrief({assessment: {...assessment, findings: [], scores: []}});
assert.equal(zero.priorities.length, 0);
assert.match(zero.conclusion, /not proof.*safe/i);
const preview = buildInsightBrief({assessment, live: {active: true, previewState: 'running', previewScenario: {label: 'Web example'}}});
assert.equal(preview.source, 'Simulated preview');
assert.equal(preview.priorities.length, 0);
assert.equal(preview.role.value, 'unknown');

const batches = buildInsightBrief({assessment, live: {active: true, previewState: 'idle', result: {analyst: {batches: [result.analyst, result.analyst]}}}});
assert.equal(batches.ai.status, 'Validated batches');
assert.match(batches.ai.summary, /No cross-batch synthesis/);
assert.equal(batches.actions.length, 2);
assert.equal(batches.actions[1].batch, 2, 'citations retain batch namespace');
const summarizedBatches = buildInsightBrief({assessment, live: {active: true, previewState: 'idle', result: {assessment_summary: {next_actions: []}, analyst: {batches: [result.analyst, result.analyst]}}}});
assert.equal(summarizedBatches.actions[1]?.batch, 2, 'an empty global summary must not hide batch-scoped actions');

const html = readFileSync('vulnassess/ui/static/workflow.html', 'utf8');
assert.ok(html.indexOf('id="assessment-brief"') < html.indexOf('id="viewport"'));
assert.match(html, /href="\/static\/workflow-refresh.css"/);
assert.match(html, /id="toggle-insights"[^>]*aria-expanded="false"/);
assert.match(html, /data-flow-theme="light"/, 'the workflow opens in the clean light workspace');
assert.match(html, /id="toggle-theme"[^>]*aria-label="Switch to dark theme">Dark theme/);
const tokens = readFileSync('vulnassess/ui/static/tokens.css', 'utf8');
const lightTokens = [...tokens.matchAll(/:root\.workflow-theme \{([^}]+)\}/g)].at(-1)[1];
const darkTokens = tokens.match(/:root\.workflow-theme\[data-flow-theme="dark"\] \{([^}]+)\}/)[1];
for (const palette of [lightTokens, darkTokens]) {
  for (const name of ['bg', 'paper', 'soft']) {
    const hex = palette.match(new RegExp(`--flow-${name}: #([0-9a-f]{6});`))[1];
    const rgb = hex.match(/../g).map(channel => Number.parseInt(channel, 16));
    assert.ok(Math.max(...rgb) - Math.min(...rgb) <= 6, `neutral ${name} surface, not a green tint`);
  }
}
const canvasTokens = tokens.match(/:root\.workflow-theme \.viewport \{([^}]+)\}/)?.[1];
assert.ok(canvasTokens, 'a separate canvas palette keeps the light workspace from becoming one flat surface');
const categoryTokens = ['source', 'transform', 'intel', 'decision', 'output', 'ai'];
const moduleColors = categoryTokens.map(category => canvasTokens.match(new RegExp(`--module-${category}: #([0-9a-f]{6});`))?.[1]);
assert.ok(moduleColors.every(Boolean), 'each module family has an explicit identity accent');
assert.equal(new Set(moduleColors).size, categoryTokens.length, 'module identities remain distinguishable');
const refreshStyles = readFileSync('vulnassess/ui/static/workflow-refresh.css', 'utf8');
assert.match(refreshStyles, /\.flow-node \.node-disc \{[^}]*border-radius: 50%/);
assert.match(refreshStyles, /\.highlight-analysis \{[^}]*background: var\(--flow-feature-bg\)/);
assert.equal(source.includes('innerHTML'), false, 'untrusted text must use text nodes');

// Exercise actual render output with a tiny DOM fake; text remains literal and actions only navigate.
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; this.listeners = {}; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener(name, handler) { this.listeners[name] = handler; }
}
globalThis.document = {createElement: tag => new Element(tag)};
const holder = new Element('aside');
const selectedNodes = [];
renderInsightBrief(holder, stored, id => selectedNodes.push(id));
const flatten = element => [element, ...element.children.flatMap(flatten)];
const rendered = flatten(holder);
assert.ok(rendered.some(item => item.textContent === '<script>finding</script>'));
assert.equal(rendered.filter(item => item.tag === 'script').length, 0);
rendered.find(item => item.textContent === 'Inspect context evidence').listeners.click();
assert.deepEqual(selectedNodes, ['context']);
renderInsightBrief(holder, failed, () => {});
assert.equal(flatten(holder).some(item => item.textContent.includes('REJECTED PROSE')), false);
renderInsightBrief(holder, batches, () => {});
assert.ok(flatten(holder).some(item => item.textContent === 'Batch 2 / E1'));
renderInsightHighlights(holder, live, () => {});
assert.ok(flatten(holder).some(item => item.textContent === 'Exposure changes verification urgency'));
assert.ok(flatten(holder).some(item => item.textContent === 'Next: Verify access'));
console.log('Workflow brief: provenance, scoped context, canonical priorities, rejected AI, preview and batch isolation passed.');

const overviewSource = readFileSync('vulnassess/ui/static/workflow-overview.js', 'utf8');
const {renderAssessmentOverview} = await import(`data:text/javascript;base64,${Buffer.from(overviewSource).toString('base64')}`);
renderAssessmentOverview(holder, stored, id => selectedNodes.push(id));
assert.ok(flatten(holder).some(item => item.textContent === '100'));
assert.ok(flatten(holder).some(item => item.textContent === '<script>finding</script>'));
assert.ok(flatten(holder).some(item => item.textContent === 'KEV floor and environmental inputs'));
assert.equal(flatten(holder).filter(item => item.tag === 'script').length, 0);
renderAssessmentOverview(holder, failed, () => {});
assert.equal(flatten(holder).some(item => item.textContent.includes('REJECTED PROSE')), false);
assert.ok(flatten(holder).some(item => item.textContent === 'Needs review'));
renderAssessmentOverview(holder, {...stored, findingCount: 0, priorities: []}, () => {});
assert.ok(flatten(holder).some(item => item.textContent === 'No findings recorded. Verification is still needed.'));
renderAssessmentOverview(holder, {...stored, findingCount: null, priorities: [], source: 'Simulated preview'}, () => {});
assert.ok(flatten(holder).some(item => item.textContent === 'Preview only — no assessment result'));
const personal = buildInsightBrief({assessment: {}, live: {active: true, previewState: 'idle', result: {assessment_summary: {self_defence: {checked_at: '2026-10-05', boundary: 'Local machine only', limitations: 'Internet reachability unknown', checks: [{title: 'Firewall', state: 'unknown', precaution: 'Review Windows Security'}]}}}}});
renderAssessmentOverview(holder, personal, () => {});
assert.ok(flatten(holder).some(item => item.textContent === 'Firewall — unknown'));
assert.ok(flatten(holder).some(item => item.textContent === 'Review Windows Security'));
assert.ok(flatten(holder).some(item => item.textContent === 'Internet reachability unknown'));
const deviceSource = readFileSync('vulnassess/ui/static/self-defence.js', 'utf8');
const {renderSelfDefence} = await import(`data:text/javascript;base64,${Buffer.from(deviceSource).toString('base64')}`);
renderSelfDefence(holder, {self_defence: {checked_at:'test', boundary:'Local only', limitations:'Limited check', checks:[{title:'Encryption', state:'unknown', precaution:'Review settings'}], listeners:[{application:'<script>bad</script>', port:8000, binding:'this device only'}]}, ai_status:'unavailable'}, false);
assert.ok(flatten(holder).some(item => item.textContent === 'NOT VERIFIED'));
assert.ok(flatten(holder).some(item => item.textContent.includes('<script>bad</script>')));
assert.equal(flatten(holder).filter(item => item.tag === 'script').length, 0);
assert.ok(flatten(holder).some(item => item.textContent.includes('AI unavailable')));
renderSelfDefence(holder, {self_defence: {checked_at:'test', checks:[{id:'Defender',title:'Defender',state:'unknown',observation:'Defender status unknown'}], action_queue:[{title:'Verify antivirus',kind:'not verified',reason:'Status unavailable',action:'Review Windows Security',basis:['Defender']}] }}, false);
assert.ok(flatten(holder).some(item => item.textContent === 'Supporting observations'));
assert.ok(flatten(holder).some(item => item.tag === 'button' && item.textContent === 'Recheck Defender'));
const recheckButton = flatten(holder).find(item => item.textContent === 'Recheck Defender');
globalThis.fetch = async (url, options) => {
  assert.equal(url, '/api/device-recheck');
  assert.equal(options.headers['X-VulnAssess-Action'], 'device-recheck');
  assert.deepEqual(JSON.parse(options.body), {check:'Defender'});
  return {ok:true, json:async () => ({checked_at:'now',checks:[{id:'Defender',state:'enabled'}],history:[{checked_at:'now',state:'enabled'},{checked_at:'earlier',state:'unknown'}]})};
};
await recheckButton.listeners.click();
assert.equal(recheckButton.disabled, false);
assert.ok(flatten(holder).some(item => item.textContent.includes('unknown → enabled')));
assert.ok(flatten(holder).some(item => item.textContent.includes('AI advice still refers to the original assessment')));
assert.ok(flatten(holder).some(item => item.textContent === 'earlier · unknown'));
flatten(holder).find(item => item.className === 'device-action-row').listeners.click();
assert.ok(flatten(holder).some(item => item.textContent.includes('unknown → enabled')));
globalThis.fetch = async () => { throw new Error('Unavailable'); };
const currentRecheck = flatten(holder).find(item => item.textContent === 'Recheck Defender');
await currentRecheck.listeners.click();
assert.equal(currentRecheck.disabled, false);
assert.ok(flatten(holder).some(item => item.textContent === 'Unavailable'));
