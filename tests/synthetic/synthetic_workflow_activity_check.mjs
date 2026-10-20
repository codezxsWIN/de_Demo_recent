import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const load = async path => import(`data:text/javascript;base64,${Buffer.from(readFileSync(path, 'utf8')).toString('base64')}`);
const {buildActivityModel, renderWorkflowActivity, renderActivityContext} = await load('vulnassess/ui/static/workflow-activity.js');
const {buildInsightBrief} = await load('vulnassess/ui/static/workflow-insights.js');
const scenario = process.argv[2];
const layout = readFileSync('vulnassess/ui/static/workflow.html', 'utf8');
assert.ok(layout.indexOf('id="viewport"') < layout.indexOf('id="workflow-activity"'), 'The canvas must come before its background panel');
assert.ok(layout.indexOf('class="workflow-sidebar"') < layout.indexOf('id="workflow-activity"'), 'Activity belongs in the workflow sidebar');
assert.doesNotMatch(layout, /class="activity-map-heading"/);
const base = {
  source: 'Live assessment', target: 'SYNTHETIC target', findingCount: 0, serviceCount: 1,
  scanStatus: 'complete', conclusion: 'SYNTHETIC evidence-only conclusion', captureDetails: [],
  priorities: [], unscoredFindings: [], controls: [{name: 'auth_required', value: null}],
  role: {value: 'web_frontend', source: 'rule', evidence: '<script>SYNTHETIC banner</script>', confidence: .9},
  exposure: {value: 'internet_facing', source: 'manual', evidence: 'SYNTHETIC approved metadata'},
  ai: {status: 'Not requested', summary: '', effect: '', citations: [], uncertainties: []},
  coverage: ['SYNTHETIC bounded scan'], actions: [],
};
const services = [{host_ip: '192.0.2.10', port: 443, protocol: 'tcp', name: 'http', product: '<img onerror=SYNTHETIC>', tls: true}];
let brief = structuredClone(base);
let live = {active: true, busy: false, stages: new Map()};

if (scenario === 'running') {
  brief = {...brief, findingCount: null, serviceCount: null, scanStatus: 'unknown'};
  live = {...live, busy: true, stages: new Map([
    ['scope', {state: 'complete', detail: 'SYNTHETIC allowed'}],
    ['scanner', {state: 'running', detail: 'SYNTHETIC Nmap'}],
    ['nikto', {state: 'running', detail: 'SYNTHETIC bounded Nikto'}],
  ])};
  const model = buildActivityModel(brief, live, services);
  assert.equal(model.title, 'Inspect the web endpoint');
  assert.equal(model.detail, 'SYNTHETIC bounded Nikto');
  assert.equal(model.running.length, 2);
  assert.match(model.why, /bounded Nikto/);
  assert.equal(model.phases.find(item => item.label === 'Collection').state, 'running');
} else if (scenario === 'rejected') {
  brief = {...brief, ai: {...brief.ai, status: 'Needs review', error: 'SYNTHETIC rejected'}};
  live = {...live, result: {ai_status: 'needs_review'}};
  assert.equal(buildActivityModel(brief, live).title, 'Evidence collected · AI not validated');
} else if (scenario === 'preview') {
  brief = {...brief, source: 'Simulated preview', serviceCount: null, findingCount: null};
  const model = buildActivityModel(brief, live, services);
  assert.equal(model.services.length, 0);
  assert.equal(model.preview, true);
  assert.match(model.why, /No scanner or model is called/);
} else if (scenario === 'partial') {
  brief = {...brief, scanStatus: 'partial'};
  live = {...live, result: {ai_status: 'validated'}, stages: new Map([
    ['nikto', {state: 'error', detail: 'SYNTHETIC timeout'}],
    ['nvd', {state: 'skipped', detail: 'SYNTHETIC no CVE'}],
  ])};
  const model = buildActivityModel(brief, live);
  assert.match(model.title, /Partial collection/);
  assert.equal(model.failures[0].detail, 'SYNTHETIC timeout');
  assert.equal(model.notRun[0].detail, 'SYNTHETIC no CVE');
  const noFindings = buildActivityModel(brief, {...live, stages: new Map(['score', 'queue', 'rationale'].map(id => [id, {state: 'skipped', detail: 'SYNTHETIC no findings'}]))});
  assert.equal(noFindings.phases.find(item => item.label === 'Priority').status, '0 recorded · 3 not applicable');
  const replay = buildActivityModel(brief, {...live, reuseRecent: true, stages: new Map([['scanner', {state: 'complete'}]])});
  assert.equal(replay.recent[0].retained, true);
} else if (scenario === 'priorities') {
  brief = {...brief, findingCount: 1, priorities: [{finding_id: 'SYNTHETIC F1', title: 'SYNTHETIC content-security-policy missing', risk: 30, band: 'Low', native_fallback: 'nikto:default=30', reason: 'SYNTHETIC configured priority'}],
    actions: [{action: 'SYNTHETIC verify configuration', reason: 'SYNTHETIC reason', batch: 2, evidence_ids: ['E1']}]};
  live = {...live, result: {ai_status: 'validated'}};
  assert.equal(buildActivityModel(brief, live).title, 'Assessment ready for review');
} else if (scenario === 'stored') {
  brief = {...brief, source: 'Stored assessment'};
  live = {...live, active: false};
  assert.match(buildActivityModel(brief, live).why, /not a new scan/);
} else {
  throw new Error('Unknown synthetic scenario');
}

class SyntheticNode {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.attributes = {}; }
  set innerHTML(_value) { throw new Error('Untrusted evidence must not enter innerHTML'); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; }
  setAttribute(key, value) { this.attributes[key] = value; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
}
globalThis.document = {createElement: tag => new SyntheticNode(tag)};
const holder = new SyntheticNode('div');
const before = JSON.stringify({brief, events: [...live.stages], services});
const inspected = [];
renderWorkflowActivity(holder, brief, live, services, id => inspected.push(id));
const flatten = node => [node, ...node.children.flatMap(flatten)];
const nodes = flatten(holder);
const text = nodes.map(node => node.textContent || '').join('\n');
assert.equal(JSON.stringify({brief, events: [...live.stages], services}), before, 'Presentation must not mutate evidence, scores or stages');
assert.ok(nodes.some(node => node.textContent === 'The context behind the result'));
assert.match(text, /Unknown does not mean absent/);
assert.match(text, /AI interpretation & next steps/);
assert.match(text, /Coverage, skipped work & unknowns/);
assert.ok(nodes.some(node => node.tag === 'blockquote' && node.textContent === '<script>SYNTHETIC banner</script>'));
nodes.find(node => node.textContent === 'Inspect context evidence →').listeners.click();
assert.deepEqual(inspected, ['context']);
const contextHolder = new SyntheticNode('div');
renderActivityContext(contextHolder, brief);
const contextText = flatten(contextHolder).map(node => node.textContent || '').join('\n');
assert.match(contextText, /SYNTHETIC target/);
assert.match(contextText, /SYNTHETIC approved metadata/);
assert.doesNotMatch(contextText, /45\.33\.32\.156/);
const workflowSource = readFileSync('vulnassess/ui/static/workflow.js', 'utf8');
assert.match(workflowSource, /liveState\.active && liveState\.previewState === 'idle' && \['context', 'nmap', 'nikto'\]\.includes\(view\.node\)/);
assert.match(workflowSource, /renderActivityContext\(content, brief\)/);
// Exercise the real inspector routing with deliberately unrelated stored data.
const inspectorSource = workflowSource.slice(workflowSource.indexOf('function renderInspector() {'), workflowSource.indexOf('function renderAnalyst() {'));
for (const identity of ['context', 'nmap']) {
  const panel = new SyntheticNode('section');
  const makeElement = (tag, className, value) => {
    const item = new SyntheticNode(tag); item.className = className; item.textContent = value; return item;
  };
  const env = {
    view: {node: identity, assessment: {run: {run_id: 'SYNTHETIC stored'}, hosts: [{ip: '192.0.2.99'}], findings: [], scores: [], context: []}},
    liveState: {active: true, previewState: 'idle', target: 'SYNTHETIC active endpoint', scan: {
      services: [{port: 7001, name: 'SYNTHETIC active service'}],
      decision_frame: {context: {role: {value: 'SYNTHETIC active role', evidence: 'SYNTHETIC active proof'}}},
    }},
    content: panel, element: makeElement, icon: () => new SyntheticNode('svg'),
    applyLiveRunToNodes: value => value, buildNodes: () => [{id: identity, group: 'transform', title: identity}],
    nodeDetails: () => ({input: 'SYNTHETIC module input', operation: 'SYNTHETIC internal operation', output: 'SYNTHETIC internal output', provenance: 'SYNTHETIC implementation', rows: [{label: 'WRONG STORED HOST', value: '192.0.2.99'}], quotes: [], records: []}),
    selection: () => ({}), currentAnalysis: () => null, buildInsightBrief, renderActivityContext,
    rows: items => makeElement('div', '', items.map(item => item.value).join(' ')),
  };
  const renderActualInspector = new Function('env', `const {view, liveState, content, element, icon, applyLiveRunToNodes, buildNodes, nodeDetails, selection, currentAnalysis, buildInsightBrief, renderActivityContext, rows} = env; ${inspectorSource}; return renderInspector;`)(env);
  renderActualInspector();
  const panelText = flatten(panel).map(item => item.textContent || '').join('\n');
  assert.match(panelText, /SYNTHETIC active endpoint/);
  assert.match(panelText, /Module internals/);
  assert.match(panelText, /SYNTHETIC internal operation/);
  assert.match(panelText, /SYNTHETIC implementation/);
  assert.doesNotMatch(panelText, /WRONG STORED HOST|192\.0\.2\.99/);
  assert.match(panelText, identity === 'context' ? /SYNTHETIC active proof/ : /SYNTHETIC active service/);
}
if (scenario === 'running') {
  const counts = nodes.filter(node => node.tag === 'dd').map(node => node.textContent);
  assert.deepEqual(counts.slice(0, 3), ['—', '—', '—']);
}
if (scenario === 'rejected') {
  assert.match(text, /AI output was withheld/);
  assert.doesNotMatch(text, /SYNTHETIC verify configuration/);
}
if (scenario === 'preview') assert.doesNotMatch(text, /192\.0\.2\.10/);
if (scenario === 'priorities') {
  assert.match(text, /Configured fallback: nikto:default=30 · not CVSS/);
  assert.match(text, /Built-in guidance, not an exploitation claim/);
  assert.match(text, /Batch 2 · Evidence E1/);
}

// Live titles must come from the target's evidence frame, not an unrelated run.
const targetTitle = 'SYNTHETIC target-specific finding';
const insight = buildInsightBrief({assessment: {hosts: [], findings: [], scores: [], context: []}, live: {
  active: true, previewState: 'idle', result: {
    decision_frame: {priorities: [{finding_id: 'SYNTHETIC target finding', title: targetTitle}]},
    assessment_summary: {finding_count: 1, priorities: [{finding_id: 'SYNTHETIC target finding', risk: 30, band: 'Low'}]},
  },
}});
assert.equal(insight.priorities[0].title, targetTitle);
// Details toggles one dock, rather than opening a second panel over the canvas.
const detailsToggleSource = workflowSource.slice(workflowSource.indexOf("document.getElementById('toggle-insights').addEventListener"), workflowSource.indexOf("document.getElementById('toggle-theme').addEventListener"));
const rail = {hidden: true};
const dock = {hidden: true};
const toggle = new SyntheticNode('button');
const selectedView = {node: ''};
new Function('document', 'inspector', 'view', 'updateLocation', 'renderGraph', 'fit', detailsToggleSource)(
  {getElementById: id => id === 'workflow-sidebar' ? rail : toggle}, dock, selectedView, () => {}, () => {}, () => {},
);
toggle.listeners.click({currentTarget: toggle});
assert.equal(rail.hidden, false);
assert.equal(toggle.attributes['aria-expanded'], 'true');
dock.hidden = false; selectedView.node = 'context';
toggle.listeners.click({currentTarget: toggle});
assert.equal(rail.hidden, true);
assert.equal(dock.hidden, true);
assert.equal(selectedView.node, '');
assert.equal(toggle.attributes['aria-expanded'], 'false');
console.log(`PASS synthetic activity scenario: ${scenario}`);
