import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source = readFileSync(new URL('../../vulnassess/ui/static/workflow-data.js', import.meta.url), 'utf8');
const workflow = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const layoutSource = readFileSync(new URL('../../vulnassess/ui/static/workflow-layout.js', import.meta.url), 'utf8');
const layout = await import(`data:text/javascript;base64,${Buffer.from(layoutSource).toString('base64')}`);
const beforeEdges = JSON.stringify(workflow.EDGES);
const routingSource = readFileSync(new URL('../../vulnassess/ui/static/workflow-routing.js', import.meta.url), 'utf8');
const routing = await import(`data:text/javascript;base64,${Buffer.from(routingSource).toString('base64')}`);
const beforeNodes = JSON.stringify(workflow.NODE_SPECS);
const routes = routing.routeConnections(workflow.NODE_SPECS, workflow.EDGES, workflow.SIZE);
assert.equal(routes.size, workflow.EDGES.length, 'Every dependency must be drawn');
for (const edge of workflow.EDGES) {
  const route = routes.get(`${edge.from}:${edge.to}`);
  assert.equal(route.clear, true, `${edge.from}:${edge.to} must have a clear route`);
  assert.doesNotMatch(route.path, /NaN|undefined/);
  for (let i = 1; i < route.points.length; i++) {
    const a = route.points[i - 1], b = route.points[i];
    if (route.kind !== 'curve') assert.ok(a.x === b.x || a.y === b.y, 'Fallback routes use orthogonal lanes');
    for (const node of workflow.NODE_SPECS.filter(node => ![edge.from, edge.to].includes(node.id))) {
      for (const box of routing.moduleObstacles(node)) {
        const hits = routing.segmentHitsBox(a,b,box);
        assert.equal(hits, false, `${edge.from}:${edge.to} crosses ${node.id} or its caption`);
      }
    }
  }
}
assert.ok([...routes.values()].filter(route => route.kind === 'curve').length >= workflow.EDGES.length * .7, 'Most default connections remain direct smooth curves, not lane detours');
for (const id of ['nmap','nessus','nikto']) {
  const branch = routes.get(`scope:${id}`);
  assert.equal(branch.kind,'curve','Scanner branches use the familiar smooth fan-out');
  assert.ok(branch.points[1].x >= branch.points[0].x,'Scanner branches leave scope towards the right, without backwards loops');
}
for (const edge of workflow.EDGES) {
  const route = routes.get(`${edge.from}:${edge.to}`);
  if (route.kind !== 'curve') continue;
  for (const id of [edge.from,edge.to]) {
    const node = workflow.NODE_SPECS.find(node => node.id === id);
    for (const box of routing.moduleObstacles(node)) {
      for (let i=1;i<route.points.length;i++) assert.equal(routing.segmentHitsBox(route.points[i-1],route.points[i],box),false,'Curves must also clear their own endpoint discs and captions');
    }
  }
}
assert.equal(JSON.stringify(workflow.EDGES), beforeEdges, 'Routing never mutates dependencies');
assert.equal(JSON.stringify(workflow.NODE_SPECS), beforeNodes, 'Routing never moves modules');
const movedModules = workflow.NODE_SPECS.map(node => node.id === 'context' ? {...node, x: node.x + 30} : node);
assert.ok([...routing.routeConnections(movedModules, workflow.EDGES, workflow.SIZE).values()].every(route => route.clear), 'A valid moved module is rerouted');
const canonicalPoint = workflow.NODE_SPECS.find(node => node.id === 'canonical');
const overlapped = workflow.NODE_SPECS.map(node => node.id === 'context' ? {...node, x: canonicalPoint.x, y: canonicalPoint.y} : node);
const obstructed = routing.routeConnections(overlapped, workflow.EDGES, workflow.SIZE);
assert.equal(obstructed.size, workflow.EDGES.length, 'Even obstructed custom links remain visible');
assert.ok([...obstructed.values()].some(route => !route.clear), 'Impossible custom routing is flagged, never silently hidden');
const saved = layout.readLayout({nmap: {x: 410, y: 240}, scope: {x: -1000, y: 9999}, unknown: {x: 25, y: 25}, nikto: {x: 'wrong', y: 50}}, workflow.NODE_SPECS, workflow.SIZE);
assert.deepEqual(saved.nmap, {x: 410, y: 240});
assert.deepEqual(saved.scope, {x: 95, y: workflow.SIZE.height - 142});
assert.equal(saved.unknown, undefined);
assert.equal(saved.nikto, undefined);
const moved = layout.moveNode(saved, 'nmap', 640, 330, workflow.SIZE);
assert.deepEqual(moved.nmap, {x: 640, y: 330});
assert.deepEqual(saved.nmap, {x: 410, y: 240}, 'dragging must not mutate a saved layout');
assert.deepEqual(layout.positionNodes(workflow.NODE_SPECS, moved).find(node => node.id === 'nmap'), {...workflow.NODE_SPECS.find(node => node.id === 'nmap'), x: 640, y: 330});
assert.deepEqual(layout.positionNodes(workflow.NODE_SPECS, {}).find(node => node.id === 'nmap'), workflow.NODE_SPECS.find(node => node.id === 'nmap'));
assert.deepEqual([...layout.pathNodeIds([{id: 'scanner'}, {id: 'context'}], ['scope', 'nmap', 'context', 'analyst'])], ['scope', 'nmap', 'context', 'analyst']);
assert.deepEqual([...layout.pathNodeIds([{node: 'scope', edges: ['scope:nmap']}, {node: 'nmap', edges: []}], [])], ['scope', 'nmap']);
const liveSource = readFileSync(new URL('../../vulnassess/ui/static/workflow.js', import.meta.url), 'utf8');
const selectorSource = liveSource.slice(liveSource.indexOf('function syncLiveSelection()'), liveSource.indexOf('function renderLiveExecution()'));
const labels = new Map();
const fakeDocument = {getElementById: id => { if (!labels.has(id)) labels.set(id, {}); return labels.get(id); }};
const hostControl = {replaceChildren(...items) {this.items = items;}};
const findingControl = {replaceChildren(...items) {this.items = items;}};
const activeState = {active: true, previewState: 'idle', target: 'https://test.example:7001/', scan: {resolved_ip: '192.0.2.10', finding_count: 6}};
new Function('liveState', 'hostSelect', 'findingSelect', 'element', 'document', selectorSource + '\nsyncLiveSelection();')(activeState, hostControl, findingControl, (tag, cls, text) => ({text}), fakeDocument);
assert.match(hostControl.items[0].text, /192\.0\.2\.10/);
assert.equal(hostControl.disabled, true);
assert.equal(findingControl.disabled, true);
assert.equal(labels.get('data-kind').textContent, 'LIVE ASSESSMENT');
const liveDeclarations = liveSource.slice(liveSource.indexOf('const analysisStages ='), liveSource.indexOf('function appendInvestigation'));
const liveSteps = new Function(liveDeclarations + '\nreturn executionSteps();')();
assert.ok(liveSteps.every(step => step.node), 'every live stage must map to a canvas node');
const livePath = layout.pathNodeIds(liveSteps, ['scope', 'nmap', 'context', 'analyst']);
for (const id of ['nikto', 'canonical', 'score', 'queue', 'rationale', 'report']) {
  assert.ok(livePath.has(id), id + ' must stay visible in the live execution path');
}
assert.ok(!livePath.has('nessus'), 'import-only scanner must not be marked as executed');
const input = JSON.parse(readFileSync(0, 'utf8'));
const before = JSON.stringify(input.assessment);
const nodes = workflow.buildNodes(input.assessment, input.scope);
const spine = ['scope', 'nmap', 'canonical', 'intel', 'score', 'queue', 'report'].map(id => nodes.find(node => node.id === id));
for (let index = 1; index < spine.length; index++) {
  assert.ok(spine[index].x > spine[index - 1].x, 'The main spine reads left to right');
  assert.ok(workflow.EDGES.some(edge => edge.from === spine[index - 1].id && edge.to === spine[index].id), 'Every spine connection must be a real dependency');
}
assert.equal(new Set(nodes.map(node => node.id)).size, nodes.length);
for (const node of nodes) {
  assert.ok(node.x >= 95 && node.x + 95 <= workflow.SIZE.width, `${node.id} module must fit horizontally`);
  assert.ok(node.y >= 48 && node.y + 122 <= workflow.SIZE.height, `${node.id} module and label must fit vertically`);
  for (const other of nodes.filter(other => other.id !== node.id)) {
    assert.ok(Math.abs(node.x - other.x) >= 190 || Math.abs(node.y - other.y) >= 170, `${node.id} and ${other.id} modules must not overlap`);
  }
}
for (const edge of workflow.EDGES) {
  assert.ok(nodes.some(node => node.id === edge.from));
  assert.ok(nodes.some(node => node.id === edge.to));
  assert.notEqual(edge.from, edge.to);
}
for (const identity of ['scope', 'nmap', 'nessus', 'nikto', 'canonical', 'nvd', 'epss', 'kev', 'intel', 'context', 'shadow', 'score', 'queue', 'rationale', 'report', 'analyst', 'evaluation', 'rescan']) assert.ok(nodes.some(node => node.id === identity));
assert.equal(nodes.find(node => node.id === 'analyst').status, 'Not run');
assert.equal(nodes.find(node => node.id === 'report').status, 'Artifact not attached');
assert.equal(nodes.find(node => node.id === 'evaluation').status, 'No result attached');
assert.ok(!workflow.EDGES.some(edge => edge.from === 'analyst' && ['context', 'score', 'queue'].includes(edge.to)));
const host = input.assessment.hosts[0].ip;
const slice = workflow.currentSlice(input.assessment, host);
assert.deepEqual(slice.scores, input.assessment.scores.filter(score => score.host_ip === host));
const score = slice.scores[0];
const details = workflow.nodeDetails('score', input.assessment, input.scope, input.weights, {host, finding: score.finding_id});
assert.deepEqual(details.records, [score]);
assert.equal(details.rows.find(row => row.label === 'Risk').value, score.risk);
assert.equal(details.rows.find(row => row.label === 'Threat multiplier').value, score.threat_multiplier);
assert.deepEqual(workflow.currentSlice(input.assessment, '', score.finding_id).profiles, input.assessment.context.filter(profile => profile.host_ip === score.host_ip));
const oldProfile = {...input.assessment.context[0], controls: {waf: {value: false, confidence: 0.5, source: 'rule', evidence: 'none observed'}}};
const oldAssessment = {...input.assessment, context: [oldProfile]};
const oldContext = workflow.nodeDetails('context', oldAssessment, input.scope, input.weights, {host: oldProfile.host_ip});
assert.equal(oldContext.quotes.find(item => item.label.endsWith('/ waf')).value, 'Unknown');
assert.equal(oldProfile.controls.waf.value, false);
const basis = workflow.evidenceBasis(oldAssessment, oldProfile.host_ip);
assert.equal(basis.observed.length, oldAssessment.hosts.find(item => item.ip === oldProfile.host_ip).services.length);
assert.ok(basis.context.some(line => line.includes('Role')));
assert.ok(basis.notChecked.some(line => line.includes('Nessus')));
assert.ok(basis.notChecked.some(line => line.includes('WAF')));
assert.ok(basis.nextVerification.includes('authorised'));
const selected = {host};
const result = {runId: input.assessment.run.run_id, hostIp: host, status: 'complete', result: {}};
assert.equal(workflow.buildNodes(input.assessment, input.scope, selected, result).find(node => node.id === 'analyst').status, 'Response received');
assert.equal(workflow.buildNodes(input.assessment, input.scope, {host: 'synthetic-other'}, result).find(node => node.id === 'analyst').status, 'Not run');
assert.equal(workflow.buildNodes(input.assessment, input.scope, selected, {...result, status: 'error'}).find(node => node.id === 'analyst').status, 'Request failed');
const empty = {...input.assessment, hosts: [], findings: [], scores: [], enrichments: [], context: [], rationales: [], feeds_meta: [], run: {...input.assessment.run, summary: {}}};
assert.equal(workflow.buildNodes(empty, null).find(node => node.id === 'score').status, 'No stored output');
assert.equal(workflow.buildNodes(empty, null).find(node => node.id === 'nmap').status, 'No scan evidence recorded');
const fixtureAssessment = {...input.assessment, feeds_meta: [
  {feed: 'nvd', path: 'C:\\repo\\tests\\synthetic\\feeds\\nvd', rows: 2, file_date: '2026-09-23'},
  {feed: 'epss', path: 'C:\\repo\\tests\\synthetic\\feeds\\epss.csv', rows: 2, file_date: '2026-09-05'},
  {feed: 'kev', path: 'C:\\repo\\tests\\synthetic\\feeds\\kev.json', rows: 1, file_date: '2026-09-05'},
]};
for (const feed of ['nvd', 'epss', 'kev']) {
  const fixtureNode = workflow.buildNodes(fixtureAssessment, input.scope).find(node => node.id === feed);
  assert.equal(fixtureNode.status, 'Test fixture only');
  assert.match(workflow.nodeDetails(feed, fixtureAssessment, input.scope, input.weights).message, /not operational/i);
}
assert.equal(JSON.stringify(input.assessment), before);
console.log(`WORKFLOW: ${nodes.length} nodes; graph links, stored score fidelity, empty states and analyst isolation passed`);

const clientSource = readFileSync(new URL('../../vulnassess/ui/static/analyst-client.js', import.meta.url), 'utf8');
const client = await import(`data:text/javascript;base64,${Buffer.from(clientSource).toString('base64')}`);
const syntheticResponse = (runId, hostIp) => ({
  run_id: runId, host_ip: hostIp, model: 'synthetic-model', canonical_scores_changed: false,
  analysis: {
    summary: 'Synthetic response for a pure queue test, not model evidence.', confidence: 'low',
    recommended_actions: [{order: 1, action: 'Synthetic action', reason: 'Synthetic reason', finding_ids: ['synthetic-finding'], evidence_ids: ['E1']}],
    correlations: [], uncertainties: ['Synthetic uncertainty'],
  },
  evidence: [{id: 'E1', text: 'Synthetic evidence for a unit test only.'}],
});
const requested = [];
let activeRequests = 0;
let peakRequests = 0;
const queue = client.createAnalysisQueue({request: async (runId, hostIp) => {
  requested.push(hostIp);
  activeRequests += 1;
  peakRequests = Math.max(peakRequests, activeRequests);
  await Promise.resolve();
  activeRequests -= 1;
  return syntheticResponse(runId, hostIp);
}});
assert.equal(requested.length, 0, 'Constructing the queue must not request analysis');
const queueTargets = ['synthetic-host-a', 'synthetic-host-b', 'synthetic-host-c'];
const finished = await queue.start('synthetic-run', queueTargets);
assert.deepEqual(requested, queueTargets);
assert.equal(peakRequests, 1);
assert.equal(finished.busy, false);
assert.deepEqual(finished.entries.map(entry => entry.status), ['complete', 'complete', 'complete']);
assert.deepEqual(queueTargets, ['synthetic-host-a', 'synthetic-host-b', 'synthetic-host-c']);

let releaseRequest;
const heldResponse = new Promise(resolve => { releaseRequest = resolve; });
const stoppedRequests = [];
const stoppedQueue = client.createAnalysisQueue({request: async (runId, hostIp) => {
  stoppedRequests.push(hostIp);
  await heldResponse;
  return syntheticResponse(runId, hostIp);
}});
const pendingQueue = stoppedQueue.start('synthetic-run', queueTargets);
await assert.rejects(stoppedQueue.start('synthetic-run', queueTargets), /already in progress/);
assert.equal(stoppedQueue.stopAfterCurrent(), true);
releaseRequest();
const stopped = await pendingQueue;
assert.deepEqual(stoppedRequests, ['synthetic-host-a']);
assert.deepEqual(stopped.entries.map(entry => entry.status), ['complete', 'not-run', 'not-run']);
assert.equal(stoppedQueue.stopAfterCurrent(), false);

const failedRequests = [];
const failedQueue = client.createAnalysisQueue({request: async (_runId, hostIp) => {
  failedRequests.push(hostIp);
  throw new Error('Synthetic model unavailable');
}});
const failed = await failedQueue.start('synthetic-run', queueTargets);
assert.deepEqual(failedRequests, ['synthetic-host-a']);
assert.deepEqual(failed.entries.map(entry => entry.status), ['error', 'not-run', 'not-run']);
assert.equal(failed.entries[0].result, null);
assert.equal(failed.entries[0].error, 'Synthetic model unavailable');
await assert.rejects(queue.start('synthetic-run', []), /recorded systems/);
await assert.rejects(queue.start('synthetic-run', ['synthetic-host-a', 'synthetic-host-a']), /distinct/);
for (const invalid of [
  {...syntheticResponse('synthetic-run', 'synthetic-host-a'), run_id: 'synthetic-other-run'},
  {...syntheticResponse('synthetic-run', 'synthetic-host-a'), host_ip: 'synthetic-other-host'},
  {...syntheticResponse('synthetic-run', 'synthetic-host-a'), canonical_scores_changed: true},
  {...syntheticResponse('synthetic-run', 'synthetic-host-a'), evidence: []},
]) {
  assert.throws(() => client.validateAnalystResponse(invalid, 'synthetic-run', 'synthetic-host-a'));
}
const mismatchedQueue = client.createAnalysisQueue({request: async () => syntheticResponse('synthetic-other-run', 'synthetic-host-a')});
const mismatched = await mismatchedQueue.start('synthetic-run', queueTargets);
assert.deepEqual(mismatched.entries.map(entry => entry.status), ['error', 'not-run', 'not-run']);
const originalFetch = globalThis.fetch;
const streamed = [
  {type: 'stage', stage: 'model', state: 'running', detail: 'Checking local model'},
  {type: 'stage', stage: 'model', state: 'complete', detail: 'Model ready'},
  {type: 'result', result: syntheticResponse('synthetic-run', 'synthetic-host-a')},
];
const wire = streamed.map(event => JSON.stringify(event)).join('\n') + '\n';
const bytes = new TextEncoder().encode(wire);
globalThis.fetch = async () => new Response(new ReadableStream({
  start(controller) {
    controller.enqueue(bytes.slice(0, 13));
    controller.enqueue(bytes.slice(13, 71));
    controller.enqueue(bytes.slice(71));
    controller.close();
  },
}));
try {
  const seen = [];
  const result = await client.requestAnalystProgress('synthetic-run', 'synthetic-host-a', event => seen.push(event));
  assert.equal(result.run_id, 'synthetic-run');
  assert.deepEqual(seen, streamed.slice(0, 2));
  for (const provider of ['google', 'groq_qwen', 'groq', 'openrouter']) {
    const calls = [];
    globalThis.fetch = async (url, options) => {
      calls.push({url, options});
      return new Response(wire);
    };
    const cloudResult = await client.requestAnalystProgress('synthetic-run', 'synthetic-host-a', () => {}, provider);
    assert.equal(cloudResult.canonical_scores_changed, false);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, '/api/analyst/synthetic-run/synthetic-host-a/events');
    assert.equal(calls[0].options.method, 'POST');
    assert.equal(calls[0].options.headers['X-VulnAssess-Action'], 'cloud-analyst');
    assert.deepEqual(JSON.parse(calls[0].options.body), {provider, share_evidence: true});
    await assert.rejects(client.requestAnalystProgress('synthetic-run', 'synthetic-host-a', () => {}, 'unknown'), /Unknown analyst provider/);
    assert.equal(calls.length, 1, 'An unknown provider must fail before fetch');
  }
  globalThis.fetch = async () => new Response(`${JSON.stringify({type: 'error', message: 'Model unavailable'})}\n`);
  await assert.rejects(client.requestAnalystProgress('synthetic-run', 'synthetic-host-a'), /Model unavailable/);
} finally {
  globalThis.fetch = originalFetch;
}
assert.equal(JSON.stringify(input.assessment), before);
// The live analyst inspector must show this run's validated response, never
// the separately selected database assessment or a disabled stored-host action.
const analystRenderer = liveSource.slice(liveSource.indexOf('function renderAnalyst()'), liveSource.indexOf('async function analyzeTarget('));
function syntheticElement(tag, cls, text) {
  return {tag, cls, text, children: [], listeners: {}, dataset: {},
    append(...items) {this.children.push(...items);},
    setAttribute() {}, addEventListener(name, callback) {this.listeners[name] = callback;}};
}
for (const validated of [true, false]) {
  const holder = syntheticElement('div');
  const controls = new Map(['new-target', 'live-run-mode', 'open-run'].map(id => [id, syntheticElement('input')]));
  const modelControl = {focused: false, focus() {this.focused = true;}};
  const panel = {hidden: true};
  const state = {active: true, previewState: 'idle', busy: false, target: 'synthetic-current-target',
    scan: {resolved_ip: '192.0.2.10'}, stages: new Map(),
    result: validated ? {analyst: {model: 'synthetic-google', evidence: [], analysis: {
      summary: 'SYNTHETIC validated live assessment', recommended_actions: [], correlations: [], uncertainties: [],
    }}} : {ai_status: 'needs_review', ai_attempts: [{detail: 'SYNTHETIC rejected output'}]}};
  const forbidden = () => {throw new Error('Must not read or analyze unrelated stored evidence');};
  const env = {liveState: state, view: {host: ''}, content: holder, element: syntheticElement,
    currentAnalysis: forbidden, evidenceBasis: forbidden, analyzeTarget: forbidden,
    analysisStages: [], appendBatchReview: () => false, appendDecisionFrame() {},
    appendModelContextEffect() {}, appendQuotes() {}, appendInvestigation() {},
    runPanel: panel, providerSelect: modelControl, document: {getElementById: id => controls.get(id)}};
  new Function('env', `const {${Object.keys(env).join(',')}} = env; ${analystRenderer}; renderAnalyst();`)(env);
  const action = holder.children[0];
  const button = action.children.find(item => item.tag === 'button');
  assert.equal(button.disabled, false, 'Live evidence does not require a stored-host selection');
  assert.equal(button.text, 'Configure AI re-analysis · no scan');
  button.listeners.click();
  assert.equal(controls.get('new-target').value, state.target);
  assert.equal(controls.get('live-run-mode').value, 'reuse');
  assert.equal(panel.hidden, false);
  assert.equal(modelControl.focused, true);
  assert.equal(action.children.some(item => item.text === 'SYNTHETIC validated live assessment'), validated);
  assert.equal(action.children.some(item => item.text === 'SYNTHETIC rejected output'), !validated);
}
const targetAnalyzer = liveSource.slice(liveSource.indexOf('async function analyzeTarget('), liveSource.indexOf('function populateFindings()'));
const noConsentControls = new Map(['share-evidence', 'target-check-result', 'open-run'].map(id => [id, syntheticElement('input')]));
noConsentControls.get('share-evidence').checked = false;
const noConsentPanel = {hidden: true};
const deniedAnalysis = await new Function('view', 'document', 'runPanel', `${targetAnalyzer}; return analyzeTarget('synthetic-host', 'synthetic-run', 'google');`)(
  {assessment: {}}, {getElementById: id => noConsentControls.get(id)}, noConsentPanel,
);
assert.equal(deniedAnalysis.status, 'error');
assert.match(deniedAnalysis.error, /Confirm evidence sharing/);
assert.equal(noConsentPanel.hidden, false);
console.log('ANALYST: sequential requests, duplicate prevention, stop, failure, identity and citation checks; analyst queue safety passed');

const networkInsightsSource = readFileSync(new URL('../../vulnassess/ui/static/workflow-insights.js', import.meta.url), 'utf8');
const networkInsights = await import(`data:text/javascript;base64,${Buffer.from(networkInsightsSource).toString('base64')}`);
const networkStored = {hosts: [{ip: '192.0.2.1', services: [{port: 22, name: 'ssh'}]}], findings: [], scores: [], context: []};
const liveNetworkCase = {active: true, scan: {services: [{port: 7001, protocol: 'tcp', product: 'Oracle WebLogic admin httpd'}]}};
assert.deepEqual(networkInsights.buildInsightBrief({assessment: networkStored, live: liveNetworkCase}).networkServices,
  liveNetworkCase.scan.services, 'Live network highlights belong only to the live target');
assert.equal(networkInsights.buildInsightBrief({assessment: networkStored, live: {active: true}}).networkServices.length, 0,
  'Missing live evidence must not borrow a stored target service');
assert.equal(networkInsights.buildInsightBrief({assessment: networkStored, live: {active: true, previewState: 'running'}}).networkServices.length, 0,
  'Preview cannot present stored services as actual live evidence');
assert.equal(networkInsights.buildInsightBrief({assessment: networkStored}).networkServices[0].host_ip, '192.0.2.1');
const overviewNetworkSource = readFileSync(new URL('../../vulnassess/ui/static/workflow-overview.js', import.meta.url), 'utf8');
const networkOverview = await import(`data:text/javascript;base64,${Buffer.from(overviewNetworkSource).toString('base64')}`);
const networkDoc = globalThis.document;
try {
  globalThis.document = {createElement: syntheticElement};
  const networkHolder = syntheticElement('div');
  networkHolder.replaceChildren = function(...items) {this.children = items;};
  const networkBrief = networkInsights.buildInsightBrief({assessment: networkStored, live: {...liveNetworkCase, error: 'SYNTHETIC rejected'}});
  networkOverview.renderAssessmentOverview(networkHolder, networkBrief, () => {});
  const allText = item => [item.textContent || '', ...item.children.flatMap(allText)];
  assert.ok(allText(networkHolder).includes('AI network assessment'));
  assert.ok(allText(networkHolder).includes('7001/tcp · Oracle WebLogic admin httpd'));
  assert.equal(networkBrief.ai.summary, '', 'Rejected AI prose stays unavailable beside scanner observations');
} finally {
  globalThis.document = networkDoc;
}
console.log('NETWORK HIGHLIGHTS: target binding, preview isolation and rejected AI separation passed');
