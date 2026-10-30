import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source = readFileSync('vulnassess/ui/static/workflow.js', 'utf8').replaceAll('\r\n', '\n');
const initialization = source.slice(source.indexOf('let providerChoiceChanged = false;'), source.indexOf("document.getElementById('allow-fallback').addEventListener('change', updateCloudConsent);"));
const consentFunction = source.slice(source.indexOf('function updateCloudConsent() {'), source.indexOf('let providerChoiceChanged = false;'));
const html = readFileSync('vulnassess/ui/static/workflow.html', 'utf8');
const shareInput = html.match(/<input id="share-evidence"[^>]*>/)[0];
assert.doesNotMatch(shareInput, /checked/);
assert.match(html, /aria-describedby="analyst-provider-hint"/);
assert.match(html, /selected cloud analyst/);
const providerMarkup = html.match(/<select id="analyst-provider"[^>]*>(.*?)<\/select>/s)[1];
assert.doesNotMatch(providerMarkup, /disabled/);
assert.match(providerMarkup, /<option value="google" selected>Google Gemini<\/option>/);
assert.match(source, /if \(\(provider !== 'ollama' \|\| localFallback\) && !document.getElementById\('share-evidence'\).checked\)/);
assert.match(source, /if \(cloudFallback && !document.getElementById\('share-evidence'\).checked\)/);

async function check(scenario) {
  const options = ['ollama', 'google', 'groq', 'groq_qwen', 'openrouter'].map(value => ({value, label: value, disabled: false}));
  const select = {value: 'google', options, disabled: false, addEventListener(name, fn) {this[name] = fn;}};
  const elements = {
    'analyst-provider-hint': {textContent: ''},
    'share-evidence': {checked: false},
    'allow-fallback': {checked: true},
    'cloud-consent': {hidden: false},
  };
  let resolve;
  const pending = new Promise(done => {resolve = done;});
  const liveState = {busy: false};
  const runState = {busy: false};
  const view = {analyses: new Map()};
  const calls = [];
  const context = vm.createContext({providerSelect: select, liveState, runState, view,
    document: {getElementById: id => elements[id]},
    fetch: (url, config) => {calls.push({url, config}); return pending;},
  });
  vm.runInContext(consentFunction + initialization, context);
  if (scenario === 'choice') {select.value = 'ollama'; select.change();}
  if (scenario === 'same-choice') select.change();
  if (scenario === 'changed-value') select.value = 'groq';
  if (scenario === 'live-busy') liveState.busy = true;
  if (scenario === 'run-busy') runState.busy = true;
  if (scenario === 'analysis-busy') view.analyses.set('host', {status: 'running'});
  if (scenario === 'disabled') select.disabled = true;
  const providers = options.filter(option => option.value !== 'ollama').map(option => ({id: option.value, configured: scenario === 'none' ? false : option.value === 'google'}));
  resolve({ok: scenario !== 'failed', json: async () => ({providers, recommended: scenario === 'invalid-recommendation' ? 'unknown' : scenario === 'none' || scenario === 'same-choice' ? 'ollama' : 'google'})});
  for (let i = 0; i < 20; i++) await Promise.resolve();
  assert.equal(select.value, ['choice', 'none'].includes(scenario) ? 'ollama' : scenario === 'changed-value' ? 'groq' : 'google', scenario);
  assert.ok(options.every(option => !option.disabled), 'Every provider remains selectable regardless of credentials');
  assert.equal(elements['share-evidence'].checked, false, 'Discovery never grants consent');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/api/analyst-providers');
  assert.equal(calls[0].config.cache, 'no-store');
  if (scenario === 'failed') assert.match(elements['analyst-provider-hint'].textContent, /could not be loaded/);
  else {
    assert.match(elements['analyst-provider-hint'].textContent, /availability has not been checked/);
    assert.match(elements['analyst-provider-hint'].textContent, /API key missing/);
  }
}
for (const scenario of ['default', 'choice', 'same-choice', 'changed-value', 'live-busy', 'run-busy', 'analysis-busy', 'disabled', 'none', 'failed', 'invalid-recommendation']) await check(scenario);

// Exercise the actual render functions without loading the page or calling a model.
function element(tag, className = '', textContent = '') {
  return {tag, className, textContent, children: [], dataset: {},
    append(...items) {this.children.push(...items);},
    replaceChildren() {this.children = [];},
    setAttribute() {}, addEventListener() {},
  };
}
function renderedText(node) {
  return [node.textContent, ...node.children.map(renderedText)].join('\n');
}
const attempts = [
  {provider: 'google', status: 'unavailable', detail: 'Google Gemini returned HTTP 503: service unavailable'},
  {provider: 'ollama', status: 'timeout', detail: 'Ollama timed out after 45s'},
];
const helper = source.slice(source.indexOf('function appendProviderAttempts('), source.indexOf('function renderLiveResult()'));
const analystRenderer = source.slice(source.indexOf('function renderAnalyst()'), source.indexOf('async function analyzeTarget('));
const liveRenderer = source.slice(source.indexOf('function renderLiveResult()'), source.indexOf('function showAssessmentRail()'));
for (const location of ['top-level', 'summary', 'stored-error', 'stored-success', 'batch-success']) {
  const content = element('main');
  const liveHolder = element('section');
  const result = {ai_attempts: attempts};
  const liveState = {active: !location.startsWith('stored'), previewState: 'idle', busy: false, target: 'Office', stages: new Map(), result};
  if (location === 'summary') {delete result.ai_attempts; result.assessment_summary = {ai_attempts: attempts};}
  if (location === 'batch-success') result.analyst = {batches: [{}], ai_attempts: attempts};
  const stored = {status: 'error', error: 'Final Ollama failure', ai_attempts: attempts};
  if (location === 'stored-success') Object.assign(stored, {status: 'complete', result: {ai_attempts: attempts, analysis: {summary: 'Validated', recommended_actions: [], uncertainties: []}, evidence: []}});
  const context = vm.createContext({element, content, liveState, providerSelect: {}, view: {host: 'Office'}, analysisStages: [],
    currentAnalysis: () => stored, evidenceBasis: () => null,
    appendBatchReview: (_holder, analyst) => !!analyst.batches,
    appendDecisionFrame() {}, appendModelContextEffect() {}, appendInvestigation() {},
    appendLiveSummary(holder, summary) {if (summary) context.appendProviderAttempts(holder, summary.ai_attempts);},
    document: {getElementById: () => liveHolder},
  });
  vm.runInContext(helper + analystRenderer + liveRenderer, context);
  context.renderAnalyst();
  const text = renderedText(content);
  for (const attempt of attempts) assert.ok(text.includes(attempt.detail), `${location}: analyst shows ${attempt.provider} detail`);
  assert.match(text, /Google Gemini: unavailable/);
  assert.match(text, /Local Ollama: timeout/);
  context.renderLiveResult();
  const liveText = renderedText(liveHolder);
  for (const attempt of attempts) {
    assert.ok(liveText.includes(attempt.detail), `${location}: live result shows ${attempt.provider} detail`);
    assert.equal(liveText.split(attempt.detail).length - 1, 1, 'Each attempt is shown once');
  }
}
{
  const start = source.indexOf('  const accept = event => {', source.indexOf('async function startLiveRun('));
  const end = source.indexOf('\n  try {\n    const response = await fetch(', start);
  assert.ok(start > 0 && end > start);
  const inspected = [];
  const liveState = {stages: new Map()};
  const view = {node: 'analyst'};
  const context = vm.createContext({target: '127.0.0.2', liveState, view,
    liveStages: [['generation'], ['validation']],
    renderLiveProgress() {}, renderLiveExecution() {}, renderGraph() {}, renderLiveResult() {},
    refreshLatestReportLink() {}, showAssessmentRail() {}, isLiveAssessmentResult: () => true,
    renderInspector() {inspected.push(liveState.stages.get('generation')?.detail || liveState.scan?.target || liveState.result?.ai_status);},
  });
  vm.runInContext(source.slice(start, end) + '\nthis.accept = accept;', context);
  context.accept({type: 'stage', stage: 'generation', state: 'running', detail: 'Batch 16 is generating'});
  assert.equal(inspected.at(-1), 'Batch 16 is generating', 'The open inspector updates while generation is running');
  context.accept({type: 'stage', stage: 'validation', state: 'complete', detail: 'Citations validated'});
  context.accept({type: 'scan', scan: {services: [], target: '127.0.0.2'}});
  context.accept({type: 'result', result: {ai_status: 'validated'}});
  assert.equal(inspected.length, 4, 'Every accepted stage, scan and result refreshes the open inspector');
  view.node = null;
  context.accept({type: 'stage', stage: 'generation', state: 'running', detail: 'Next batch'});
  assert.equal(inspected.length, 4, 'A closed inspector stays closed');
}
{
  const nodes = new Map();
  const scan = {resolved_ip: '127.0.0.2', finding_count: 21, assessment_summary: {priorities: Array(21).fill({})}};
  const liveState = {active: true, previewState: 'idle', target: 'Office', scan};
  const select = {replaceChildren() {}};
  const context = vm.createContext({liveState, hostSelect: select, findingSelect: select, element,
    document: {getElementById(id) {if (!nodes.has(id)) nodes.set(id, {}); return nodes.get(id);}},
  });
  const start = source.indexOf('function syncLiveSelection()');
  vm.runInContext(source.slice(start, source.indexOf('function renderLiveExecution()', start)), context);
  context.syncLiveSelection();
  assert.match(nodes.get('record-summary').textContent, /21 scored/, 'Scored evidence is visible before AI finishes');
  delete scan.assessment_summary;
  context.syncLiveSelection();
  assert.match(nodes.get('record-summary').textContent, /priorities pending/, 'Missing counts do not claim zero scored findings');
}
console.log('PASS provider choices, consent, provider errors, live inspector updates and pending score counts');
