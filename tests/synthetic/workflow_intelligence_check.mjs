import assert from 'node:assert/strict';
import {mountCachedIntelligence} from '../../vulnassess/ui/static/workflow-intelligence.js';
import {buildNodes, nodeDetails, nodeExecutionEntry} from '../../vulnassess/ui/static/workflow-data.js';

class Element {
  constructor(tag) {this.tag = tag; this.children = []; this.listeners = {}; this.value = ''; this.isConnected = true; this.textContent = '';}
  append(...items) {this.children.push(...items);}
  replaceChildren(...items) {this.children = items;}
  setAttribute() {}
  addEventListener(name, handler) {this.listeners[name] = handler;}
}
globalThis.document = {createElement: tag => new Element(tag)};
const calls = [];
globalThis.fetch = async (url, options) => {
  calls.push({url, options});
  return {ok: true, json: async () => url.includes('?') ? {
    state: 'cached', record: {nvd: {cvss31_base: 10}, epss: {epss: 0.99, score_date: '2026-10-23'}, kev_listed: true,
      kev: {requiredAction: 'Apply vendor updates', dueDate: '2022-04-18'},
      cpe_match: {returned: 1, total_results: 2, coverage: 'partial', fetched_at: '2026-10-25', notice: 'Applicability only; not a confirmed finding'}},
    cache: {feeds: [{feed: 'epss', status: 'stale', date: '2026-10-23'}]}, sources: {},
  } : {cve_ids: ['CVE-2022-0543'], cache: {feeds: [
    {feed: 'nvd', status: 'cached'}, {feed: 'epss', status: 'stale', date: '2026-10-23'},
    {feed: 'kev', status: 'missing'},
  ]}}};
};
const holder = new Element('div');
mountCachedIntelligence(holder);
for (let i = 0; i < 10; i++) await Promise.resolve();
const panel = holder.children[0];
const input = panel.children[2].children[0];
const button = panel.children[3];
const status = panel.children[4];
const output = panel.children[5];
assert.equal(input.value, 'CVE-2022-0543');
await button.listeners.click();
assert.ok(output.children.some(item => item.textContent === 'CVSS 3.1: 10'));
assert.ok(output.children.some(item => item.textContent.includes('EPSS scoring date: 2026-10-23')));
assert.ok(output.children.some(item => item.textContent.includes('stale')));
assert.ok(output.children.some(item => item.textContent.includes('1 of 2 criteria · partial')));
assert.ok(output.children.some(item => item.textContent.includes('not a confirmed finding')));
assert.ok(panel.children[1].textContent.includes('not evidence'));
assert.match(panel.children[6].textContent, /cache availability/i);
assert.match(panel.children[6].textContent, /does not establish use/);
const previous = calls.length;
input.value = 'https://arbitrary.invalid';
await button.listeners.click();
assert.equal(calls.length, previous, 'Invalid identifiers never become network requests');
assert.match(status.textContent, /valid CVE/);
assert.ok(calls.every(call => call.options.method == null && call.options.cache === 'no-store'));
for (const source of ['nvd', 'epss', 'kev']) {
  const scopedHolder = new Element('div');
  mountCachedIntelligence(scopedHolder, 'CVE-2022-0543', source);
  for (let i = 0; i < 30; i++) await Promise.resolve();
  const scopedPanel = scopedHolder.children[0];
  const rendered = scopedPanel.children[5].children.map(item => item.textContent).join('\n');
  assert.ok(scopedPanel.children[4].textContent.includes('cached publisher data'), 'Automatically loads a cached CVE');
  if (source === 'nvd') {
    assert.match(rendered, /CVSS 3.1: 10/);
    assert.match(rendered, /CPE Match: 1 of 2/);
    assert.ok(!rendered.includes('EPSS probability'));
  } else if (source === 'epss') {
    assert.match(rendered, /EPSS probability: 0.99/);
    assert.match(rendered, /next 30 days/);
    assert.ok(!rendered.includes('CPE Match'));
  } else {
    assert.match(rendered, /CISA KEV: Listed/);
    assert.match(rendered, /Required action: Apply vendor updates/);
    assert.match(rendered, /CISA due date: 2022-04-18/);
    assert.ok(!rendered.includes('EPSS probability'));
  }
}
const assessment = {findings: [], hosts: [], scores: [], enrichments: [], context: [], rationales: [],
  run: {summary: {}}, feeds_meta: [{feed: 'nvd', rows: 5, path: 'snapshot.json'}], feeds_meta_scope: 'run_snapshot'};
assert.match(buildNodes(assessment, null).find(node => node.id === 'nvd').status, /run usage unverified/);
assert.match(nodeDetails('nvd', assessment, null, null).message, /does not establish/);
for (const feed of ['nvd', 'epss', 'kev']) {
  for (const [state, detail, expected] of [
    ['complete', 'Checked 1 CVE IDs; 0 matched', 'Checked in this run'],
    ['skipped', 'No scanner-named CVE IDs to look up', 'Skipped in this run'],
    ['error', 'No operational intelligence cache available', 'Failed in this run'],
    ['running', 'Looking up CVEs', 'Checking in this run'],
  ]) {
    const entry = nodeExecutionEntry(new Map([[feed, {state, detail}]]), [feed]);
    assert.equal(entry.state, state);
    assert.equal(entry.detail, `${expected} · ${detail}`);
  }
  assert.equal(nodeExecutionEntry(new Map(), [feed]), undefined);
}
globalThis.fetch = async () => ({ok: true, json: async () => ({cve_ids: [], cache: {feeds: [
  {feed: 'nvd', status: 'cached'}, {feed: 'epss', status: 'fixture'}, {feed: 'kev', status: 'offline_snapshot'},
]}})});
for (const [feed, label] of [['nvd', 'cached'], ['epss', 'test data only'], ['kev', 'local snapshot']]) {
  const emptyHolder = new Element('div');
  mountCachedIntelligence(emptyHolder, '', feed);
  for (let i = 0; i < 10; i++) await Promise.resolve();
  assert.match(emptyHolder.children[0].children[6].textContent, new RegExp(`${feed.toUpperCase()}: ${label}`));
  assert.match(emptyHolder.children[0].children[4].textContent, /No operational CVEs cached/);
}
globalThis.fetch = async () => {throw new Error('Cache unavailable');};
const failedHolder = new Element('div');
mountCachedIntelligence(failedHolder, '', 'nvd');
for (let i = 0; i < 10; i++) await Promise.resolve();
assert.match(failedHolder.children[0].children[6].textContent, /availability: unavailable/);
console.log('Workflow intelligence viewer preserves source dates, cache status and reference-only boundaries');
