import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../../vulnassess/ui/static/findings.js', import.meta.url), 'utf8');
const html = await readFile(new URL('../../vulnassess/ui/static/findings.html', import.meta.url), 'utf8');
const ids = [...html.matchAll(/id="([^"]+)"/g)].map(match => match[1]);

// Small DOM contract harness: all IDs come from the actual page, and unsafe
// HTML sinks fail immediately. No server, scanner or provider is involved.
class Element {
  constructor(tag) {
    this.tag = tag; this.children = []; this.listeners = {}; this.attributes = {};
    this.style = {}; this.value = ''; this.disabled = false; this.open = false;
    this.classList = {add: value => { this.className = value; }};
    this._text = '';
  }
  set innerHTML(_) { throw new Error('Unsafe HTML sink'); }
  set outerHTML(_) { throw new Error('Unsafe HTML sink'); }
  insertAdjacentHTML() { throw new Error('Unsafe HTML sink'); }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  append(...children) {
    this.children.push(...children);
    if (this.tag === 'select' && this.children.length === children.length) this.value = children[0]?.value ?? '';
  }
  replaceChildren(...children) { this.children = []; this._text = ''; this.append(...children); }
  addEventListener(event, listener) { (this.listeners[event] ??= []).push(listener); }
  emit(event, extra = {}) { for (const listener of this.listeners[event] ?? []) listener({preventDefault() {}, ...extra}); }
  setAttribute(key, value) { this.attributes[key] = value; }
  showModal() { this.open = true; }
  close() { this.open = false; this.emit('close'); }
  focus() { this.focused = true; }
  click() { this.emit('click'); }
  remove() { this.removed = true; }
}

async function page(data, {status = 200, reject = false, pending = false} = {}) {
  const elements = Object.fromEntries(ids.map(id => [id, new Element(id.endsWith('filter') || id === 'run-select' ? 'select' : 'div')]));
  for (const id of ['risk-filter', 'cve-filter', 'host-filter']) elements[id].value = 'all';
  elements.download.disabled = true;
  elements['run-select'].disabled = true;
  const requests = [], blobs = [], revoked = [], timers = [];
  let resolveFetch;
  const response = {ok: status === 200, json: async () => data};
  const context = vm.createContext({
    document: {getElementById: id => { assert.ok(elements[id], `Unknown page ID: ${id}`); return elements[id]; }, createElement: tag => new Element(tag), body: new Element('body')},
    window: {location: {href: 'http://localhost:8080/findings', origin: 'http://localhost:8080'}},
    URL: class extends URL {
      static createObjectURL(blob) { blobs.push(blob); return 'blob:synthetic'; }
      static revokeObjectURL(url) { revoked.push(url); }
    },
    Blob, setTimeout: callback => timers.push(callback),
    fetch: async (url, options) => {
      requests.push({url, options});
      if (reject) throw new Error('Synthetic network failure');
      if (pending) return new Promise(resolve => { resolveFetch = resolve; });
      return response;
    },
  });
  vm.runInContext(source, context);
  const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
  await flush();
  return {elements, requests, blobs, revoked, timers, context, finish: async () => { resolveFetch(response); await flush(); }};
}

const guidance = {source: 'Reviewed conditional guidance', meaning: 'Observed condition', scenario: 'Conditional only', prerequisites: ['Verify applicability'], impact: 'Not established', patch: ['Install vendor fix'], mitigations: ['Restrict access'], verify: ['Retain before/after evidence']};
const base = {tool: 'nikto', protocol: 'tcp', scores: [], guidance, observation_status: 'Scanner observation, not proof', evidence: '<script>alert(1)</script>\noriginal evidence', ai: []};
const data = {state: 'ready', capture_id: 'capture-test', target: 'Loopback', captured_at: '2026-10-22T10:00:00Z', ai_status: 'not_attempted', findings: [
  {...base, id: 'one', host: '127.0.0.1', port: 6379, title: '=HYPERLINK("bad")', priority: 90, band: 'Critical', cves: [{id: 'CVE-2022-0543', match_method: 'explicit'}], report_url: '/captures/capture-test/report#finding-1'},
  {...base, id: 'two', host: '127.0.0.2', port: 80, title: 'Unsupported header', priority: 30, band: 'Low', severity_basis_missing: true, cves: [{id: 'CVE-2000-1234', match_method: 'cpe_range'}], report_url: 'javascript:alert(1)'},
  {...base, id: 'three', host: '127.0.0.1', port: 81, title: 'Zero scored', priority: 0, band: 'Low', cves: []},
  {...base, id: 'four', host: '127.0.0.3', port: null, title: 'Unscored', priority: null, band: 'Unscored', cves: []},
  {...base, id: 'five', host: '127.0.0.2', title: 'Mixed associations', priority: 20, band: 'Medium', cves: [{id: 'CVE-2000-1111', match_method: 'explicit'}, {id: 'CVE-2000-2222', match_method: 'cpe_range'}]},
]};
const app = await page(data, {pending: true});
const el = app.elements;
assert.equal(el['finding-table'].attributes['aria-busy'], 'true');
assert.equal(el.download.disabled, true);
await app.finish();
assert.equal(app.requests.length, 1);
assert.equal(app.requests[0].url, '/api/vulnerability-findings');
assert.equal(app.requests[0].options.cache, 'no-store');
assert.equal(el['run-select'].disabled, true);
assert.match(el['run-meta'].textContent, /Latest completed live capture/);
assert.equal(el['metric-total'].textContent, '5');
assert.equal(el['metric-attention'].textContent, '1');
assert.equal(el['metric-cve'].textContent, '3');
assert.equal(el['metric-unscored'].textContent, '2');
assert.equal(el['finding-rows'].children.length, 5);
assert.equal(el['host-filter'].children.length, 4);
assert.match(el['distribution-track'].attributes['aria-label'], /Scanner-named.*: 2/);
assert.match(el['distribution-track'].attributes['aria-label'], /Candidate association.*: 1/);
el.search.value = 'cve-2022'; el.search.emit('input');
assert.match(el['result-count'].textContent, /^1 of 5/);
el['finding-rows'].children[0].emit('keydown', {key: 'Enter'});
assert.equal(el['detail-dialog'].open, true);
assert.ok(el['detail-body'].textContent.includes(base.evidence));
assert.match(el['detail-body'].textContent, /Install vendor fix/);
assert.match(el['detail-body'].textContent, /Retain before\/after evidence/);
assert.equal(el['trace-link'].href, 'http://localhost:8080/captures/capture-test/report#finding-1');
el.dismiss.emit('click');
assert.equal(el['detail-dialog'].open, false);
assert.equal(el['finding-rows'].children[0].focused, true);
el.download.emit('click');
const csv = await app.blobs[0].text();
assert.ok(csv.includes('"\'=HYPERLINK(""bad"")"'));
assert.ok(csv.includes(base.evidence));
assert.ok(!csv.includes('Unsupported header'));
app.timers.forEach(callback => callback());
assert.deepEqual(app.revoked, ['blob:synthetic']);
for (const prefix of ['=', '+', '-', '@', '  =', '\t=', '\r', '\n', '\u0001+']) {
  assert.ok(vm.runInContext(`csvCell(${JSON.stringify(prefix + 'value')})`, app.context).startsWith('"\''), `Unsafe prefix ${JSON.stringify(prefix)}`);
}
assert.equal(vm.runInContext('csvCell(null)', app.context), '""');
assert.equal(vm.runInContext('csvCell(0)', app.context), '"0"');
el.reset.emit('click');
el['cve-filter'].value = 'candidate'; el['cve-filter'].emit('change');
assert.match(el['result-count'].textContent, /^2 of 5/);
el['host-filter'].value = '127.0.0.2'; el['host-filter'].emit('change');
el['risk-filter'].value = 'unscored'; el['risk-filter'].emit('change');
assert.match(el['result-count'].textContent, /^1 of 5/);
el['finding-rows'].children[0].emit('click');
assert.equal(el['trace-link'].href, '/workflow');
el.search.value = 'no matching finding'; el.search.emit('input');
assert.equal(el.download.disabled, true);
assert.match(el['finding-rows'].textContent, /No findings match/);
el.reset.emit('click');
el['cve-filter'].value = 'none'; el['cve-filter'].emit('change');
assert.match(el['result-count'].textContent, /^2 of 5/);
el.reset.emit('click');
el.search.value = '81'; el.search.emit('input');
assert.match(el['finding-rows'].textContent, /0\/100/);
for (const payload of [{state: 'empty', findings: [], message: 'No completed capture'}, {...data, findings: []}]) {
  const empty = await page(payload);
  assert.equal(empty.elements.download.disabled, true);
  assert.equal(empty.elements['metric-total'].textContent, '0');
  assert.match(empty.elements['finding-rows'].textContent, /No (completed live assessment|findings recorded)/);
}
for (const [payload, options] of [[{error: {message: 'Could not be verified'}}, {status: 409}], [null, {reject: true}], [{state: 'ready', findings: {}}, {}]]) {
  const failure = await page(payload, options);
  assert.equal(failure.elements.download.disabled, true);
  assert.equal(failure.elements.notice.className, 'error');
  assert.equal(failure.elements['metric-total'].textContent, '—');
  assert.match(failure.elements['finding-rows'].textContent, /Assessment unavailable/);
}
console.log('findings page contract checks passed');
