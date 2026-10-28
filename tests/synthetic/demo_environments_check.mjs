import assert from 'node:assert/strict';
import {DEMO_ENVIRONMENTS, mountDemoEnvironments, demoFromHash} from '../../vulnassess/ui/static/demo-environments.js';

class Element {
  constructor(value = '') { this.value = value; this.hidden = false; this.disabled = false; this.textContent = ''; this.listeners = {}; this.attributes = {}; this.dataset = {}; }
  addEventListener(name, callback) { (this.listeners[name] ||= []).push(callback); }
  dispatchEvent(event) { for (const callback of this.listeners[event.type] || []) callback(event); }
  removeAttribute(name) { delete this[name]; }
  setAttribute(name, value) { this.attributes[name] = value; }
}
const ids = ['demo-environment', 'new-target', 'live-run-mode', 'demo-environment-description', 'open-demo-environment', 'analyst-provider', 'share-evidence'];
const elements = Object.fromEntries(ids.map(id => [id, new Element()]));
const choices = ['harbordesk', 'office', 'iot'].map(id => { const el = new Element(); el.dataset.demoChoice = id; return el; });
globalThis.document = {getElementById: id => elements[id], querySelectorAll: () => choices};
globalThis.fetch = () => { throw new Error('Presets must not launch network operations'); };
elements['new-target'].value = 'existing-custom-target';
elements['analyst-provider'].value = 'ollama';
elements['share-evidence'].checked = false;
let busy = false;
const checked = [];
const controller = mountDemoEnvironments({getBusy: () => busy, onSelect: demo => checked.push(demo.target)});
const choose = id => { elements['demo-environment'].value = id; elements['demo-environment'].dispatchEvent(new Event('change')); };
assert.equal(DEMO_ENVIRONMENTS.length, 3);
assert.equal(demoFromHash('#demo-environments'), '');
for (const id of ['harbordesk', 'office', 'iot']) assert.equal(demoFromHash(`#demo-environments=${id}`), id);
for (const hash of ['#demo-environments=unknown', '#demo-environments=__proto__', '#demo-environments=http://outside.test', '#demo-environments=office&run=true', '#node=context']) assert.equal(demoFromHash(hash), null);
assert.equal(elements['new-target'].value, 'existing-custom-target');
assert.equal(elements['open-demo-environment'].hidden, true);
assert.equal(checked.length, 0);
for (const demo of DEMO_ENVIRONMENTS) {
  elements['live-run-mode'].value = 'self';
  choices.find(button => button.dataset.demoChoice === demo.id).dispatchEvent(new Event('click'));
  assert.equal(choices.find(button => button.dataset.demoChoice === demo.id).attributes['aria-pressed'], 'true');
  assert.equal(choices.filter(button => button.attributes['aria-pressed'] === 'true').length, 1);
  assert.equal(elements['new-target'].value, demo.target);
  assert.equal(elements['live-run-mode'].value, 'new');
  assert.equal(elements['open-demo-environment'].href, demo.url);
  assert.equal(elements['open-demo-environment'].hidden, false);
  assert.ok(elements['demo-environment-description'].textContent.includes(demo.target));
  assert.equal(elements['demo-environment-description'].textContent.includes('Docker Desktop'), demo.id !== 'harbordesk');
  assert.equal(elements['analyst-provider'].value, 'ollama');
  assert.equal(elements['share-evidence'].checked, false);
  assert.equal(checked.at(-1), demo.target);
}
assert.deepEqual(checked, ['http://127.0.0.1:8787/', '127.0.0.2', '127.0.0.3']);
assert.ok(!DEMO_ENVIRONMENTS.find(item => item.id === 'office').target.includes('http'));
assert.ok(!DEMO_ENVIRONMENTS.find(item => item.id === 'iot').target.includes('8798'));
elements['new-target'].value = '192.0.2.44';
elements['new-target'].dispatchEvent(new Event('input'));
assert.equal(elements['demo-environment'].value, '');
assert.equal(elements['open-demo-environment'].hidden, true);
assert.equal(elements['open-demo-environment'].href, undefined);
for (const invalid of ['__proto__', 'constructor', 'http://outside.invalid', 'unknown', '']) {
  const count = checked.length;
  choose(invalid);
  assert.equal(elements['new-target'].value, '192.0.2.44');
  assert.equal(elements['open-demo-environment'].hidden, true);
  assert.equal(checked.length, count);
}
choose('office');
const count = checked.length;
busy = true;
controller.setBusy(true);
assert.equal(elements['demo-environment'].disabled, true);
assert.ok(choices.every(button => button.disabled));
choose('harbordesk');
assert.equal(elements['demo-environment'].value, 'office');
assert.equal(elements['new-target'].value, '127.0.0.2');
assert.equal(checked.length, count);
busy = false;
controller.setBusy(false);
assert.equal(elements['demo-environment'].disabled, false);
for (const mode of ['self', 'reuse', 'saved']) {
  choose('iot');
  elements['live-run-mode'].value = mode;
  elements['live-run-mode'].dispatchEvent(new Event('change'));
  assert.equal(elements['demo-environment'].value, '');
  assert.equal(elements['open-demo-environment'].hidden, true);
}
console.log('PASS: three demo presets, exact targets, scope callback, custom editing, busy guard and consent preservation');
