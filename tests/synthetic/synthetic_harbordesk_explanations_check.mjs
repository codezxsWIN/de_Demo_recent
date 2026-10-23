// Synthetic pure-logic DOM checks. No socket, browser, scanner or real fetch is used.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const nodes = new Map();
const created = [];
let document;
class Node {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.listeners = new Map();
    this.attributes = new Map();
    this.dataset = {};
    this.className = '';
    this.value = 'Avery';
    this.open = false;
    this.isConnected = true;
    this.text = '';
    const classes = new Set();
    this.classList = {
      add: name => classes.add(name),
      remove: name => classes.delete(name),
      contains: name => classes.has(name)
    };
    created.push(this);
  }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(' '); }
  set innerHTML(_value) { throw new Error('Unsafe HTML rendering in explanation UI'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name); }
  addEventListener(name, listener) {
    const listeners = this.listeners.get(name) || [];
    listeners.push(listener); this.listeners.set(name, listeners);
  }
  click() {
    for (const listener of this.listeners.get('click') || []) {
      listener({target:this, currentTarget:this, preventDefault() {}});
    }
  }
  keyDown(key) {
    const result = {prevented:false,stopped:false};
    for (const listener of this.listeners.get('keydown') || []) {
      listener({
        key, target:this,
        preventDefault() { result.prevented = true; },
        stopPropagation() { result.stopped = true; }
      });
    }
    return result;
  }
  focus() { document.activeElement = this; }
  showModal() { this.open = true; }
  close() {
    this.open = false;
    for (const listener of this.listeners.get('close') || []) listener({target:this});
  }
  querySelector(selector) {
    if (selector === 'h1') { const heading = new Node('h1'); heading.textContent = 'Overview'; return heading; }
    return null;
  }
}
const byId = id => {
  if (!nodes.has(id)) { const node = new Node(); node.id = id; nodes.set(id, node); }
  return nodes.get(id);
};
const overview = byId('overview');
document = {
  body:new Node('body'), cookie:'', activeElement:null,
  getElementById:byId, createElement:tag => new Node(tag),
  querySelectorAll:selector => selector === '.panel' ? [overview] : []
};
let fetchCalls = 0;
let fakeFetch = async () => { throw new Error('Unexpected fetch in pure-logic test'); };
const context = vm.createContext({
  document, window:{addEventListener() {}}, location:{hash:''},
  console, AbortController, setTimeout, clearTimeout, URLSearchParams,
  fetch:(...args) => { fetchCalls++; return fakeFetch(...args); }
});
const source = readFileSync(new URL('../../labs/harbordesk/site.js', import.meta.url), 'utf8');
vm.runInContext(source, context);

const hostileText = '<img src=x onerror="synthetic-only">';
const syntheticCase = {
  id:'HD-99', name:`Synthetic ${hostileText}`, endpoint:'/synthetic-only',
  expected:'Synthetic expected proof', current_scanner_coverage:'Synthetic verifier only',
  category:'network',
  explanation:{
    category:'Synthetic category', meaning:hostileText,
    scenario:'Synthetic scenario', impact:'Synthetic impact',
    patch:['Synthetic fix'], verify:['Synthetic fix check'],
    prerequisites:['Synthetic prerequisite'], source:'Synthetic source; not evidence'
  }
};
context.rememberExplanationCases({cases:[syntheticCase]});
const card = context.explanationCard(syntheticCase);
assert.equal(card.tagName, 'BUTTON');
assert.equal(card.type, 'button');
assert.equal(card.getAttribute('aria-haspopup'), 'dialog');
assert.equal(card.getAttribute('aria-controls'), 'case-explanation');

await context.openExplanation('HD-99', card);
assert.equal(byId('case-explanation').open, true);
assert.equal(document.activeElement, byId('explanation-close'));
for (const heading of ['In plain English','Why it matters','How it happens','What a check should show','How to fix it','How to confirm the fix']) {
  assert.ok(byId('explanation-body').textContent.includes(heading));
}
assert.ok(byId('explanation-title').textContent.includes(hostileText));
assert.ok(byId('explanation-body').textContent.includes(hostileText));
assert.equal(created.filter(node => node.tagName === 'IMG').length, 0);
assert.equal(fetchCalls, 0);

byId('explanation-close').click();
assert.equal(byId('case-explanation').open, false);
assert.equal(document.activeElement, card);
assert.equal(document.body.classList.contains('explanation-open'), false);

await context.openExplanation('HD-99', card);
assert.deepEqual(byId('case-explanation').keyDown('Enter'), {prevented:false,stopped:false});
assert.equal(byId('case-explanation').open, true);
assert.deepEqual(byId('case-explanation').keyDown('Escape'), {prevented:true,stopped:true});
assert.equal(byId('case-explanation').open, false);
assert.equal(document.activeElement, card);

byId('explanation-body').scrollTop = 400;
await context.openExplanation('HD-99', card);
assert.equal(byId('explanation-body').scrollTop, 0);
byId('explanation-close').click();

context.rememberExplanationCases({cases:[{
  ...syntheticCase, id:'HD-98', explanation:{...syntheticCase.explanation, patch:[]}
}]});
await context.openExplanation('HD-98', card);
assert.ok(byId('explanation-body').textContent.includes('Missing complete reviewed explanation for HD-98'));
assert.ok(byId('explanation-body').children[0].className.includes('error'));
byId('explanation-close').click();

const response = data => ({ok:true,status:200,text:async () => JSON.stringify(data)});
fakeFetch = async path => {
  assert.equal(path, '/__lab__/ground-truth');
  return response({cases:[syntheticCase]});
};
await context.openExplanation('HD-97', card);
assert.ok(byId('explanation-body').textContent.includes('Missing vulnerability case HD-97'));
byId('explanation-close').click();

let finishFetch;
fakeFetch = () => new Promise(resolve => { finishFetch = resolve; });
const pending = context.openExplanation('HD-96', card);
byId('explanation-close').click();
finishFetch(response({cases:[{...syntheticCase,id:'HD-96'}]}));
await pending;
assert.equal(byId('case-explanation').open, false);
assert.equal(document.activeElement, card);

const oldRequest = context.openExplanation('HD-95', card);
const finishOldRequest = finishFetch;
byId('explanation-close').click();
await context.openExplanation('HD-99', card);
finishOldRequest(response({cases:[{...syntheticCase,id:'HD-95',name:'Stale synthetic case'}]}));
await oldRequest;
assert.equal(byId('explanation-title').textContent, syntheticCase.name);
assert.equal(byId('case-explanation').open, true);
byId('explanation-close').click();
console.log('9 explanation interaction checks passed');
