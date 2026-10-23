// Offline UI contract: consent, editable transcription, safe rendering, source highlighting.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const nodes = new Map();
class Element {
  constructor() { this.checked = false; this.value = ''; this.children = []; this.dataset = {}; this.hidden = true; this.disabled = false; this.textContent = ''; this.classList = {toggle(){},add(){},remove(){}}; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren() { this.children = []; }
  setAttribute() {}
  focus() {}
  scrollIntoView() {}
  click() {}
  addEventListener() {}
  querySelectorAll() { return []; }
  set innerHTML(_) { throw new Error('Untrusted HTML must never be rendered'); }
}
const get = id => { if (!nodes.has(id)) nodes.set(id,new Element()); return nodes.get(id); };
get('helpy-panel').dataset.capture = 'SYNTHETIC-capture';
get('helpy-provider').value = 'google';
let recognitions = 0, requests = 0, cancelled = 0, spoken = 0, recognizer;
const supportedReply = (changes = {}) => ({ok:true,json:async()=>({status:'supported',capture_id:'SYNTHETIC-capture',model:'SYNTHETIC AI',message:'Source selection',excerpts:[{reference:'B1:executive',text:'<script>literal scanner text</script>',section:'ai',citations:['E1'],batch:1}],...changes})});
let fetchImpl = async () => supportedReply();
const windowEvents = new Map();
class Recognition {
  constructor() { recognitions++; recognizer = this; }
  start() { this.onstart(); }
  stop() { this.onend(); }
  abort() { this.onend?.(); }
}
const source = new Element();
const details = new Element(); details.tagName = 'DETAILS'; details.open = false;
source.parentElement = details;
source.classList.add = name => { source.highlight = name; };
const context = {
  document: {
    querySelector: selector => selector === '#helpy-panel' ? get('helpy-panel') : selector.startsWith('[data-claim-ref=') ? source : null,
    getElementById: get, createElement: () => new Element(), querySelectorAll: () => [],
    body: new Element()
  },
  window: { SpeechRecognition: Recognition, speechSynthesis: {cancel(){cancelled++;},speak(){spoken++;}},addEventListener(name,listener){windowEvents.set(name,listener);} },
  CSS:{escape: value => value}, SpeechSynthesisUtterance: class {constructor(text){this.text = text;}},
  AbortController, setTimeout, clearTimeout,
  fetch: async (...args) => { requests++; return fetchImpl(...args); }
};
vm.runInNewContext(readFileSync('vulnassess/ui/static/helpy.js','utf8'),context);
get('helpy-listen').onclick();
assert.equal(recognitions,0,'No microphone activation without consent');
get('helpy-voice-consent').checked = true;
get('helpy-question').value = 'Explain';
get('helpy-listen').onclick();
assert.equal(recognitions,1);
recognizer.onresult({results:[[{transcript:'this service'}]]});
assert.equal(get('helpy-question').value,'Explain this service');
assert.equal(requests,0,'Dictation never automatically submits a question');
await get('helpy-send').onclick();
assert.equal(requests,0,'Cloud sharing requires separate consent');
get('helpy-share').checked = true;
get('helpy-speak').checked = true;
await get('helpy-send').onclick();
assert.equal(requests,1);
assert.equal(spoken,1);
assert.equal(source.highlight,'helpy-selected');
assert.equal(details.open,true);
assert.equal(get('helpy-transcript').children.length,2);
const reply = get('helpy-transcript').children[1];
assert.equal(reply.children[2].textContent,'<script>literal scanner text</script>');
get('helpy-provider').onchange();
assert.equal(get('helpy-share').checked,false,'Changing providers resets sharing consent');
get('helpy-stop').onclick();
assert.ok(cancelled > 0);
get('helpy-provider').value = 'ollama';
function beginPending() {
  let finish, signal;
  fetchImpl = (_url, options) => {
    signal = options.signal;
    return new Promise(resolve => { finish = resolve; });
  };
  get('helpy-question').value = 'SYNTHETIC pending question';
  const promise = get('helpy-send').onclick();
  return {promise,signal,finish:reply => finish(reply)};
}
const spokenBeforeClear = spoken;
const pending = beginPending();
get('helpy-clear').onclick();
assert.equal(pending.signal.aborted,true,'Clear aborts the pending transport');
pending.finish(supportedReply());
await pending.promise;
assert.equal(get('helpy-transcript').children.length,0,'Clear must not be undone by an in-flight answer');
assert.equal(spoken,spokenBeforeClear,'A cleared reply must not be spoken');
assert.equal(get('helpy-send').disabled,false);

get('helpy-toggle').onclick();
const beforeClose = beginPending();
const transcriptBeforeClose = get('helpy-transcript').children.length;
get('helpy-close').onclick();
assert.equal(get('helpy-panel').hidden,true);
assert.equal(beforeClose.signal.aborted,true,'Close aborts the pending transport');
beforeClose.finish(supportedReply());
await beforeClose.promise;
assert.equal(get('helpy-transcript').children.length,transcriptBeforeClose,'Close suppresses late replies');
assert.equal(spoken,spokenBeforeClear,'A hidden panel must not speak a cancelled reply');

const beforeProviderChange = beginPending();
get('helpy-provider').value = 'google';
get('helpy-share').checked = true;
get('helpy-provider').onchange();
const transcriptBeforeProviderChange = get('helpy-transcript').children.length;
beforeProviderChange.finish(supportedReply());
await beforeProviderChange.promise;
assert.equal(beforeProviderChange.signal.aborted,true);
assert.equal(get('helpy-share').checked,false);
assert.equal(get('helpy-transcript').children.length,transcriptBeforeProviderChange);

get('helpy-provider').value = 'ollama';
get('helpy-clear').onclick();
const oldRequest = beginPending();
get('helpy-clear').onclick();
const newRequest = beginPending();
oldRequest.finish(supportedReply());
await oldRequest.promise;
assert.equal(get('helpy-send').disabled,true,'An obsolete request cannot unlock a newer request');
assert.equal(get('helpy-transcript').children.length,1);
newRequest.finish(supportedReply());
await newRequest.promise;
assert.equal(get('helpy-send').disabled,false);
assert.equal(get('helpy-transcript').children.length,2);

get('helpy-clear').onclick();
get('helpy-question').value = 'SYNTHETIC malformed reply';
fetchImpl = async () => supportedReply({excerpts:[{reference:'R:limits',section:'brief'}]});
await get('helpy-send').onclick();
assert.equal(get('helpy-transcript').children.length,2);
assert.equal(get('helpy-transcript').children[1].children[0].textContent,'Helpy · unavailable');
assert.ok(get('helpy-status').textContent.includes('invalid response'));

get('helpy-clear').onclick();
get('helpy-question').value = 'SYNTHETIC wrong assessment';
fetchImpl = async () => supportedReply({capture_id:'SYNTHETIC-other-capture'});
await get('helpy-send').onclick();
assert.ok(get('helpy-status').textContent.includes('Assessment mismatch'));
assert.equal(get('helpy-transcript').children[1].children[0].textContent,'Helpy · unavailable');

get('helpy-clear').onclick();
get('helpy-question').value = 'SYNTHETIC provider failure';
fetchImpl = async () => ({ok:false,json:async()=>({error:'SYNTHETIC provider unavailable'})});
await get('helpy-send').onclick();
assert.equal(get('helpy-status').textContent,'SYNTHETIC provider unavailable');
assert.equal(get('helpy-send').disabled,false);

get('helpy-clear').onclick();
get('helpy-question').value = 'SYNTHETIC transport timeout';
fetchImpl = async () => { const error = new Error('SYNTHETIC timeout'); error.name = 'AbortError'; throw error; };
await get('helpy-send').onclick();
assert.ok(get('helpy-status').textContent.includes('timed out'));
assert.equal(get('helpy-send').disabled,false);

get('helpy-clear').onclick();
get('helpy-question').value = 'SYNTHETIC unsupported question';
fetchImpl = async () => supportedReply({status:'not_established',message:'SYNTHETIC not established',excerpts:[]});
await get('helpy-send').onclick();
assert.equal(get('helpy-transcript').children[1].children[1].textContent,'SYNTHETIC not established');

const beforePageHide = beginPending();
windowEvents.get('pagehide')();
const transcriptBeforePageHide = get('helpy-transcript').children.length;
beforePageHide.finish(supportedReply());
await beforePageHide.promise;
assert.equal(beforePageHide.signal.aborted,true);
assert.equal(get('helpy-transcript').children.length,transcriptBeforePageHide);
console.log('Helpy offline voice/transcript, consent, highlight, cancellation, race and response-validation contracts passed');
