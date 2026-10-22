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
  window: { SpeechRecognition: Recognition, speechSynthesis: {cancel(){cancelled++;},speak(){spoken++;}},addEventListener(){} },
  CSS:{escape: value => value}, SpeechSynthesisUtterance: class {constructor(text){this.text = text;}},
  AbortController, setTimeout, clearTimeout,
  fetch: async () => { requests++; return {ok:true,json:async()=>({capture_id:'SYNTHETIC-capture',model:'SYNTHETIC AI',message:'Source selection',excerpts:[{reference:'B1:executive',text:'<script>literal scanner text</script>',section:'ai',citations:['E1'],batch:1}]})}; }
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
console.log('Helpy offline voice/transcript, consent and highlight contracts passed');
