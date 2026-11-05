"""Render saved AI only after a server validation bound to the displayed case."""

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = r"""
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
globalThis.fetch=()=>{throw new Error('Network forbidden in synthetic UI tests');};
const source=readFileSync('vulnassess/ui/static/network-live.js','utf8');
const start=source.indexOf('function renderAI()');
const end=source.indexOf("for(const e of ['office','iot'])");
assert.ok(start>=0&&end>start);
const actual=source.slice(start,end);
class Element {
  constructor(tag='div',text=''){this.tag=tag;this.textContent=text;this.children=[];}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=children;}
  setAttribute(){}
  get firstChild(){return this.children[0];}
  set innerHTML(_value){throw new Error('Content must remain text');}
}
const text=node=>[node.textContent,...node.children.map(text)].join('\n');
const makeCase=(sha256='a'.repeat(64))=>({
  id:'live-'+'1'.repeat(32),sha256,action:'ftp-anonymous',finished_at:'historical',findings:[],
  ai:{status:'validated_selection',provider:'offline',model:'test',generated_at:'historical',
    facts_sha256:'f'.repeat(64),sections:{observations:[{reference:'observation',
      text:'SAVED_AI_ONLY: The recorded same-endpoint retest is complete.'}]}}
});
const validation=(item,status='current')=>({[item.id]:{status,case_sha256:item.sha256,
  facts_sha256:'f'.repeat(64)}});
const build=new Function('initial','receive',`
  let selected=initial.selected,cases=[],environment='office',refreshing=false,paused=false;
  let packets=[],showWindow=false,aiValidations=initial.validations||{},aiProgress=null;
  const nodes={};
  const $=id=>nodes[id]??=(new initial.Element());
  const el=(tag,text)=>new initial.Element(tag,text);
  const document={hidden:false,querySelectorAll:()=>[]},location={hash:''};
  const operations={office:[['ftp-anonymous','FTP']],iot:[['mqtt-exchange','MQTT']]};
  const time=value=>value,date=value=>value;
  const json=receive,renderTopology=()=>{},renderPackets=()=>{};
  const renderCase=()=>renderAI();
  ${actual}
  return {renderAI,refresh,choose,nodes,setSelected:value=>{selected=value;},setProgress:value=>{aiProgress=value;}};
`);
const harness=(item,validations={},receive=async()=>({investigations:[item]}))=>
  build({selected:item,validations,Element},receive);
const hidden=ui=>{
  assert.equal(text(ui.nodes['ai-answer']),'');
  assert.match(ui.nodes['ai-status'].textContent,/Re-explain the current evidence/);
  assert.doesNotMatch(ui.nodes['ai-status'].textContent,/validated|SAVED_AI_ONLY/);
};
const shown=ui=>{
  assert.match(text(ui.nodes['ai-answer']),/SAVED_AI_ONLY/);
  assert.match(ui.nodes['ai-status'].textContent,/evidence selections validated/);
};
"""


def run_node(script: str) -> None:
    node = shutil.which("node")
    assert node is not None, "MISSING: node for saved-AI freshness regressions"
    completed = subprocess.run(
        [node, "--input-type=module", "-"],
        input=HARNESS + script,
        cwd=ROOT,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_saved_ai_requires_current_validation_and_matching_case_hash() -> None:
    run_node(r"""
const item=makeCase(),before=JSON.stringify(item);
const mismatched=validation({...item,sha256:'b'.repeat(64)});
const wrongCase={'different-id':validation(item)[item.id]};
for(const map of [{},validation(item,'stale'),validation(item,'not_requested'),
  validation(item,'invalid'),
  mismatched,wrongCase,{[item.id]:{status:'current'}}]){
  const ui=harness(item,map);ui.renderAI();hidden(ui);
}
for(const sha256 of [undefined,null,'']){
  const missingHash={...item,sha256};
  const ui=harness(missingHash,validation(missingHash));ui.renderAI();hidden(ui);
}
const ui=harness(item,validation(item));ui.renderAI();shown(ui);
assert.equal(JSON.stringify(item),before);
// A failed/unknown AI result cannot be promoted by a current validation entry.
const failed={...item,ai:{...item.ai,status:'failed'}};
const unavailable=harness(failed,validation(failed));unavailable.renderAI();hidden(unavailable);
""")


def test_failed_request_is_visible_without_erasing_a_previous_valid_explanation() -> None:
    run_node(r"""
const item=makeCase();
item.ai_attempts=[{provider:'ollama',stage:'generate',status:'failed',finished_at:'failed-later'}];
const ui=harness(item,validation(item));ui.renderAI();shown(ui);
assert.match(ui.nodes['ai-attempt-summary'].textContent,/response generation.*failed/);
assert.match(ui.nodes['ai-attempt-summary'].textContent,/original generation date/);
assert.match(ui.nodes['ai-status'].textContent,/historical/);
""")


def test_first_failed_request_is_not_presented_as_no_request() -> None:
    run_node(r"""
const item=makeCase();item.ai={status:'not_requested'};
item.ai_attempts=[{provider:'ollama',stage:'validate',status:'failed',finished_at:'retained'}];
const ui=harness(item);ui.renderAI();
assert.match(ui.nodes['ai-status'].textContent,/latest AI request failed/);
assert.doesNotMatch(ui.nodes['ai-status'].textContent,/No AI request/);
assert.equal(text(ui.nodes['ai-answer']),'');
""")


def test_identical_reference_normalisation_is_disclosed() -> None:
    run_node(r"""
const item=makeCase();item.ai.normalisation={duplicate_references_removed:{observations:2}};
const ui=harness(item,validation(item));ui.renderAI();shown(ui);
assert.match(ui.nodes['ai-attempt-summary'].textContent,/2 repeated identical evidence reference/);
assert.match(ui.nodes['ai-attempt-summary'].textContent,/no new claims were supplied/);
""")


def test_status_poll_does_not_erase_actual_generation_progress() -> None:
    run_node(r"""
const item=makeCase();item.ai={status:'not_requested'};
const ui=harness(item,{},async()=>({investigations:[item],ai_progress:{running:true,case_id:item.id,stage:'generate',provider:'ollama'}}));
await ui.refresh();
assert.match(ui.nodes['ai-status'].textContent,/ollama.*response generation.*in progress/);
assert.doesNotMatch(ui.nodes['ai-status'].textContent,/No AI request/);
ui.setProgress({running:false});ui.renderAI();
assert.match(ui.nodes['ai-status'].textContent,/No AI request/);
""")


def test_poll_replaces_validation_map_and_removes_previously_displayed_ai() -> None:
    run_node(r"""
const item=makeCase(),before=JSON.stringify(item);
let payload={investigations:[item],ai_validations:validation(item)};
const ui=harness(item,{},async()=>payload);
ui.renderAI();hidden(ui);
await ui.refresh();shown(ui);
payload={investigations:[item],ai_validations:validation(item,'stale')};
await ui.refresh();hidden(ui);
payload={investigations:[item],ai_validations:validation(item)};
await ui.refresh();shown(ui);
payload={investigations:[item]};
await ui.refresh();hidden(ui);
assert.equal(JSON.stringify(item),before);
""")


def test_new_explanation_waits_for_server_validation_of_its_new_case_hash() -> None:
    run_node(r"""
const old=makeCase(),fresh=makeCase('b'.repeat(64));
const ui=harness(old,validation(old),async()=>({investigations:[fresh],
  ai_validations:validation(fresh)}));
ui.renderAI();shown(ui);
// Mirrors an explanation response: it replaces selected, not server validation.
ui.setSelected(fresh);ui.renderAI();hidden(ui);
await ui.refresh();shown(ui);
""")


def test_failed_refresh_clears_the_last_validation() -> None:
    run_node(r"""
const item=makeCase();
const ui=harness(item,validation(item),async()=>{throw new Error('Offline status');});
ui.renderAI();shown(ui);
await ui.refresh();hidden(ui);
""")


def test_environment_change_clears_validation_before_the_next_poll() -> None:
    run_node(r"""
const item=makeCase();let finish;
const ui=harness(item,validation(item),()=>new Promise(resolve=>{finish=resolve;}));
ui.renderAI();shown(ui);
ui.choose('iot');
ui.setSelected(item);ui.renderAI();hidden(ui);
finish({investigations:[],ai_validations:{}});
await new Promise(resolve=>setImmediate(resolve));
hidden(ui);
""")
