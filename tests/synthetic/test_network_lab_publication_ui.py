"""Exercise the actual publication controls without a browser or network."""

import shutil
import subprocess
from pathlib import Path


def test_report_links_keep_the_live_workspace_and_publication_never_scans():
    script = r"""
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync('vulnassess/ui/static/network-coverage.js','utf8');
const start=source.indexOf('function renderCoverage(suite)');
const end=source.indexOf('function refreshCoverage(',start);
assert.ok(start>=0 && end>start);
class Element {
  constructor(tag='div',text=''){this.tag=tag;this.textContent=text;this.children=[];this.events={};}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=children;}
  addEventListener(name,fn){this.events[name]=fn;}
  set innerHTML(_value){throw new Error('Use safe text nodes');}
}
const nodes={},calls=[];
const $=id=>nodes[id]??=new Element();
const el=(tag,text)=>new Element(tag,text);
const capture='assessment-lab-'+'a'.repeat(32);
const suite={id:'full-'+'b'.repeat(32),environment:'office',finished_at:'retained',
  coverage:{},checks:[],conditions:[],findings:[],ground_truth:{status:'unverified'}};
const linked={...suite,main_assessment:{status:'saved',capture_id:capture,run_id:'retained-run',snapshot_hash:'f'.repeat(64)}};
let response=linked;
const post=async(action,body)=>{calls.push([action,body]);return response;};
const setBusy=()=>{};
const render=new Function('$','el','post','setBusy','coverageTable','coverageEvidence',`
  let environment='office',currentCoverage;
  const date=value=>value,refresh=()=>{};
  ${source.slice(start,end)}
  return renderCoverage;
`)($,el,post,setBusy,()=>new Element('table'),()=>new Element('button'));
const all=node=>[node,...node.children.flatMap(all)];
render(linked);
const links=all(nodes['coverage-content']).filter(n=>n.tag==='a');
assert.equal(links.length,2);
assert.deepEqual(links.map(n=>n.href),[
  `/captures/${capture}/report`, `/vulnerabilities?capture=${capture}`]);
assert.ok(links.every(n=>n.target==='_blank'&&n.rel==='noopener'));
assert.equal(calls.length,0);
render({...linked,main_assessment:{status:'saved',capture_id:'https://evil.invalid/'}});
assert.equal(all(nodes['coverage-content']).filter(n=>n.tag==='a').length,0);
render(suite);
const button=all(nodes['coverage-content']).find(n=>n.tag==='button'&&n.events.click);
assert.ok(button);
await button.events.click();
assert.deepEqual(calls,[['publish',{assessment_id:suite.id}]]);
assert.equal(all(nodes['coverage-content']).filter(n=>n.tag==='a').length,2);
calls.length=0;
$('ai-provider').value='google';$('cloud-consent').checked=false;
render(linked);
let generate=all(nodes['coverage-content']).find(n=>n.tag==='button'&&n.textContent==='Generate full AI report');
await generate.events.click();
assert.equal(calls.length,0);
assert.match(nodes['coverage-ai-status'].textContent,/Confirm evidence sharing/);
$('cloud-consent').checked=true;
const report={capture_id:'assessment-SYNTHETIC-report',source_capture_id:capture,source_snapshot_hash:'f'.repeat(64),ai_status:'validated',provider:'google',model:'SYNTHETIC model not called',generated_at:'historical'};
response={...linked,ai_reports:[report]};
await generate.events.click();
assert.deepEqual(calls,[['report',{assessment_id:suite.id,provider:'google',cloud_consent:true}]]);
let full=all(nodes['coverage-content']).find(n=>n.tag==='a'&&n.textContent==='Open full AI report ↗');
assert.equal(full.href,`/captures/${report.capture_id}/report`);
assert.equal(full.target,'_blank');
for(const changed of [{...report,source_capture_id:'unrelated'}, {...report,source_snapshot_hash:'0'.repeat(64)}, {...report,capture_id:'https://evil.invalid'}]){
  render({...linked,ai_reports:[changed]});
  assert.equal(all(nodes['coverage-content']).filter(n=>n.tag==='a').length,2);
}
"""
    node = shutil.which("node")
    assert node, "Node is required for publication UI regression checks"
    result = subprocess.run(
        [node, "--input-type=module", "-"],
        input=script,
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
