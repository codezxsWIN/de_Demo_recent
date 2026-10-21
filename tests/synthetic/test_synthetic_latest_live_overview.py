"""Stored overview must point to the newest verified live report, not mix its data."""

import shutil
import subprocess
from pathlib import Path


def test_stored_overview_surfaces_latest_separate_capture():
    node = shutil.which("node")
    assert node is not None
    script = r"""
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source = readFileSync('vulnassess/ui/static/workflow.js', 'utf8');
const helpers = source.slice(source.indexOf('async function refreshLatestReportLink()'), source.indexOf('function currentAnalysis()'));
function element(tag, className = '', text = '') {
  return {tag, className, textContent: String(text), children: [],
    append(...children) {this.children.push(...children)},
    prepend(child) {this.children.unshift(child)}};
}
const link = {hidden: true, href: ''};
const holder = element('section');
const saved = {capture_id: 'assessment-new', payload: {findings: [{title: 'SYNTHETIC header observation'}]}, result: {
  target: 'https://synthetic.example:4280/', scan_status: 'complete',
  finding_count: 8, ai_status: 'validated', services: [{port: 4280}],
  assessment_summary: {conclusion: 'SYNTHETIC result'},
}};
let renders = 0;
const context = {element, document: {getElementById: () => link},
  view: {assessment: {run: {run_id: 'synthetic-old'}}},
  liveState: {active: false}, renderGraph: () => {renders++},
  getRecord: async path => path === '/api/captures?page=1'
    ? {captures: [{capture_id: saved.capture_id, status: 'recorded'}]}
    : saved,
  encodeURIComponent,
};
vm.createContext(context);
vm.runInContext('let latestSavedCapture = null;\n' + helpers, context);
await context.refreshLatestReportLink();
assert.equal(renders, 1);
assert.equal(link.hidden, false);
assert.equal(link.href, '/captures/assessment-new/report');
context.renderLatestSavedCard(holder);
assert.equal(holder.children.length, 1);
const card = holder.children[0];
assert.match(card.children[2].textContent, /older stored run synthetic-old/);
assert.equal(card.children[3].children[2].children[0].textContent, '8');
assert.equal(card.children[5].children[0].textContent, 'SYNTHETIC header observation');
assert.equal(card.children.at(-1).href, '/captures/assessment-new/report');
console.log('Latest live assessment is visibly separate from stored run');
"""
    completed = subprocess.run(
        [node, "--input-type=module", "-"],
        input=script,
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
