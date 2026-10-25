import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {preserveWorkflowNavigation} from '../../vulnassess/ui/static/workflow-navigation.js';

function anchor(href, attributes = {}) {
  return {href, target: '', title: '', attributes,
    hasAttribute: name => name in attributes,
    getAttribute: name => attributes[name] ?? null,
    setAttribute: (name, value) => { attributes[name] = value; },
  };
}
for (const suffix of ['', '/report', '/report/download', '/report#findings']) {
  const link = anchor(`http://localhost:8765/captures/assessment-test_123${suffix}`, {rel: 'external'});
  let prevented = false;
  const event = {target: {closest: () => link}, preventDefault: () => { prevented = true; }};
  preserveWorkflowNavigation(event, 'http://localhost:8765');
  assert.equal(link.target, '_blank', 'Reports must not unload the live workflow');
  assert.match(link.attributes.rel, /noopener/);
  assert.match(link.attributes.rel, /noreferrer/);
  assert.match(link.attributes.rel, /external/);
  assert.equal(prevented, false, 'Keep native browser navigation and modifier behavior');
}
for (const path of ['/', '/findings', '/vulnerabilities', '/environment?capture=assessment-test', '/captures', '/captures?page=2', '/website-check']) {
  const link = anchor(`http://localhost:8765${path}`);
  preserveWorkflowNavigation({target: {closest: () => link}}, 'http://localhost:8765');
  assert.equal(link.target, '_blank', `${path} must leave the workflow mounted`);
  assert.match(link.attributes.rel, /noopener/);
}
for (const href of ['/workflow#node=report', '/workflow?run=demo', 'https://other.test/captures/assessment-a/report', 'javascript:alert(1)', '/api/live-assessment/events']) {
  const link = anchor(href);
  preserveWorkflowNavigation({target: {closest: () => link}}, 'http://localhost:8765');
  assert.equal(link.target, '', `Unrelated navigation unchanged: ${href}`);
}
const download = anchor('/captures/assessment-a/report/download', {download: ''});
preserveWorkflowNavigation({target: {closest: () => download}}, 'http://localhost:8765');
assert.equal(download.target, '');
preserveWorkflowNavigation({target: null}, 'http://localhost:8765');
const source = await readFile(new URL('../../vulnassess/ui/static/workflow.js', import.meta.url), 'utf8');
assert.ok(source.includes("document.addEventListener('click', preserveWorkflowNavigation, true)"), 'Handle links added later by scan progress updates');
console.log('Report navigation preserves the workflow page; native links and unrelated actions unchanged');
