import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const load = async file => {
  const source = readFileSync(new URL(`../../vulnassess/ui/static/${file}`, import.meta.url), 'utf8');
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
};
const {EDGES, NODE_SPECS} = await load('workflow-data.js');
const {PREVIEW_SCENARIOS} = await load('workflow-preview.js');
const nodeIds = new Set(NODE_SPECS.map(node => node.id));
const edgeIds = new Set([...EDGES.map(edge => `${edge.from}:${edge.to}`), 'context:analyst']);

assert.deepEqual(Object.keys(PREVIEW_SCENARIOS), ['light', 'web', 'noWeb', 'modelError', 'denied']);
for (const [name, scenario] of Object.entries(PREVIEW_SCENARIOS)) {
  assert.ok(scenario.label && scenario.context && scenario.steps.length, name);
  assert.equal(new Set(scenario.steps.map(step => step.id)).size, scenario.steps.length, name);
  for (const step of scenario.steps) {
    assert.ok(nodeIds.has(step.node), `${name}: unknown node ${step.node}`);
    assert.ok(step.detail.startsWith('Simulated:') || step.detail.startsWith('Simulated failure:') || step.detail.startsWith('Skipped:'), `${name}: unlabeled simulation`);
    assert.ok(['complete', 'skipped', 'error'].includes(step.outcome), `${name}: invalid outcome`);
    for (const edge of step.edges) assert.ok(edgeIds.has(edge), `${name}: unknown edge ${edge}`);
    if (step.outcome === 'skipped') assert.equal(step.edges.length, 0, name);
  }
  if (scenario.steps.some(step => step.outcome === 'error')) {
    assert.equal(scenario.steps.at(-1).outcome, 'error', `${name}: steps after blocker`);
  }
}
assert.ok(PREVIEW_SCENARIOS.web.steps.some(step => step.node === 'zap'));
assert.ok(PREVIEW_SCENARIOS.web.steps.some(step => step.node === 'nikto'));
assert.ok(PREVIEW_SCENARIOS.noWeb.steps.some(step => step.node === 'zap' && step.outcome === 'skipped'));
assert.ok(PREVIEW_SCENARIOS.denied.steps.every(step => step.node === 'scope'));
console.log('PREVIEW: five labeled branch examples, valid nodes and edges, skip and blocker boundaries passed');
