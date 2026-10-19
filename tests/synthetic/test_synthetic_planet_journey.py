"""Synthetic DOM regression tests for the existing scroll effect; no browser or network."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARNESS = r"""
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source = readFileSync('vulnassess/ui/static/app.js', 'utf8').replaceAll('\r\n', '\n');
const start = source.indexOf('function initialisePlanetJourney()');
const end = source.indexOf('\n}\n', start);
assert.ok(start >= 0 && end > start, 'Original planet initializer must exist');
const script = source.slice(start, end + 3);
const events = new Map();
const media = new Map();
const classes = new Set(['project-view']);
const style = () => ({
  setProperty(name, value) { this[name] = value; },
  removeProperty(name) { delete this[name]; },
});
const planet = {style: style()};
const journey = {hidden: true, style: style(), querySelector: () => planet};
const hero = {style: style(), getBoundingClientRect: () => ({left: 0, top: -context.window.scrollY, width: 1200, height: 720})};
const scenarioSection = {offsetHeight: 800, getBoundingClientRect: () => ({top: 800 - context.window.scrollY})};
const globe = {style: style(), getBoundingClientRect: () => ({left: 700, top: 1800 - context.window.scrollY, width: 400, height: 400})};
const query = text => {
  if (!media.has(text)) media.set(text, {
    matches: text.includes('min-width'),
    listeners: [],
    addEventListener(name, callback) { assert.equal(name, 'change'); this.listeners.push(callback); },
  });
  return media.get(text);
};
const motion = query('(prefers-reduced-motion: reduce)');
const desktop = query('(min-width: 900px)');
const context = {
  document: {
    body: {classList: {
      add: value => classes.add(value),
      toggle(value, on) { if (on) classes.add(value); else classes.delete(value); },
    }},
    getElementById: id => id === 'hero' ? hero : scenarioSection,
    querySelector: selector => selector.includes('planet') ? journey : globe,
  },
  location: {hash: ''},
  window: {
    innerWidth: 1200, innerHeight: 800, scrollY: 0,
    matchMedia: query,
    addEventListener(name, callback) { events.set(name, callback); },
  },
};
vm.createContext(context);
vm.runInContext(script, context);
const active = () => {
  assert.equal(journey.hidden, false);
  assert.ok(classes.has('has-planet-journey'));
  assert.match(planet.style.transform, /^translate\(-?[\d.]+px, -?[\d.]+px\)$/);
  assert.ok(Number.parseFloat(planet.style.width) > 0);
  assert.ok(Number.parseFloat(planet.style.height) > 0);
};
const inactive = () => {
  assert.equal(journey.hidden, true);
  assert.ok(!classes.has('has-planet-journey'));
  assert.equal(hero.style['--handoff'], undefined);
  assert.equal(globe.style['--globe-reveal'], undefined);
};
"""


@pytest.mark.parametrize(
    "scenario",
    [
        "desktop",
        "narrow_then_resize",
        "narrow_then_media_change",
        "desktop_then_narrow",
        "reduced_then_enabled",
        "enabled_then_reduced",
        "scroll_down_and_back",
        "workbench_then_project",
        "project_then_workbench",
    ],
)
def test_original_planet_effect_recovers_without_reloading(scenario: str) -> None:
    node = shutil.which("node")
    assert node is not None, "MISSING: node for synthetic scroll-effect regression"
    completed = subprocess.run(
        [node, "--input-type=module", "-"],
        input=HARNESS
        + f"\nconst scenario = {scenario!r};\n"
        + r"""
if (scenario.startsWith('narrow_')) desktop.matches = false;
if (scenario === 'reduced_then_enabled') motion.matches = true;
if (scenario === 'workbench_then_project') context.location.hash = '#stage-evidence';
context.initialisePlanetJourney();
if (scenario.startsWith('narrow_')) {
  inactive(); desktop.matches = true;
  if (scenario.endsWith('resize')) events.get('resize')();
  else { assert.equal(desktop.listeners.length, 1); desktop.listeners[0](); }
  active();
} else if (scenario === 'desktop_then_narrow') {
  active(); desktop.matches = false; events.get('resize')(); inactive();
} else if (scenario === 'reduced_then_enabled') {
  inactive(); motion.matches = false;
  assert.equal(motion.listeners.length, 1); motion.listeners[0](); active();
} else if (scenario === 'enabled_then_reduced') {
  active(); motion.matches = true;
  assert.equal(motion.listeners.length, 1); motion.listeners[0](); inactive();
} else if (scenario === 'scroll_down_and_back') {
  active(); const original = planet.style.transform;
  context.window.scrollY = 600; events.get('scroll')(); active();
  assert.notEqual(planet.style.transform, original);
  context.window.scrollY = 0; events.get('scroll')(); active();
  assert.equal(planet.style.transform, original);
} else if (scenario === 'workbench_then_project') {
  inactive(); context.location.hash = '#hero'; events.get('hashchange')(); active();
} else if (scenario === 'project_then_workbench') {
  active(); context.location.hash = '#stage-evidence'; events.get('hashchange')(); inactive();
} else active();
console.log('Synthetic original scroll effect passed: ' + scenario);
""",
        cwd=ROOT,
        capture_output=True,
        encoding="utf-8",
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
