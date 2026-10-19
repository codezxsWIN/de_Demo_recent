import { scoreVector, sandbox } from './cvss31.js';
import { createAnalysisQueue } from './analyst-client.js';
import { initialiseCobeGlobe } from './cobe-globe.js';

const embedded = document.getElementById('assessment-data');
const bootstrap = JSON.parse(embedded.textContent);
initialiseCobeGlobe(bootstrap.assessment);
initialiseScenario();
initialisePlanetJourney();
initialiseInteractions();

// The hero's planet leaves the artwork, sinks behind the scenario and shrinks onto the Cobe globe; every frame is a pure function of scroll position.
function initialisePlanetJourney() {
  const journey = document.querySelector('[data-planet-journey]');
  const planet = journey?.querySelector('.planet');
  const hero = document.getElementById('hero');
  const scenario = document.getElementById('project-scenario');
  const globe = document.querySelector('[data-cobe-globe]');
  if (!journey || !planet || !hero || !scenario || !globe) return;
  const clamp = value => Math.min(1, Math.max(0, value));
  const ease = value => value * value * (3 - 2 * value);
  const mix = (from, to, amount) => ({
    x: from.x + (to.x - from.x) * amount, y: from.y + (to.y - from.y) * amount,
    rx: from.rx + (to.rx - from.rx) * amount, ry: from.ry + (to.ry - from.ry) * amount,
  });
  const update = () => {
    // Re-evaluate after a pane resize: a narrow first load must not disable the journey forever.
    const enabled = !window.matchMedia('(prefers-reduced-motion: reduce)').matches
      && window.matchMedia('(min-width: 900px)').matches
      && !location.hash.startsWith('#stage-');
    journey.hidden = !enabled;
    document.body.classList.toggle('has-planet-journey', enabled);
    if (!enabled) {
      hero.style.removeProperty('--handoff');
      globe.style.removeProperty('--globe-reveal');
      return;
    }
    const scrolled = window.scrollY;
    const heroBox = hero.getBoundingClientRect();
    // Rim circle measured in project-horizon.png (1600x1050): radius 2000, centre (800, 2732).
    const scaleX = heroBox.width / 1600;
    const scaleY = Math.max(heroBox.height, 720) / 1050;
    const start = { x: heroBox.left + 800 * scaleX, y: heroBox.top + scrolled + 2732 * scaleY, rx: 2000 * scaleX, ry: 2000 * scaleY };
    const radius = Math.max(window.innerWidth * 1.1, 1300);
    const backdrop = { x: window.innerWidth / 2, y: window.innerHeight * 0.7 + radius, rx: radius, ry: radius };
    const globeBox = globe.getBoundingClientRect();
    // Cobe's bright rim sits at 0.797 of the canvas radius (measured), so the planet's rim lands exactly on it.
    const sphere = globeBox.width / 2 * 0.797;
    const landing = { x: globeBox.left + globeBox.width / 2, y: globeBox.top + globeBox.height / 2, rx: sphere, ry: sphere };
    const scenarioTop = scenario.getBoundingClientRect().top + scrolled;
    const landStart = scenarioTop + scenario.offsetHeight - window.innerHeight;
    const landEnd = Math.max(globeBox.top + scrolled + globeBox.height / 2 - window.innerHeight / 2, landStart + 1);
    const sink = ease(clamp(scrolled / Math.max(scenarioTop - window.innerHeight * 0.15, 1)));
    // Motion completes at 80% of the landing; the last 20% is a pure in-place crossfade onto the globe.
    const landLinear = clamp((scrolled - landStart) / (landEnd - landStart) / 0.8);
    const land = ease(landLinear);
    const beforeLanding = mix(start, backdrop, sink);
    const at = mix(beforeLanding, landing, land);
    // Size settles faster than position, so the planet is already small when the showcase text scrolls in.
    const shrink = 1 - (1 - landLinear) ** 3;
    at.rx = beforeLanding.rx + (landing.rx - beforeLanding.rx) * shrink;
    at.ry = beforeLanding.ry + (landing.ry - beforeLanding.ry) * shrink;
    // Track the visible rim, not the centre, so the shrinking planet stays on screen.
    const rimTop = (beforeLanding.y - beforeLanding.ry) + ((landing.y - landing.ry) - (beforeLanding.y - beforeLanding.ry)) * land;
    at.y = rimTop + at.ry;
    planet.style.width = `${(at.rx * 2.24).toFixed(1)}px`;
    planet.style.height = `${(at.ry * 2.24).toFixed(1)}px`;
    planet.style.transform = `translate(${(at.x - at.rx * 1.12).toFixed(1)}px, ${(at.y - at.ry * 1.12).toFixed(1)}px)`;
    // The planet sits exactly under the artwork's planet, so masking the artwork after 4px of scroll is invisible.
    const handoff = clamp(scrolled / 4);
    const arrival = clamp(((scrolled - landStart) / (landEnd - landStart) - 0.8) / 0.2);
    // Dim to 65% while it is a backdrop behind text; full strength where it hands over to the artwork and the globe.
    const backdropDim = 1 - 0.35 * sink * (1 - landLinear);
    journey.style.opacity = (backdropDim * (1 - arrival)).toFixed(3);
    hero.style.setProperty('--handoff', handoff.toFixed(3));
    globe.style.setProperty('--globe-reveal', arrival.toFixed(3));
  };
  window.addEventListener('scroll', update, { passive: true });
  window.addEventListener('resize', update);
  window.addEventListener('hashchange', update);
  for (const query of ['(prefers-reduced-motion: reduce)', '(min-width: 900px)']) {
    window.matchMedia(query).addEventListener('change', update);
  }
  update();
}

// Reveal the scenario once when it scrolls into view; if it is already visible or motion is reduced, it simply stays shown.
function initialiseScenario() {
  const section = document.getElementById('project-scenario');
  if (!section || !('IntersectionObserver' in window) || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  if (section.getBoundingClientRect().top < window.innerHeight * 0.85) return;
  section.classList.add('is-armed');
  const observer = new IntersectionObserver(entries => {
    if (!entries.some(entry => entry.isIntersecting)) return;
    section.classList.add('is-visible');
    observer.disconnect();
  }, { threshold: 0.25 });
  observer.observe(section);
}

// Pointer-driven card glow, row spotlight and nav letter swap; text is restored exactly after each swap.
function initialiseInteractions() {
  const glowCards = [...document.querySelectorAll('.model-stage, .project-door, .door-record, .scenario-step')];
  let pointer = null;
  let frame = 0;
  const paintGlow = () => {
    frame = 0;
    for (const card of glowCards) {
      const bounds = card.getBoundingClientRect();
      const near = pointer && bounds.width > 0
        && pointer.x > bounds.left - 70 && pointer.x < bounds.right + 70
        && pointer.y > bounds.top - 70 && pointer.y < bounds.bottom + 70;
      card.style.setProperty('--glow-active', near ? '1' : '0');
      if (near) {
        const angle = Math.atan2(pointer.y - (bounds.top + bounds.height / 2), pointer.x - (bounds.left + bounds.width / 2)) * 180 / Math.PI + 90;
        card.style.setProperty('--glow-angle', angle.toFixed(1));
      }
    }
  };
  document.addEventListener('pointermove', event => {
    pointer = { x: event.clientX, y: event.clientY };
    if (!frame) frame = requestAnimationFrame(paintGlow);
  }, { passive: true });
  document.documentElement.addEventListener('pointerleave', () => { pointer = null; paintGlow(); });

  for (const row of document.querySelectorAll('.project-outcome-list > a, .analyst-evidence-path li, .project-faq summary, .project-path li')) {
    row.addEventListener('pointermove', event => {
      const bounds = row.getBoundingClientRect();
      row.style.setProperty('--mx', `${(event.clientX - bounds.left).toFixed(0)}px`);
      row.style.setProperty('--my', `${(event.clientY - bounds.top).toFixed(0)}px`);
    });
    row.addEventListener('pointerleave', () => { row.style.removeProperty('--mx'); row.style.removeProperty('--my'); });
  }

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  for (const link of document.querySelectorAll('.project-nav a')) {
    const original = link.textContent;
    const letters = [...original].filter(character => character.trim());
    if (!letters.length) continue;
    link.setAttribute('aria-label', original);
    let timer = 0;
    const swap = () => {
      clearInterval(timer);
      link.style.width = `${link.getBoundingClientRect().width}px`;
      let step = 0;
      timer = setInterval(() => {
        step += 1;
        const settled = Math.floor(step / 2);
        link.textContent = [...original].map((character, index) => (
          index < settled || !character.trim() ? character : letters[(index * 5 + step * 3) % letters.length]
        )).join('');
        if (settled >= original.length) {
          clearInterval(timer);
          link.textContent = original;
          link.style.removeProperty('width');
        }
      }, 32);
    };
    link.addEventListener('pointerenter', swap);
    link.addEventListener('focus', swap);
  }
}

const workflowLink = document.getElementById('open-workflow');
const heroWorkspace = document.getElementById('hero-workspace');
if (heroWorkspace && bootstrap.assessment) heroWorkspace.href = `/workflow?run=${encodeURIComponent(bootstrap.assessment.run.run_id)}`;
if (workflowLink && !bootstrap.offline) {
  workflowLink.hidden = false;
  workflowLink.href = bootstrap.assessment ? `/workflow?run=${encodeURIComponent(bootstrap.assessment.run.run_id)}` : '/workflow';
}
const projectTarget = document.getElementById('project-analyst-target');
if (projectTarget && bootstrap.assessment?.hosts.length) {
  const profiles = new Map(bootstrap.assessment.context.map(profile => [profile.host_ip, profile]));
  projectTarget.replaceChildren(...bootstrap.assessment.hosts.map(host => {
    const option = document.createElement('option');
    const role = profiles.get(host.ip)?.role?.value;
    option.value = host.ip;
    option.textContent = `${host.ip}${role ? ` / ${String(role).replaceAll('_', ' ')}` : ''}`;
    return option;
  }));
  projectTarget.value = bootstrap.assessment.scores[0]?.host_ip || bootstrap.assessment.hosts[0].ip;
  projectTarget.disabled = Boolean(bootstrap.offline);
}
const projectRunTarget = document.getElementById('project-run-target');
const hostsWithFindings = new Set((bootstrap.assessment?.findings || []).map(item => item.host_ip));
if (projectRunTarget && projectTarget) projectRunTarget.replaceChildren(...[...projectTarget.options].map(option => {
  const copy = option.cloneNode(true);
  if (!hostsWithFindings.has(copy.value)) {
    copy.disabled = true;
    copy.textContent += ' — no stored findings';
  }
  return copy;
}));
function showProjectDoor(identity) {
  const panel = [...document.querySelectorAll('[data-project-door-host]')].find(item => !item.hidden);
  if (!panel) return;
  const buttons = [...panel.querySelectorAll('[data-project-door]')];
  const selected = buttons.find(button => button.dataset.projectDoor === identity)
    || buttons.find(button => button.getAttribute('aria-pressed') === 'true') || buttons[0];
  for (const button of buttons) button.setAttribute('aria-pressed', String(button === selected));
  for (const detail of panel.querySelectorAll('[data-project-door-detail]')) detail.hidden = detail.dataset.projectDoorDetail !== selected?.dataset.projectDoor;
}

function updateProjectLinks() {
  const host = projectTarget?.value || bootstrap.assessment?.scores[0]?.host_ip || bootstrap.assessment?.hosts[0]?.ip;
  for (const control of document.querySelectorAll('[data-project-host]')) control.value = host || '';
  for (const panel of document.querySelectorAll('[data-project-door-host]')) panel.hidden = panel.dataset.projectDoorHost !== host;
  showProjectDoor();
  for (const link of document.querySelectorAll('[data-project-workflow]')) {
    link.hidden = Boolean(bootstrap.offline || (link.dataset.requiresHost === 'true' && !host));
    if (!bootstrap.offline) {
      const parameters = new URLSearchParams();
      if (link.dataset.workflowNode) parameters.set('node', link.dataset.workflowNode);
      if (host) parameters.set('host', host);
      if (link.dataset.workflowFinding) parameters.set('finding', link.dataset.workflowFinding);
      const run = bootstrap.assessment ? `?run=${encodeURIComponent(bootstrap.assessment.run.run_id)}` : '';
      link.href = `/workflow${run}${parameters.size ? `#${parameters}` : ''}`;
    }
  }
}
updateProjectLinks();
projectTarget?.addEventListener('change', () => {
  updateProjectLinks();
  const section = location.hash.slice(1).split('?')[0] || 'project-analyst';
  const parameters = new URLSearchParams({asset: projectTarget.value});
  history.replaceState(null, '', `${location.pathname}${location.search}#${section}?${parameters}`);
});
for (const control of document.querySelectorAll('[data-project-host]')) control.addEventListener('change', () => {
  projectTarget.value = control.value;
  updateProjectLinks();
  const parameters = new URLSearchParams({asset: control.value});
  history.replaceState(null, '', `${location.pathname}${location.search}#${control.closest('section').id}?${parameters}`);
});
for (const button of document.querySelectorAll('[data-project-door]')) button.addEventListener('click', () => {
  showProjectDoor(button.dataset.projectDoor);
  const parameters = new URLSearchParams({asset: projectTarget.value, finding: button.dataset.projectDoor});
  history.replaceState(null, '', `${location.pathname}${location.search}#project-doors?${parameters}`);
});
const projectAnalystNote = document.getElementById('project-analyst-note');
if (projectAnalystNote) {
  if (bootstrap.offline) projectAnalystNote.textContent = 'Offline snapshot. Local model requests are unavailable here.';
  else if (!bootstrap.assessment?.hosts.length) projectAnalystNote.textContent = 'No recorded system is attached to this view.';
}
for (const note of document.querySelectorAll('[data-offline-note]')) note.hidden = !bootstrap.offline;
document.getElementById('project-offline').hidden = !bootstrap.offline;
const panels = [...document.querySelectorAll('[data-panel]')];
const dialog = document.getElementById('inspector');
const stageNames = new Set(['evidence', 'context', 'risk', 'priorities']);
const assetAddresses = (bootstrap.assessment?.hosts || []).map(host => host.ip);
let selectedAsset = bootstrap.assessment?.scores[0]?.host_ip || assetAddresses[0] || '';
let lastTrigger = null;
let tourStep = -1;

function showAsset(address) {
  if (!assetAddresses.includes(address)) address = assetAddresses[0] || '';
  selectedAsset = address;
  const index = assetAddresses.indexOf(address);
  for (const control of document.querySelectorAll('[data-asset-select]')) {
    control.setAttribute('aria-pressed', String(control.dataset.assetSelect === address));
  }
  for (const panel of document.querySelectorAll('[data-asset-panel]')) panel.hidden = panel.dataset.assetPanel !== address;
  const contextPanels = [...document.querySelectorAll('[data-context-panel]')];
  for (const panel of contextPanels) panel.hidden = panel.dataset.contextPanel !== address;
  const missing = document.getElementById('context-empty');
  if (missing) missing.hidden = contextPanels.some(panel => !panel.hidden);
  const position = document.getElementById('deck-position');
  if (position) position.textContent = `${index + 1} / ${assetAddresses.length}`;
  for (const button of document.querySelectorAll('[data-deck-step]')) button.disabled = assetAddresses.length < 2;
}

function chooseAsset(address, stage = state().stage) {
  const parameters = state().parameters;
  parameters.set('asset', address);
  parameters.delete('finding');
  setState(stage, parameters);
  showAsset(address);
}

for (const control of document.querySelectorAll('[data-asset-select]')) control.addEventListener('click', () => chooseAsset(control.dataset.assetSelect));
for (const button of document.querySelectorAll('[data-deck-step]')) button.addEventListener('click', () => {
  if (!assetAddresses.length) return;
  const index = (assetAddresses.indexOf(selectedAsset) + Number(button.dataset.deckStep) + assetAddresses.length) % assetAddresses.length;
  chooseAsset(assetAddresses[index]);
});
for (const button of document.querySelectorAll('[data-context-asset]')) button.addEventListener('click', () => chooseAsset(button.dataset.contextAsset, 'context'));

function state() {
  const [section, query = ''] = location.hash.slice(1).split('?');
  const stage = section.startsWith('stage-') ? section.slice(6) : 'evidence';
  return {stage: stageNames.has(stage) ? stage : 'evidence', parameters: new URLSearchParams(query)};
}

function setState(stage, parameters = new URLSearchParams()) {
  const suffix = parameters.toString();
  location.hash = `stage-${stage}${suffix ? `?${suffix}` : ''}`;
}

function openInspector(identity, trigger = null) {
  if (!dialog) return;
  const selected = [...dialog.querySelectorAll('[data-inspection]')].find(item => item.dataset.inspection === identity);
  if (!selected) return;
  for (const item of dialog.querySelectorAll('[data-inspection]')) item.hidden = item !== selected;
  if (trigger) lastTrigger = trigger;
  if (!dialog.open) dialog.showModal();
  dialog.scrollTop = 0;
  document.getElementById('close-inspector').focus();
}

function restoreView() {
  const current = state();
  const projectView = !location.hash.startsWith('#stage-');
  document.body.classList.toggle('project-view', projectView);
  document.getElementById('project-entry').hidden = !projectView;
  const projectHost = current.parameters.get('asset');
  if (projectView && projectHost && assetAddresses.includes(projectHost) && projectTarget) {
    projectTarget.value = projectHost;
    updateProjectLinks();
    document.getElementById(location.hash.slice(1).split('?')[0])?.scrollIntoView({block: 'start', behavior: 'instant'});
  }
  if (projectView) showProjectDoor(current.parameters.get('finding'));
  showAsset(current.parameters.get('asset') || selectedAsset);
  for (const panel of panels) panel.hidden = panel.dataset.panel !== current.stage;
  for (const link of document.querySelectorAll('[data-stage]')) {
    const active = link.dataset.stage === current.stage;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  for (const select of document.querySelectorAll('[data-facet]')) {
    const value = current.parameters.get(select.dataset.facet) || '';
    select.value = [...select.options].some(option => option.value === value) ? value : '';
  }
  const selectors = [...document.querySelectorAll('[data-facet]')];
  let visible = false;
  for (const row of document.querySelectorAll('.queue-row')) {
    row.hidden = selectors.some(select => select.value && row.dataset[select.dataset.facet] !== select.value);
    visible ||= !row.hidden;
  }
  const empty = document.getElementById('no-results');
  if (empty) empty.hidden = visible;
  const identity = current.parameters.get('finding');
  if (identity && !projectView) openInspector(identity);
  else if (dialog?.open) dialog.close();
  document.title = projectView ? 'VulnAssess / Context Is Not Free' : `VulnAssess / ${current.stage[0].toUpperCase()}${current.stage.slice(1)}`;
  refreshAnalysisPlan();
}

for (const link of document.querySelectorAll('[data-stage]')) {
  link.addEventListener('click', event => {
    event.preventDefault();
    if (dialog?.open) dialog.close();
    const parameters = new URLSearchParams();
    if (selectedAsset) parameters.set('asset', selectedAsset);
    setState(link.dataset.stage, parameters);
  });
}
for (const button of document.querySelectorAll('[data-inspect]')) {
  button.addEventListener('click', () => {
    const current = state();
    current.parameters.set('finding', button.dataset.inspect);
    lastTrigger = button;
    setState(current.stage, current.parameters);
    openInspector(button.dataset.inspect, button);
  });
}
document.getElementById('close-inspector')?.addEventListener('click', () => dialog.close());
dialog?.addEventListener('close', () => {
  if (!location.hash.startsWith('#stage-')) return;
  const current = state();
  current.parameters.delete('finding');
  history.replaceState(null, '', `#stage-${current.stage}${current.parameters.size ? `?${current.parameters}` : ''}`);
  if (lastTrigger?.isConnected && !lastTrigger.closest('[hidden]')) lastTrigger.focus();
});
dialog?.addEventListener('click', event => { if (event.target === dialog && event.clientX < dialog.getBoundingClientRect().left) dialog.close(); });
for (const select of document.querySelectorAll('[data-facet]')) {
  select.addEventListener('change', () => {
    const parameters = new URLSearchParams();
    for (const item of document.querySelectorAll('[data-facet]')) if (item.value) parameters.set(item.dataset.facet, item.value);
    setState('priorities', parameters);
  });
}
document.getElementById('clear-filters')?.addEventListener('click', () => { setState('priorities'); restoreView(); });
document.getElementById('refresh').disabled = Boolean(bootstrap.offline);
document.getElementById('refresh').title = bootstrap.offline ? 'Offline snapshot; export again to refresh' : 'Refresh stored records';
document.getElementById('refresh').addEventListener('click', async () => {
  if (bootstrap.offline) return;
  const run = bootstrap.assessment?.run.run_id;
  try {
    if (run) {
      const response = await fetch(`/api/run/${encodeURIComponent(run)}`, {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) throw new Error('The stored run is unavailable.');
    }
    location.reload();
  } catch (error) { document.getElementById('app-status').textContent = `Refresh failed: ${error.message}`; }
});
document.getElementById('select-run')?.addEventListener('change', event => {
  if (bootstrap.offline) return;
  if (event.target.value) location.href = `/?run=${encodeURIComponent(event.target.value)}`;
});
document.getElementById('select-project-run')?.addEventListener('change', event => {
  if (!bootstrap.offline && event.target.value) location.href = `/?run=${encodeURIComponent(event.target.value)}#project-story`;
});
if (bootstrap.offline && document.getElementById('select-run')) document.getElementById('select-run').disabled = true;

let storyStep = 0;
function setStoryStep(step) {
  storyStep = Math.max(0, Math.min(2, step));
  const example = document.getElementById('story-example');
  if (!example) return;
  example.dataset.step = String(storyStep);
  for (const button of document.querySelectorAll('[data-story-step]')) button.setAttribute('aria-pressed', String(Number(button.dataset.storyStep) === storyStep));
  for (const copy of document.querySelectorAll('[data-story-copy]')) copy.hidden = Number(copy.dataset.storyCopy) !== storyStep;
  document.getElementById('story-back').disabled = storyStep === 0;
  document.getElementById('story-position').textContent = `${storyStep + 1} of 3`;
  document.getElementById('story-next').textContent = ['Add the context', 'See the priorities', 'Follow the workflow'][storyStep];
}
for (const button of document.querySelectorAll('[data-story-step]')) button.addEventListener('click', () => setStoryStep(Number(button.dataset.storyStep)));
document.getElementById('story-back')?.addEventListener('click', () => setStoryStep(storyStep - 1));
document.getElementById('story-next')?.addEventListener('click', () => {
  if (storyStep < 2) setStoryStep(storyStep + 1);
  else { location.hash = 'project-workflow'; document.getElementById('project-workflow').scrollIntoView({block: 'start'}); }
});

const modelHost = document.getElementById('model-host');
const runModel = document.getElementById('run-model');

function analystSection(label, items, render) {
  const section = document.createElement('section');
  section.className = 'analyst-section';
  const heading = document.createElement('h3');
  heading.textContent = label;
  section.append(heading);
  const list = document.createElement('ol');
  for (const item of items) list.append(render(item));
  section.append(list);
  return section;
}

function renderAnalystResult(result, output) {
  const analysis = result.analysis;
  const evidence = new Map(result.evidence.map(item => [item.id, item]));
  const header = document.createElement('div');
  header.className = 'analyst-header';
  const title = document.createElement('div');
  const eyebrow = document.createElement('span');
  eyebrow.className = 'eyebrow';
  eyebrow.textContent = `${result.model} / ${result.source || 'analyst model'}`;
  const summary = document.createElement('strong');
  summary.textContent = analysis.summary;
  title.append(eyebrow, summary);
  const confidence = document.createElement('div');
  confidence.className = 'analyst-confidence';
  const confidenceLabel = document.createElement('span');
  confidenceLabel.textContent = 'Model-reported confidence';
  const confidenceValue = document.createElement('strong');
  confidenceValue.textContent = analysis.confidence;
  confidence.append(confidenceLabel, confidenceValue);
  header.append(title, confidence);
  output.append(header);
  const frame = result.decision_frame;
  if (frame) {
    const scored = frame.mode === 'scored_findings';
    output.append(analystSection(scored ? 'Stored priority order · scores unchanged' : 'Verification only · no scored findings', scored ? frame.priorities : frame.verification_candidates || [], item => {
      const row = document.createElement('li');
      row.textContent = scored ? `${item.title} · ${item.band} ${item.risk} · ${item.reason || 'No stored reason'}` : `${item.port}/${item.protocol} ${item.service || 'service'} · verify with authorised tests`;
      return row;
    }));
  }
  if (analysis.context_effect) output.append(analystSection('AI context effect · cited interpretation', [analysis.context_effect], item => {
    const row = document.createElement('li');
    const explanation = document.createElement('p');
    explanation.textContent = item.explanation;
    const citations = document.createElement('small');
    citations.textContent = item.evidence_ids.map(identity => `${identity}: ${evidence.get(identity)?.text || 'Citation unavailable'}`).join(' / ');
    row.append(explanation, citations);
    return row;
  }));
  output.append(analystSection(frame?.mode === 'verification_only' ? 'Suggested verification steps' : 'Suggested remediation sequence', analysis.recommended_actions, item => {
    const row = document.createElement('li');
    const action = document.createElement('strong');
    action.textContent = `${item.order}. ${item.action}`;
    const reason = document.createElement('p');
    reason.textContent = item.reason;
    const citations = document.createElement('small');
    citations.textContent = item.evidence_ids.map(identity => `${identity}: ${evidence.get(identity).text}`).join(' / ');
    row.append(action, reason, citations);
    return row;
  }));
  if (analysis.correlations.length) output.append(analystSection('Correlated evidence', analysis.correlations, item => {
    const row = document.createElement('li');
    const observation = document.createElement('p');
    observation.textContent = item.observation;
    const citations = document.createElement('small');
    citations.textContent = item.evidence_ids.map(identity => `${identity}: ${evidence.get(identity).text}`).join(' / ');
    row.append(observation, citations);
    return row;
  }));
  if (analysis.uncertainties.length) output.append(analystSection('What is still unknown', analysis.uncertainties, item => {
    const row = document.createElement('li');
    row.textContent = item;
    return row;
  }));
}

const projectRunForm = document.getElementById('project-run-form');
const projectRunResults = document.getElementById('project-run-results');
const projectRunStatus = document.getElementById('project-run-status');
const projectRunStop = document.getElementById('project-run-stop');
const projectRunConfirm = document.getElementById('project-run-confirm');
const recordedHosts = (bootstrap.assessment?.hosts || []).map(host => host.ip).filter(ip => hostsWithFindings.has(ip));
let pendingAnalysisHosts = [];

function analysisTargets() {
  if (projectRunForm.elements['analysis-scope'].value === 'all') return [...recordedHosts];
  return recordedHosts.includes(projectRunTarget.value) ? [projectRunTarget.value] : [];
}

function setAnalysisControls(busy) {
  const unavailable = Boolean(bootstrap.offline || !recordedHosts.length);
  for (const control of projectRunForm.querySelectorAll('input, select, button')) control.disabled = busy || unavailable;
  projectRunTarget.disabled ||= projectRunForm.elements['analysis-scope'].value === 'all';
  if (runModel) runModel.disabled = busy || unavailable;
}

function analysisEntry(hostIp, status, label) {
  const entry = document.createElement('article');
  entry.className = 'run-entry';
  entry.dataset.host = hostIp;
  entry.dataset.status = status;
  const heading = document.createElement('div');
  heading.className = 'run-entry-heading';
  const host = document.createElement('strong');
  host.textContent = hostIp;
  const badge = document.createElement('span');
  badge.className = 'run-entry-status';
  badge.textContent = label;
  heading.append(host, badge);
  entry.append(heading);
  return entry;
}

function renderAnalysisQueue(state) {
  setAnalysisControls(state.busy);
  projectRunStop.hidden = !state.busy || state.entries.length < 2;
  projectRunStop.disabled = state.stopRequested;
  const complete = state.entries.filter(entry => entry.status === 'complete').length;
  const failed = state.entries.filter(entry => entry.status === 'error').length;
  const notRun = state.entries.filter(entry => entry.status === 'not-run').length;
  const running = state.entries.find(entry => entry.status === 'running');
  projectRunStatus.textContent = state.busy
    ? `${state.stopRequested ? 'Stopping after' : 'Analyzing'} ${running?.hostIp || 'current request'} / ${complete} responses received`
    : `${complete} responses received / ${failed} failed / ${notRun} not started`;
  const labels = {queued: 'Queued', running: 'Waiting for model', complete: 'Response received', error: 'Request failed', 'not-run': 'Not started'};
  for (const item of state.entries) {
    const existing = [...projectRunResults.children].find(child => child.dataset.host === item.hostIp);
    if (existing?.dataset.status === item.status) continue;
    const entry = analysisEntry(item.hostIp, item.status, labels[item.status]);
    if (item.error) {
      const error = document.createElement('p');
      error.className = 'run-entry-error';
      error.textContent = item.error;
      if (item.status === 'error') error.setAttribute('role', 'alert');
      entry.append(error);
    }
    if (item.result) {
      const disclosure = document.createElement('details');
      disclosure.className = 'run-response';
      disclosure.open = state.entries.length === 1;
      const summary = document.createElement('summary');
      summary.textContent = 'Cited response and uncertainties';
      disclosure.append(summary);
      renderAnalystResult(item.result, disclosure);
      entry.append(disclosure);
    }
    if (existing) existing.replaceWith(entry);
    else projectRunResults.append(entry);
  }
}

const projectAnalysisQueue = createAnalysisQueue({onChange: renderAnalysisQueue});

function refreshAnalysisPlan() {
  const targets = analysisTargets();
  const assessment = bootstrap.assessment;
  document.getElementById('project-run-assessment').textContent = assessment ? `Recorded assessment / ${assessment.run.run_id}` : 'No assessment selected.';
  document.getElementById('run-system-count').textContent = assessment ? String(targets.length) : 'Unavailable';
  document.getElementById('run-finding-count').textContent = assessment ? String(assessment.findings.filter(item => targets.includes(item.host_ip)).length) : 'Unavailable';
  document.getElementById('run-score-count').textContent = assessment ? String(assessment.scores.filter(item => targets.includes(item.host_ip)).length) : 'Unavailable';
  const current = projectAnalysisQueue.snapshot();
  setAnalysisControls(current.busy);
  if (!current.entries.length && targets.length) projectRunResults.replaceChildren(...targets.map(host => analysisEntry(host, 'not-requested', 'Not requested')));
  const note = document.getElementById('project-run-note');
  if (bootstrap.offline) note.textContent = 'Offline snapshot. Local model requests are unavailable here.';
  else if (!recordedHosts.length) note.textContent = 'A stored assessment with at least one recorded finding is required.';
}

function reviewAnalysis() {
  if (bootstrap.offline || projectAnalysisQueue.snapshot().busy || !bootstrap.assessment) return;
  pendingAnalysisHosts = analysisTargets();
  if (!pendingAnalysisHosts.length) return;
  document.getElementById('run-confirm-title').textContent = `Analyze ${pendingAnalysisHosts.length} recorded ${pendingAnalysisHosts.length === 1 ? 'system' : 'systems'}?`;
  document.getElementById('run-confirm-assessment').textContent = `Assessment ${bootstrap.assessment.run.run_id} / existing evidence only`;
  document.getElementById('run-confirm-targets').replaceChildren(...pendingAnalysisHosts.map(host => {
    const item = document.createElement('li');
    item.textContent = host;
    return item;
  }));
  projectRunConfirm.showModal();
  document.getElementById('run-confirm-cancel').focus();
}

projectRunForm.addEventListener('submit', event => { event.preventDefault(); reviewAnalysis(); });
projectRunForm.addEventListener('change', refreshAnalysisPlan);
projectTarget?.addEventListener('change', refreshAnalysisPlan);
for (const control of document.querySelectorAll('[data-project-host]')) control.addEventListener('change', refreshAnalysisPlan);
document.getElementById('run-confirm-cancel').addEventListener('click', () => projectRunConfirm.close());
projectRunConfirm.addEventListener('close', () => { pendingAnalysisHosts = []; document.getElementById('project-run-review').focus(); });
document.getElementById('run-confirm-start').addEventListener('click', async () => {
  if (!projectRunConfirm.open || bootstrap.offline || projectAnalysisQueue.snapshot().busy || !bootstrap.assessment || !pendingAnalysisHosts.length) return;
  const targets = [...pendingAnalysisHosts];
  projectRunConfirm.close();
  projectRunResults.replaceChildren();
  try { await projectAnalysisQueue.start(bootstrap.assessment.run.run_id, targets); }
  catch (error) { projectRunStatus.textContent = error.message; setAnalysisControls(false); }
});
projectRunStop.addEventListener('click', () => projectAnalysisQueue.stopAfterCurrent());
window.addEventListener('beforeunload', event => {
  if (projectAnalysisQueue.snapshot().busy) { event.preventDefault(); event.returnValue = ''; }
});
runModel?.addEventListener('click', () => {
  if (!recordedHosts.includes(modelHost?.value) || bootstrap.offline || projectAnalysisQueue.snapshot().busy) return;
  projectTarget.value = modelHost.value;
  updateProjectLinks();
  projectRunForm.elements['analysis-scope'].value = 'selected';
  history.replaceState(null, '', `${location.pathname}${location.search}#project-run?${new URLSearchParams({asset: modelHost.value})}`);
  restoreView();
  reviewAnalysis();
});

const systemTheme = matchMedia('(prefers-color-scheme: dark)');
let themePreference = 'dark';
function setTheme(theme) {
  themePreference = ['system', 'light', 'dark'].includes(theme) ? theme : 'dark';
  document.documentElement.dataset.theme = themePreference === 'system' ? (systemTheme.matches ? 'dark' : 'light') : themePreference;
  for (const button of document.querySelectorAll('[data-theme-choice]')) button.setAttribute('aria-pressed', String(button.dataset.themeChoice === themePreference));
  try { localStorage.setItem('vulnassess-theme', themePreference); } catch { document.getElementById('app-status').textContent = 'Theme preference applies to this page only.'; }
}
let theme = 'dark';
try { theme = localStorage.getItem('vulnassess-theme') || theme; } catch { theme = 'light'; }
const requestedTheme = state().parameters.get('theme');
if (requestedTheme === 'light' || requestedTheme === 'dark') theme = requestedTheme;
setTheme(theme);
for (const button of document.querySelectorAll('[data-theme-choice]')) button.addEventListener('click', () => setTheme(button.dataset.themeChoice));
systemTheme.addEventListener('change', () => { if (themePreference === 'system') setTheme('system'); });

const tourSteps = [
  {stage: 'evidence', target: '.asset-grid', title: 'Begin with the scanner.', copy: 'These are the hosts in this recorded assessment. Select a finding to see its original evidence and recorded score.'},
  {stage: 'evidence', target: '.feed-grid', title: 'Intelligence has a date.', copy: 'The vulnerability, EPSS and KEV facts came from local snapshots. Their dates and digests stay visible.'},
  {stage: 'context', target: '.context-grid', title: 'A role needs a clue.', copy: 'Compare the role with its quoted evidence. A MySQL banner supports the database role; the confidence is a separate question.'},
  {stage: 'risk', target: '#comparison', title: 'One weakness, two priorities.', copy: 'The base severity is shared. The recorded environment and context differ. The highlighted rows show where.'},
  {stage: 'priorities', target: '#ranked-list', title: 'The finding reaches the queue.', copy: 'The list uses stored risk and band values. Selecting a finding opens its reason, score inputs and provenance.'},
  {stage: 'priorities', target: '.evaluation', title: 'A demonstration is not a result.', copy: 'Synthetic records can demonstrate the workflow. Real captures and independent expert judgments are still needed to evaluate the method.'}
];
const followedScore = bootstrap.assessment?.scores.find(score => score.finding_id === bootstrap.tour_finding);
if (followedScore) {
  tourSteps[0].target = `[id="host-${followedScore.host_ip}"]`;
  tourSteps[0].copy = `Follow ${followedScore.cve_id} on ${followedScore.host_ip}. The finding starts with a scanner record, not a model's guess.`;
  tourSteps[2].target = `[id="context-${followedScore.host_ip}"]`;
  tourSteps[2].copy = `The stored role for ${followedScore.host_ip} has a confidence and an exact evidence quote. Manual tags are marked separately.`;
  tourSteps[4].target = `#ranked-list [data-inspect="${followedScore.finding_id}"]`;
  tourSteps[4].copy = `The same finding now has stored risk ${followedScore.risk} and band ${followedScore.band}. Open it to inspect the score inputs and original source.`;
}

function showTour() {
  document.querySelector('.tour-target')?.classList.remove('tour-target');
  const tour = document.getElementById('tour');
  tour.hidden = tourStep < 0;
  if (tourStep < 0) return;
  if (dialog?.open) dialog.close();
  const step = tourSteps[tourStep];
  setState(step.stage);
  restoreView();
  document.getElementById('tour-position').textContent = `TRACE ONE FINDING / ${tourStep + 1} OF ${tourSteps.length}`;
  document.getElementById('tour-title').textContent = step.title;
  document.getElementById('tour-copy').textContent = step.copy;
  document.getElementById('tour-back').disabled = tourStep === 0;
  document.getElementById('tour-next').textContent = tourStep === tourSteps.length - 1 ? 'Finish' : 'Next';
  const target = document.querySelector(step.target);
  if (target) {
    const address = target.dataset.assetPanel || target.dataset.contextPanel;
    if (address) showAsset(address);
    target.classList.add('tour-target'); target.scrollIntoView({block: 'nearest', behavior: 'instant'});
  }
}
document.getElementById('start-tour').disabled = !bootstrap.assessment;
document.getElementById('start-tour').addEventListener('click', () => { tourStep = 0; showTour(); });
document.getElementById('tour-next').addEventListener('click', () => { tourStep = tourStep === tourSteps.length - 1 ? -1 : tourStep + 1; showTour(); });
document.getElementById('tour-back').addEventListener('click', () => { tourStep = Math.max(0, tourStep - 1); showTour(); });
document.getElementById('tour-close').addEventListener('click', () => { tourStep = -1; showTour(); });
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  if (document.getElementById('palette')?.open) return;
  if (dialog?.open) {
    event.preventDefault();
    dialog.close();
  }
  if (tourStep >= 0) {
    tourStep = -1;
    showTour();
    document.getElementById('start-tour').focus();
  }
});
const sandboxForm = document.getElementById('sandbox-form');
let sandboxProfile = null;
function sandboxResult() {
  const selected = bootstrap.assessment?.scores.find(score => score.finding_id === sandboxForm?.elements.finding.value);
  if (!selected || !sandboxProfile) return;
  const elements = sandboxForm.elements;
  const errorBox = document.getElementById('sandbox-error');
  const missing = elements['epss-missing'].checked;
  elements.epss.disabled = missing;
  document.getElementById('sandbox-epss').textContent = missing ? 'Absent' : elements.epss.value;
  try {
    const result = sandbox(selected.base_vector, sandboxProfile, {
      role: elements.role.value, exposure: elements.exposure.value, environment: elements.environment.value,
      waf: elements.waf.checked, kev: elements.kev.checked, epss: missing ? null : Number(elements.epss.value)
    }, bootstrap.configuration.weights.values);
    document.getElementById('sandbox-environmental').textContent = String(result.environmental);
    document.getElementById('sandbox-threat').textContent = result.multiplier === null ? 'Unscored' : String(result.multiplier);
    document.getElementById('sandbox-risk').textContent = String(result.risk);
    document.getElementById('sandbox-band').textContent = result.band;
    document.getElementById('sandbox-vector').textContent = result.vector;
    errorBox.hidden = true;
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.hidden = false;
    for (const name of ['environmental', 'threat', 'risk', 'band']) document.getElementById(`sandbox-${name}`).textContent = 'Unavailable';
  }
}
function resetSandbox() {
  const selected = bootstrap.assessment?.scores.find(score => score.finding_id === sandboxForm?.elements.finding.value);
  if (!selected) return;
  sandboxProfile = JSON.parse(JSON.stringify(selected.inputs));
  const elements = sandboxForm.elements;
  elements.role.value = selected.inputs.role.value;
  elements.exposure.value = selected.inputs.exposure.value;
  elements.environment.value = selected.inputs.manual?.environment?.value || 'prod';
  elements.waf.checked = Boolean(selected.inputs.controls?.waf?.value);
  elements.kev.checked = selected.kev;
  elements['epss-missing'].checked = selected.epss_percentile === null;
  elements.epss.value = selected.epss_percentile === null ? '0' : String(selected.epss_percentile);
  sandboxResult();
}
if (sandboxForm) {
  if (bootstrap.tour_finding) sandboxForm.elements.finding.value = bootstrap.tour_finding;
  sandboxForm.addEventListener('submit', event => event.preventDefault());
  sandboxForm.addEventListener('input', event => event.target.name === 'finding' ? resetSandbox() : sandboxResult());
  document.getElementById('sandbox-reset').addEventListener('click', resetSandbox);
  resetSandbox();
}
document.getElementById('selfcheck')?.addEventListener('click', async () => {
  const result = document.getElementById('selfcheck-result');
  try {
    let fixture = bootstrap.cvss_fixture;
    if (!fixture) {
      const response = await fetch('/api/cvss-fixture', {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) throw new Error('CVSS regression fixture is unavailable.');
      fixture = await response.json();
    }
    const failures = fixture.vectors.filter(row => {
      const scored = scoreVector(row.vector);
      return scored.base !== row.base || scored.environmental !== row.environmental;
    });
    const scenarioFailures = fixture.sandbox_cases.filter(row => {
      const scored = sandbox(row.vector, row.profile, row.changes, fixture.sandbox_weights);
      return Object.keys(row.expected).some(key => scored[key] !== row.expected[key]);
    });
    result.textContent = `${fixture.vectors.length - failures.length} of ${fixture.vectors.length} CVSS vectors match Python. ${fixture.sandbox_cases.length - scenarioFailures.length} of ${fixture.sandbox_cases.length} sandbox cases match; ${failures.length + scenarioFailures.length} failed.`;
  } catch (error) { result.textContent = `Not run: ${error.message}`; }
});

window.addEventListener('hashchange', restoreView);
restoreView();
if (state().parameters.get('tour') === '1' && bootstrap.tour_finding) {
  tourStep = 0;
  showTour();
}

const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
function fillDials(scope) {
  for (const dial of scope.querySelectorAll('[data-dial]')) {
    dial.querySelector('.dial-value')?.setAttribute('stroke-dasharray', `${dial.dataset.dial} 100`);
  }
}
const revealables = [...document.querySelectorAll('[data-reveal]')];
if (revealables.length && 'IntersectionObserver' in window && !reduceMotion) {
  const revealer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add('revealed');
      fillDials(entry.target);
      revealer.unobserve(entry.target);
    }
  }, {threshold: 0.15});
  for (const item of revealables) revealer.observe(item);
} else {
  for (const item of revealables) {
    item.classList.add('revealed');
    fillDials(item);
  }
}

function countUp(element) {
  const target = Number(element.dataset.count);
  if (!Number.isFinite(target) || reduceMotion || target === 0) { element.textContent = String(target); return; }
  const started = performance.now();
  const duration = 700;
  function tick(now) {
    const share = Math.min((now - started) / duration, 1);
    element.textContent = String(Math.round(target * (1 - Math.pow(1 - share, 3))));
    if (share < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}
for (const value of document.querySelectorAll('[data-count]')) {
  if ('IntersectionObserver' in window && !reduceMotion) {
    const counter = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        countUp(entry.target);
        counter.unobserve(entry.target);
      }
    }, {threshold: 0.5});
    counter.observe(value);
  } else countUp(value);
}

const palette = document.getElementById('palette');
const paletteInput = document.getElementById('palette-input');
const paletteResults = document.getElementById('palette-results');
const paletteCount = document.getElementById('palette-count');
const paletteEntries = [];
let paletteMatches = [];
let paletteActive = 0;

function buildPalette() {
  const stageDetail = {
    evidence: 'What the scanners observed',
    context: 'What the clues imply',
    risk: 'Why urgency changes',
    priorities: 'What to examine first'
  };
  for (const stage of stageNames) {
    paletteEntries.push({kind: 'Stage', label: stage[0].toUpperCase() + stage.slice(1), detail: stageDetail[stage], stage});
  }
  const assessment = bootstrap.assessment;
  if (!assessment) return;
  const scored = new Map(assessment.scores.map(score => [score.finding_id, score]));
  for (const host of assessment.hosts) {
    paletteEntries.push({
      kind: 'Host',
      label: host.ip,
      detail: `${host.services.length} stored services`,
      stage: 'evidence',
      anchor: `host-${host.ip}`
    });
  }
  for (const finding of assessment.findings) {
    const score = scored.get(finding.id) || {};
    const identity = score.cve_id || finding.cve_ids.join(' ') || finding.tool_native_id;
    paletteEntries.push({
      kind: 'Finding',
      label: finding.title,
      detail: `${score.band || 'Unscored'} \u00b7 ${finding.host_ip} \u00b7 ${identity}`,
      terms: `${finding.tool} ${identity} ${finding.host_ip} ${score.risk ?? ''}`,
      finding: finding.id
    });
  }
}

function choosePalette(entry) {
  palette.close();
  const current = state();
  if (entry.finding) {
    const parameters = current.parameters;
    parameters.set('finding', entry.finding);
    setState(current.stage, parameters);
    restoreView();
    openInspector(entry.finding);
    return;
  }
  setState(entry.stage);
  restoreView();
  if (entry.anchor) {
    const target = document.getElementById(entry.anchor);
    if (target?.dataset.assetPanel) chooseAsset(target.dataset.assetPanel, entry.stage);
    target?.scrollIntoView({block: 'nearest'});
  }
}

function renderPalette() {
  const terms = paletteInput.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  paletteMatches = paletteEntries.filter(entry => {
    const haystack = `${entry.kind} ${entry.label} ${entry.detail} ${entry.terms || ''}`.toLowerCase();
    return terms.every(term => haystack.includes(term));
  }).slice(0, 40);
  if (paletteActive >= paletteMatches.length) paletteActive = 0;
  paletteResults.replaceChildren();
  paletteMatches.forEach((entry, index) => {
    const item = document.createElement('li');
    item.className = index === paletteActive ? 'palette-item active' : 'palette-item';
    item.id = `palette-option-${index}`;
    item.setAttribute('role', 'option');
    item.setAttribute('aria-selected', String(index === paletteActive));
    for (const [className, text] of [['palette-kind', entry.kind], ['palette-label', entry.label], ['palette-detail', entry.detail]]) {
      const part = document.createElement('span');
      part.className = className;
      part.textContent = text;
      item.append(part);
    }
    item.addEventListener('click', () => choosePalette(entry));
    paletteResults.append(item);
  });
  if (!paletteMatches.length) {
    const empty = document.createElement('li');
    empty.className = 'palette-empty';
    empty.textContent = 'Nothing stored matches that search.';
    paletteResults.append(empty);
  }
  paletteCount.textContent = `${paletteMatches.length} of ${paletteEntries.length}`;
  paletteInput.setAttribute('aria-activedescendant', paletteMatches.length ? `palette-option-${paletteActive}` : '');
}

function openPalette() {
  if (!palette || palette.open) return;
  paletteInput.value = '';
  paletteActive = 0;
  renderPalette();
  palette.showModal();
  paletteInput.focus();
}

if (palette) {
  buildPalette();
  document.getElementById('open-palette').addEventListener('click', openPalette);
  document.getElementById('close-palette').addEventListener('click', () => palette.close());
  palette.addEventListener('close', () => document.getElementById('open-palette').focus({preventScroll: true}));
  paletteInput.addEventListener('input', () => { paletteActive = 0; renderPalette(); });
  paletteInput.addEventListener('keydown', event => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (!paletteMatches.length) return;
      const step = event.key === 'ArrowDown' ? 1 : -1;
      paletteActive = (paletteActive + step + paletteMatches.length) % paletteMatches.length;
      renderPalette();
      document.getElementById(`palette-option-${paletteActive}`)?.scrollIntoView({block: 'nearest'});
    } else if (event.key === 'Enter') {
      event.preventDefault();
      if (paletteMatches[paletteActive]) choosePalette(paletteMatches[paletteActive]);
    }
  });
  document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openPalette();
    }
  });
}
