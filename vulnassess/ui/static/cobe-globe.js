import createGlobe from './vendor/cobe.js';

const MAX_SYSTEMS = 12;
const MAX_LINKS = 8;
const LATITUDES = [34, -30, 8, -40, 46];
const BANDS = new Set(['critical', 'high', 'medium', 'low']);

function labelNode(className, ...lines) {
  const node = document.createElement('span');
  node.className = className;
  for (const line of lines) {
    const part = document.createElement('span');
    part.textContent = line;
    node.append(part);
  }
  return node;
}

function tokenColour(name, fallback) {
  const probe = document.createElement('canvas').getContext('2d');
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  if (!probe || !value) return fallback;
  probe.fillStyle = value;
  const hex = probe.fillStyle;
  if (!hex.startsWith('#') || hex.length !== 7) return fallback;
  return [1, 3, 5].map(offset => parseInt(hex.slice(offset, offset + 2), 16) / 255);
}

function isSynthetic(assessment) {
  return assessment.feeds_meta.some(item => String(item.path).toLowerCase().includes('synthetic'))
    || assessment.findings.some(item => String(item.provenance?.raw_path).toLowerCase().includes('synthetic'));
}

// Positions are a deterministic layout, not geolocation: lab systems use private addresses.
function describeAssessment(assessment) {
  const roles = new Map(assessment.context.map(profile => [profile.host_ip, profile.role?.value]));
  const top = new Map();
  for (const score of assessment.scores) {
    if (!top.has(score.host_ip) || score.risk > top.get(score.host_ip).risk) top.set(score.host_ip, score);
  }
  const shown = [...assessment.hosts]
    .sort((a, b) => (top.get(b.ip)?.risk ?? -1) - (top.get(a.ip)?.risk ?? -1) || a.ip.localeCompare(b.ip))
    .slice(0, MAX_SYSTEMS);
  const spacing = Math.min(60, 330 / Math.max(shown.length, 1));
  const systems = shown.map((host, index) => ({
    id: `host-${host.ip.replace(/[^A-Za-z0-9]/g, '-')}`,
    ip: host.ip,
    name: String(host.hostname || host.ip).slice(0, 40),
    role: String(roles.get(host.ip) || 'unknown').replaceAll('_', ' '),
    band: top.get(host.ip)?.band || 'Unscored',
    location: [LATITUDES[index % LATITUDES.length], spacing * (index - (shown.length - 1) / 2)],
  }));
  const byIp = new Map(systems.map(system => [system.ip, system]));
  const groups = new Map();
  for (const score of assessment.scores) {
    if (!score.cve_id || !score.base_vector || score.base_score == null || !byIp.has(score.host_ip)) continue;
    const key = JSON.stringify([score.cve_id, score.base_vector, score.base_score, score.epss_percentile, score.kev]);
    const group = groups.get(key) || new Map();
    const current = group.get(score.host_ip);
    if (!current || score.risk > current.risk) group.set(score.host_ip, score);
    groups.set(key, group);
  }
  const links = [];
  for (const group of groups.values()) {
    const ends = [...group.values()].sort((a, b) => b.risk - a.risk);
    for (let index = 1; index < ends.length && links.length < MAX_LINKS; index += 1) {
      const [first, second] = [ends[index - 1], ends[index]];
      links.push({
        id: `link-${links.length}`,
        from: byIp.get(first.host_ip).location,
        to: byIp.get(second.host_ip).location,
        text: `${first.cve_id} · base ${first.base_score}`,
        detail: `same inputs · ${first.band} vs ${second.band}`,
      });
    }
  }
  return { systems, links, total: assessment.hosts.length, synthetic: isSynthetic(assessment) };
}

function describeReadout(root, assessment, summary) {
  const orbit = root.closest('.showcase-orbit');
  const status = orbit?.querySelector('[data-globe-status]');
  const note = orbit?.querySelector('[data-globe-note]');
  if (!status || !note) return;
  if (!assessment) {
    status.textContent = 'NO ASSESSMENT SELECTED';
    note.textContent = 'Choose a recorded run to place its systems.';
    return;
  }
  const count = summary.systems.length < summary.total
    ? `TOP ${summary.systems.length} OF ${summary.total} SYSTEMS`
    : `${summary.total} ${summary.total === 1 ? 'SYSTEM' : 'SYSTEMS'}`;
  const shared = `${summary.links.length} SHARED ${summary.links.length === 1 ? 'WEAKNESS' : 'WEAKNESSES'}`;
  status.textContent = [`RUN ${assessment.run.run_id}`, summary.synthetic ? 'SYNTHETIC' : 'SOURCE UNLABELLED', count, shared]
    .join(' / ').toUpperCase();
  note.textContent = summary.links.length
    ? 'Positions are illustrative, not geolocated.'
    : 'No weakness with identical inputs spans two systems. Positions are illustrative.';
}

export function initialiseCobeGlobe(assessment) {
  const root = document.querySelector('[data-cobe-globe]');
  const canvas = root?.querySelector('canvas');
  if (!root || !canvas || root.dataset.ready) return;
  root.dataset.ready = 'true';

  const summary = assessment
    ? describeAssessment(assessment)
    : { systems: [], links: [], total: 0, synthetic: false };
  for (const system of summary.systems) {
    const label = labelNode('cobe-marker-label', system.name, `${system.role} / ${system.band}`);
    label.dataset.band = system.band.toLowerCase();
    label.style.positionAnchor = `--cobe-${system.id}`;
    label.style.opacity = `var(--cobe-visible-${system.id}, 0)`;
    root.append(label);
  }
  for (const link of summary.links) {
    const badge = labelNode('cobe-traffic-label', link.text, link.detail);
    badge.style.positionAnchor = `--cobe-arc-${link.id}`;
    badge.style.opacity = `var(--cobe-visible-arc-${link.id}, 0)`;
    root.append(badge);
  }
  describeReadout(root, assessment, summary);

  const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let pointerStart = null;
  // Cobe faces longitude 0 (the middle of the layout) toward the viewer at phi = 3π/2.
  let phi = 1.5 * Math.PI;
  let theta = 0.2;
  let drag = { phi: 0, theta: 0 };
  let paused = false;
  let animationFrame;
  let globe;
  let visibilitySheet;
  let publishedVisibility = '';
  let mirroredVisibility = new Set();

  const syncVisibility = () => {
    const text = visibilitySheet?.textContent ?? '';
    if (text === publishedVisibility) return;
    publishedVisibility = text;
    const next = new Set();
    for (const [, name, value] of text.matchAll(/(--cobe-visible-[\w-]+):([^;]*);/g)) {
      root.style.setProperty(name, value);
      next.add(name);
    }
    for (const name of mirroredVisibility) if (!next.has(name)) root.style.removeProperty(name);
    mirroredVisibility = next;
  };

  const resize = () => {
    const width = root.clientWidth;
    if (!width || globe) return;
    const fallbackMarker = tokenColour('--muted', [0.6, 0.6, 0.6]);
    const append = document.head.append;
    // Cobe writes label visibility into an inline <style> the CSP blocks; keep it detached and mirror it via CSSOM.
    document.head.append = (...nodes) => {
      for (const node of nodes) {
        if (node instanceof HTMLStyleElement) visibilitySheet = node;
        else append.call(document.head, node);
      }
    };
    try {
      globe = createGlobe(canvas, {
      devicePixelRatio: Math.min(window.devicePixelRatio || 1, 2),
      width,
      height: width,
      phi,
      theta,
      dark: 1,
      diffuse: 3,
      mapSamples: 16000,
      mapBrightness: 1.8,
      mapBaseBrightness: 0,
      baseColor: [1, 1, 1],
      markerColor: fallbackMarker,
      glowColor: [1, 1, 1],
      markerElevation: 0.02,
      markers: summary.systems.map(({ id, location, band }) => ({
        id,
        location,
        size: 0.04,
        color: BANDS.has(band.toLowerCase()) ? tokenColour(`--${band.toLowerCase()}`, fallbackMarker) : fallbackMarker,
      })),
      arcs: summary.links.map(({ id, from, to }) => ({ id, from, to })),
      arcColor: tokenColour('--ink', [0.9, 0.9, 0.9]),
      arcWidth: 0.8,
      arcHeight: 0.25,
      opacity: 0.85,
      });
    } finally {
      delete document.head.append;
    }
    canvas.style.opacity = '1';
    const animate = () => {
      if (!paused && !still) phi += 0.003;
      globe.update({ phi: phi + drag.phi, theta: theta + drag.theta });
      syncVisibility();
      animationFrame = requestAnimationFrame(animate);
    };
    animate();
  };

  const resizeObserver = new ResizeObserver(entries => {
    if (entries[0]?.contentRect.width > 0) {
      resizeObserver.disconnect();
      resize();
    }
  });
  resizeObserver.observe(root);

  canvas.addEventListener('pointerdown', event => {
    pointerStart = { x: event.clientX, y: event.clientY };
    canvas.setPointerCapture(event.pointerId);
    canvas.style.cursor = 'grabbing';
    paused = true;
  });
  canvas.addEventListener('pointermove', event => {
    if (!pointerStart) return;
    drag = { phi: (event.clientX - pointerStart.x) / 300, theta: (event.clientY - pointerStart.y) / 1000 };
  });
  const finishDrag = () => {
    if (!pointerStart) return;
    phi += drag.phi;
    theta += drag.theta;
    drag = { phi: 0, theta: 0 };
    pointerStart = null;
    paused = false;
    canvas.style.cursor = 'grab';
  };
  canvas.addEventListener('pointerup', finishDrag);
  canvas.addEventListener('pointercancel', finishDrag);

  window.addEventListener('pagehide', () => {
    cancelAnimationFrame(animationFrame);
    globe?.destroy();
  }, { once: true });
}
