// Presentation only: explain recorded work without launching tools or changing facts.
const readable = value => String(value ?? 'Unknown').replaceAll('_', ' ');
const definitions = {
  scope: ['Confirm permission', 'Resolve the entered address and check the deterministic scope fence before any target scan.'],
  model: ['Check AI configuration', 'Check the selected provider configuration. A key or installed model does not prove generation will succeed.'],
  scanner: ['Discover services', 'Use bounded Nmap discovery to observe reachable ports and service fingerprints. An open port is not itself a vulnerability.'],
  endpoint_scan: ['Check the requested endpoint', 'Verify the exact port in the submitted URL rather than relying only on the common-port scan.'],
  nikto: ['Inspect the web endpoint', 'Run bounded Nikto checks on an approved test asset. Record web findings with their source evidence.'],
  canonical: ['Organise the evidence', 'Parse scanner records into consistent finding and service records while preserving the raw evidence.'],
  nvd: ['Check vulnerability records', 'Look up scanner-named CVEs in NVD. Without CVE identifiers, a lookup is not applicable; a banner alone is not confirmation.'],
  epss: ['Check exploitation likelihood', 'Retrieve dated EPSS information for identified CVEs. EPSS describes threat likelihood, not the safety of this particular deployment.'],
  kev: ['Check known exploitation', 'Check identified CVEs against CISA KEV. No CVE match is not the same as establishing that nothing is exploited.'],
  intel: ['Connect findings to intelligence', 'Attach supported vulnerability matches and publisher dates without inventing a CVE for an unclassified finding.'],
  context: ['Understand the surroundings', 'Use recorded services, approved metadata and observed controls to explain role and exposure. Unknown protection remains unknown.'],
  score: ['Calculate deterministic priorities', 'Apply the configured formula or an explicitly recorded native-severity fallback. The AI does not set this number.'],
  queue: ['Order the findings', 'Arrange supported findings by their deterministic priority. Unscored findings still require review.'],
  rationale: ['Explain the priority inputs', 'Show the recorded reason and score basis so a reviewer can trace the order back to evidence.'],
  evidence: ['Prepare the AI evidence case', 'Select bounded, server-issued evidence records for this target. Every generated claim must stay inside that case.'],
  coverage: ['Identify blind spots', 'Record omitted evidence, incomplete checks and controls the scan could not establish. Missing evidence is not a protective control.'],
  prompt: ['Build the grounded request', 'Package the evidence as untrusted data with a structured response schema. No scan permission or scoring authority is delegated.'],
  generation: ['Generate the AI assessment', 'Ask the explicitly selected model to interpret the bounded case. Its response is withheld until validation completes.'],
  validation: ['Verify citations and scores', 'Check identifiers, quoted evidence, claim metadata and score consistency. Unsupported output becomes Needs review.'],
  report: ['Build the assessment summary', 'Bring collection status, findings, limitations and validated AI guidance together. Collection and AI outcomes remain separate.'],
};
const phases = [
  ['Permission', ['scope', 'model']], ['Collection', ['scanner', 'endpoint_scan', 'nikto']],
  ['Understanding', ['canonical', 'nvd', 'epss', 'kev', 'intel', 'context']],
  ['Priority', ['score', 'queue', 'rationale']], ['AI review', ['evidence', 'coverage', 'prompt', 'generation', 'validation', 'report']],
];
const headerGuidance = [
  ['strict-transport-security', 'Tells browsers to use HTTPS on future visits. Review the HTTPS deployment before enabling it.'],
  ['content-security-policy', 'Limits which scripts and resources the browser can load. The policy needs to match the application.'],
  ['referrer-policy', 'Controls how much referring-page information the browser shares with another destination.'],
  ['x-content-type-options', 'Helps prevent browsers from guessing a response type instead of using the declared content type.'],
  ['permissions-policy', 'Restricts browser features such as camera and location access according to the application’s needs.'],
];

export function buildActivityModel(brief, live = {}, services = []) {
  const preview = brief.source === 'Simulated preview';
  const events = preview ? [] : [...(live.stages || new Map())];
  const running = events.filter(([, event]) => event.state === 'running');
  const failed = events.filter(([, event]) => event.state === 'error');
  const current = running.at(-1) || (live.error ? failed.at(-1) : null);
  const detail = current ? definitions[current[0]] || [current[0], 'Inspect the recorded stage details.'] : null;
  const title = preview ? 'Preview only — no assessment is running' : live.busy
    ? detail?.[0] || 'Preparing this assessment' : live.error ? 'This run needs attention'
      : live.result ? brief.scanStatus === 'partial' ? 'Partial collection — review the gaps'
        : live.result.ai_status === 'validated' ? 'Assessment ready for review' : 'Evidence collected · AI not validated'
        : 'Understand the recorded evidence';
  const why = preview ? 'This is a simulated path. No scanner or model is called.' : live.busy
    ? detail?.[1] || 'The app is preparing the selected target. No conclusion is available yet.'
    : live.error ? live.error : live.result ? brief.conclusion
      : `${brief.conclusion} You are viewing stored records, not a new scan.`;
  return {
    title, why, preview,
    detail: current?.[1].detail || '',
    running: running.map(([id]) => definitions[id]?.[0] || id),
    recent: events.filter(([, event]) => event.state === 'complete').slice(-3).map(([id, event]) => ({
      label: definitions[id]?.[0] || id, detail: event.detail,
      retained: Boolean(live.savedCapture || live.reuseRecent) && ['scanner', 'endpoint_scan', 'nikto', 'canonical', 'context'].includes(id),
    })),
    phases: phases.map(([label, ids]) => {
      const selected = events.filter(([id]) => ids.includes(id)).map(([, event]) => event.state);
      const state = preview || !live.active ? 'recorded' : selected.includes('running') ? 'running'
        : selected.includes('error') ? 'error' : selected.length === ids.length
          && selected.every(value => ['complete', 'skipped'].includes(value)) ? 'complete' : 'waiting';
      const completed = selected.filter(value => value === 'complete').length;
      const skipped = selected.filter(value => value === 'skipped').length;
      const status = state === 'complete' ? `${completed} recorded${skipped ? ` · ${skipped} not applicable` : ''}` : readable(state);
      return {label, state, status};
    }),
    services: preview ? [] : services,
    failures: failed.map(([id, event]) => ({label: definitions[id]?.[0] || id, detail: event.detail})),
    notRun: events.filter(([, event]) => event.state === 'skipped').map(([id, event]) => ({label: definitions[id]?.[0] || id, detail: event.detail})),
  };
}

function el(tag, className = '', text = '') {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = String(text ?? '').slice(0, 2400);
  return node;
}
function inspectButton(label, identity, inspect) {
  const button = el('button', 'activity-link', label);
  button.type = 'button';
  button.addEventListener('click', () => inspect(identity));
  return button;
}
function card(title, className) {
  const section = el('section', `activity-card ${className}`);
  section.append(el('h3', '', title));
  return section;
}
function evidence(label, fact) {
  const row = el('div', 'activity-fact');
  row.append(el('span', 'activity-muted', label), el('strong', '', readable(fact.value)));
  const source = fact.source === 'manual' ? 'Approved metadata' : fact.source === 'rule' ? 'Rule-based inference' : fact.source ? readable(fact.source) : 'No source recorded';
  row.append(el('small', 'activity-muted', `${source}${typeof fact.confidence === 'number' ? ` · recorded confidence ${Math.round(fact.confidence * 100)}%` : ''}`));
  const quote = fact.evidence || (fact.evidence_id ? `Evidence ${fact.evidence_id}` : 'No supporting observation recorded.');
  const detail = el('details', 'activity-evidence');
  detail.append(el('summary', '', 'Evidence & source'), el('blockquote', '', quote));
  row.append(detail);
  return row;
}

export function renderActivityContext(holder, brief) {
  holder.append(el('p', 'activity-target', brief.target));
  holder.append(evidence('System role', brief.role), evidence('Exposure', brief.exposure));
  holder.append(el('h4', '', 'Protection signals'));
  if (!brief.controls.length) holder.append(el('p', 'activity-muted', 'Control evidence has not been recorded for this selection.'));
  for (const control of brief.controls) {
    const value = control.value == null ? 'Unknown' : control.value === true ? 'Observed' : control.value === false ? 'Recorded absent' : readable(control.value);
    holder.append(evidence(readable(control.name), {...control, value}));
  }
  holder.append(el('p', 'activity-muted', 'Unknown does not mean absent. A host-level signal is not proof of protection for every endpoint.'));
}

export function renderWorkflowActivity(holder, brief, live, services, inspect) {
  const model = buildActivityModel(brief, live, services);
  holder.replaceChildren();
  const heading = el('header', 'activity-heading');
  const title = el('div');
  title.append(el('p', 'activity-eyebrow', 'ASSESSMENT / ACTIVITY & EVIDENCE'), el('h2', '', model.title), el('p', 'activity-target', brief.target));
  if (!model.preview) title.append(el('p', 'activity-context-line', `Role: ${readable(brief.role.value)} · Exposure: ${readable(brief.exposure.value)}`));
  const source = el('span', `activity-source${live.busy ? ' is-running' : ''}`, brief.source);
  heading.append(title, source);
  const stats = el('dl', 'activity-stats');
  for (const [label, value] of [['Observed services', brief.serviceCount], ['Recorded findings', brief.findingCount], ['Supported priorities', brief.priorities.length], ['AI assessment', brief.ai.status]]) {
    const stat = el('div');
    stat.append(el('dt', '', label), el('dd', '', model.preview || value == null || (brief.findingCount === null && label !== 'AI assessment') ? '—' : value));
    stats.append(stat);
  }
  const phaseList = el('ol', 'activity-phases');
  phaseList.setAttribute('aria-label', 'Assessment phases');
  for (const [index, phase] of model.phases.entries()) {
    const item = el('li', `phase-${phase.state}`);
    item.append(el('span', '', String(index + 1).padStart(2, '0')), el('strong', '', phase.label), el('small', '', phase.status));
    if (phase.state === 'running') item.setAttribute('aria-current', 'step');
    phaseList.append(item);
  }
  holder.append(heading, stats);
  if (live.active) holder.append(phaseList);
  const grid = el('div', 'activity-grid');
  const now = card(live.busy ? 'Happening now' : 'What this result means', 'activity-now');
  now.append(el('p', 'activity-purpose', model.why));
  if (model.detail) now.append(el('p', 'activity-tool-detail', model.detail));
  if (model.running.length > 1) now.append(el('p', 'activity-muted', `Also running: ${model.running.slice(0, -1).join(' · ')}`));
  if (model.recent.length && live.busy) {
    const recent = el('ul', 'activity-recent');
    for (const event of model.recent) recent.append(el('li', '', `${event.label} · ${event.retained ? 'recorded in retained evidence' : 'completed'}`));
    now.append(recent);
  }
  for (const line of brief.captureDetails || []) now.append(el('p', 'activity-muted', line));
  for (const failure of model.failures) now.append(el('p', 'activity-warning', `${failure.label}: ${failure.detail}`));
  grid.append(now);

  const context = card('The context behind the result', 'activity-context');
  renderActivityContext(context, brief);
  context.append(inspectButton('Inspect context evidence →', 'context', inspect));
  grid.append(context);

  const findings = card('Findings that need attention', 'activity-findings');
  findings.append(el('p', 'activity-muted', 'Recorded deterministic priorities · never assigned by the AI.'));
  if (!brief.priorities.length) findings.append(el('p', '', brief.findingCount === null ? 'Waiting for collection. No finding count or risk order is established.' : brief.findingCount ? 'Findings exist without supported scores. Review the unscored records.' : 'No vulnerability finding recorded. The observed services below are verification candidates, not a clean bill of health.'));
  for (const priority of brief.priorities.slice(0, 4)) {
    const row = el('article', 'activity-finding');
    const score = el('div', 'activity-score');
    score.append(el('strong', '', priority.risk), el('span', '', priority.band || 'Unscored'));
    const body = el('div');
    body.append(el('h4', '', priority.title || priority.finding_id), el('p', '', priority.reason));
    const guidance = headerGuidance.find(([header]) => String(priority.title || '').toLowerCase().includes(header));
    if (guidance) body.append(el('p', 'activity-meaning', `Why it matters · ${guidance[1]} Built-in guidance, not an exploitation claim.`));
    body.append(el('small', 'activity-muted', `${priority.native_fallback ? `Configured fallback: ${priority.native_fallback} · not CVSS` : priority.cvss_version_used ? `CVSS ${priority.cvss_version_used}` : 'Inspect recorded score basis'} · ${priority.finding_id}`));
    row.append(score, body); findings.append(row);
  }
  for (const finding of brief.unscoredFindings.slice(0, 3)) findings.append(el('p', 'activity-warning', `Unscored: ${finding.title || finding.finding_id} — ${finding.reason}`));
  if (model.services.length) {
    const list = el('div', 'activity-services');
    list.append(el('h4', '', 'Observed services'));
    for (const service of model.services.slice(0, 8)) list.append(el('p', '', `${service.host_ip ? `${service.host_ip} · ` : ''}${service.port}/${service.protocol || 'tcp'} · ${service.name || 'unknown'}${service.product ? ` · ${service.product} ${service.version || ''}` : ''}${service.tls ? ' · TLS observed' : ''}`));
    if (model.services.length > 8) list.append(el('p', 'activity-muted', `${model.services.length - 8} more services are available in the collection details.`));
    findings.append(list);
  }
  findings.append(inspectButton(brief.priorities.length > 4 ? `Inspect all ${brief.priorities.length} priorities →` : 'Inspect findings & score inputs →', 'queue', inspect));
  grid.append(findings);

  const ai = card('AI interpretation & next steps', 'activity-ai');
  ai.append(el('span', 'activity-source', brief.ai.status));
  if (brief.ai.model) ai.append(el('p', 'activity-muted', `${brief.ai.model} · ${brief.ai.confidence || 'unrecorded'} model-reported confidence; not measured accuracy`));
  ai.append(el('p', 'activity-purpose', brief.ai.summary || (brief.ai.error ? 'The AI output was withheld. Collected evidence is still available.' : 'No validated AI conclusion yet. Opening this workspace does not call a model.')));
  if (brief.ai.effect) ai.append(el('h4', '', brief.ai.status === 'Validated batches' ? 'Context interpretation · first batch' : 'Why context matters here'), el('p', '', brief.ai.effect), el('small', 'activity-muted', `Evidence: ${brief.ai.citations.join(', ')}`));
  const actions = el('ol', 'activity-actions');
  if (brief.actions.length > 4) ai.append(el('p', 'activity-muted', `Showing 4 of ${brief.actions.length} recommendations. Open the full analysis for every action and its batch-local citations.`));
  for (const action of brief.actions.slice(0, 4)) {
    const item = el('li');
    item.append(el('strong', '', action.action), el('p', '', action.reason), el('small', 'activity-muted', `${action.batch ? `Batch ${action.batch} · ` : ''}Evidence ${(action.evidence_ids || []).join(', ')}`));
    actions.append(item);
  }
  ai.append(actions, inspectButton('Open full analysis & citations →', 'analyst', inspect));
  grid.append(ai);

  const coverage = card('Coverage, skipped work & unknowns', 'activity-coverage');
  const gaps = el('ul');
  for (const gap of [...brief.coverage, ...brief.ai.uncertainties]) gaps.append(el('li', '', gap));
  coverage.append(gaps);
  if (model.notRun.length) {
    const detail = el('details');
    detail.append(el('summary', '', `${model.notRun.length} stages not run · see the recorded reasons`));
    for (const stage of model.notRun) detail.append(el('p', '', `${stage.label}: ${stage.detail}`));
    coverage.append(detail);
  }
  coverage.append(inspectButton('Inspect collection coverage →', 'nmap', inspect));
  grid.append(coverage);
  holder.append(grid);
}
