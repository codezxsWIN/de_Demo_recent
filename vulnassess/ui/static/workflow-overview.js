// Outcome-first presentation of the already-scoped, validated brief. No requests or scoring.
const text = value => String(value ?? 'Unknown').replaceAll('_', ' ');
function el(tag, className = '', value = '') {
  const item = document.createElement(tag);
  item.className = className;
  item.textContent = String(value);
  return item;
}
function section(title, className) {
  const item = el('section', `overview-section ${className}`);
  item.append(el('h3', '', title));
  return item;
}
function action(label, id, inspect) {
  const button = el('button', 'overview-action', label);
  button.type = 'button';
  button.addEventListener('click', () => inspect(id));
  return button;
}
function disclosure(label, value) {
  const detail = el('details', 'overview-disclosure');
  detail.append(el('summary', '', label), el('p', '', value));
  return detail;
}

export function renderAssessmentOverview(holder, brief, inspect) {
  holder.replaceChildren();
  const preview = brief.source === 'Simulated preview';
  const top = brief.priorities[0];
  const unscoredFindings = brief.unscoredFindings || [];
  const headline = preview ? 'Preview only — no assessment result' : brief.findingCount === null
    ? 'Waiting for evidence. No verdict yet.' : brief.findingCount === 0
      ? 'No findings recorded. Verification is still needed.' : `${brief.findingCount} finding${brief.findingCount === 1 ? '' : 's'} to review${top?.band ? ` · highest priority ${top.band}` : ''}`;
  const lead = el('header', 'overview-lead');
  const provenance = el('div', 'overview-provenance');
  provenance.append(el('span', 'overview-source', brief.source), el('span', 'overview-target', brief.target));
  lead.append(provenance, el('h2', '', headline), el('p', 'overview-verdict', brief.conclusion));
  if (brief.scanStatus === 'partial') {
    const warning = el('p', 'overview-verdict', 'Partial scan — requested checks failed; coverage is incomplete. Review the failed stages before relying on this result.');
    warning.setAttribute('role', 'status');
    lead.append(warning);
  }
  for (const line of brief.captureDetails || (brief.capturedAt ? [`Captured ${brief.capturedAt} · not a fresh scan`] : [])) lead.append(el('p', 'overview-muted', line));
  const stats = el('dl', 'overview-stats');
  for (const [label, count] of [['Observed services', brief.serviceCount], ['Recorded findings', brief.findingCount], ['Scored priorities', brief.priorities.length], ['Unscored findings', unscoredFindings.length]]) {
    const stat = el('div');
    stat.append(el('dd', '', preview || brief.findingCount === null ? '—' : count ?? '—'), el('dt', '', label));
    stats.append(stat);
  }
  lead.append(stats);
  holder.append(lead);

  const main = el('div', 'overview-main');
  if (brief.selfDefence) {
    const device = section('Your device · protection & precautions', 'overview-device');
    device.append(el('p', 'overview-muted', `Read-only observations · ${brief.selfDefence.checked_at}`));
    for (const check of brief.selfDefence.checks) {
      device.append(el('h4', '', `${check.title} — ${check.state}`), el('p', '', check.precaution));
    }
    device.append(el('p', 'overview-muted', brief.selfDefence.boundary), el('p', 'overview-muted', brief.selfDefence.limitations));
    main.append(device);
  }
  const queue = section('What needs your attention', 'overview-queue');
  queue.append(el('p', 'overview-muted', 'Recorded deterministic order · open the score inputs to trace the reasoning.'));
  if (!brief.priorities.length) {
    queue.append(el('p', 'overview-empty', brief.findingCount ? 'Findings exist, but no canonical priorities are recorded.' : brief.findingCount === null ? 'The evidence case is not ready. No risk order is claimed.' : 'There is no vulnerability queue for this selection. Start with the coverage gaps and unverified controls.'));
  }
  for (const [index, priority] of brief.priorities.slice(0, 5).entries()) {
    const row = el('article', 'overview-finding');
    const number = el('div', 'overview-score');
    number.append(el('strong', '', priority.risk ?? '—'), el('span', '', priority.band || 'Unscored'));
    const description = el('div');
    description.append(el('span', 'overview-muted', `PRIORITY ${index + 1}${priority.host_ip ? ` / ${priority.host_ip}` : ''}`), el('h4', '', priority.title || priority.finding_id || 'Finding'), el('p', '', priority.reason || 'No recorded rationale. Inspect canonical score inputs.'));
    row.append(number, description);
    queue.append(row);
  }
  queue.append(action(brief.priorities.length > 5 ? `Review all ${brief.priorities.length} priorities →` : 'Inspect findings & score inputs →', 'queue', inspect));
  main.append(queue);
  if (unscoredFindings.length) {
    const unscored = section('Unscored findings', 'overview-unscored');
    unscored.append(el('p', 'overview-muted', 'Severity review required. These findings have no supported risk order.'));
    for (const finding of unscoredFindings) {
      const row = el('article', 'overview-finding');
      const number = el('div', 'overview-score');
      number.append(el('strong', '', '—'), el('span', '', 'Unscored'));
      const description = el('div');
      description.append(el('span', 'overview-muted', finding.finding_id), el('h4', '', finding.title || finding.finding_id), el('p', '', finding.reason));
      if (finding.storedScore?.risk != null) description.append(el('p', 'overview-muted', `Stored values for audit only: risk ${finding.storedScore.risk} / band ${finding.storedScore.band || 'not recorded'}.`));
      row.append(number, description);
      unscored.append(row);
    }
    unscored.append(action('Inspect unscored findings →', 'queue', inspect));
    main.append(unscored);
  }

  const ai = section('Analyst interpretation', 'overview-analyst');
  ai.append(el('span', 'overview-status', brief.ai.status));
  if (brief.ai.model) ai.append(el('p', 'overview-muted', `${brief.ai.model}${brief.ai.confidence ? ` · ${brief.ai.confidence} confidence` : ''}`));
  ai.append(el('p', 'overview-ai-summary', brief.ai.summary || (brief.ai.error ? 'The model response did not pass validation. Its conclusions are withheld; collected evidence remains available.' : 'No validated AI assessment for this selection. The findings and context shown here come from recorded evidence.')));
  if (brief.ai.effect) ai.append(el('h4', '', 'Why context matters here'), el('p', '', brief.ai.effect), el('p', 'overview-muted', `Evidence: ${brief.ai.citations.join(', ')}`));
  if (brief.actions.length) {
    ai.append(el('h4', '', 'Recommended verification'));
    const list = el('ol', 'overview-next');
    for (const item of brief.actions) {
      const row = el('li');
      row.append(el('strong', '', item.action), el('p', '', item.reason), el('span', 'overview-muted', `${item.batch ? `Batch ${item.batch} · ` : ''}Evidence: ${(item.evidence_ids || []).join(', ')}`));
      list.append(row);
    }
    ai.append(list);
  }
  ai.append(action('Open analyst evidence & citations →', 'analyst', inspect));
  main.append(ai);
  holder.append(main);

  const rail = el('aside', 'overview-rail');
  const context = section('Context at a glance', 'overview-context');
  for (const [label, fact] of [['Asset role', brief.role], ['Exposure', brief.exposure]]) {
    const row = el('div', 'overview-fact');
    row.append(el('span', 'overview-muted', label), el('strong', '', text(fact.value)));
    if (fact.evidence) row.append(disclosure('Evidence & provenance', `${fact.evidence}${fact.source ? ` · source: ${fact.source}` : ''}${typeof fact.confidence === 'number' ? ` · recorded confidence: ${Math.round(fact.confidence * 100)}%` : ''}`));
    context.append(row);
  }
  context.append(el('h4', '', 'Protection signals'));
  context.append(el('p', 'overview-muted', 'Unknown means this assessment did not establish the control—not that the control is absent. Open the context evidence to see what was actually observed.'));
  if (!brief.controls.length) context.append(el('p', 'overview-muted', 'No control observations in this selection. Select one target for its context.'));
  for (const control of brief.controls) {
    const row = el('div', 'overview-control');
    row.append(el('span', '', text(control.name)), el('strong', '', control.value === null ? 'Unknown' : control.value === true ? 'Observed' : control.value === false ? 'Recorded absent' : text(control.value)));
    context.append(row);
  }
  context.append(action('Inspect context →', 'context', inspect));
  rail.append(context);
  const gaps = section('Before you trust the result', 'overview-gaps');
  gaps.append(el('p', 'overview-muted', 'Coverage limits and unresolved questions'));
  const list = el('ul');
  for (const gap of [...new Set([...brief.coverage, ...brief.ai.uncertainties])]) list.append(el('li', '', gap));
  gaps.append(list, action('Inspect collection evidence →', 'nmap', inspect));
  rail.append(gaps);
  holder.append(rail);
}
