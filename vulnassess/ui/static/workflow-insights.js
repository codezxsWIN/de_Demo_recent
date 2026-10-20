// Presentation-only brief. Evidence, scope and canonical numbers are never modified.
const readable = value => String(value ?? 'unknown').replaceAll('_', ' ');
const emptyFeature = () => ({value: 'unknown', evidence: '', source: '', confidence: null});
const feature = value => value && typeof value === 'object' ? {...value} : {...emptyFeature(), value: value ?? 'unknown'};

// Only complete, explicitly empty score inputs establish a missing severity basis.
// Small presentation DTOs may omit these inputs even for supported scores.
export function lacksSeverityBasis(score) {
  return ['base_score', 'env_score', 'native_fallback'].every(key => Object.prototype.hasOwnProperty.call(score, key) && score[key] === null)
    && !score.base_vector && !score.env_vector;
}

export function reviewFindingPriorities(priorities = [], unscoredFindings = [], findings = []) {
  const titles = new Map(findings.map(item => [item.id, item.title]));
  const unscored = new Map(unscoredFindings.map(item => [item.finding_id, {
    ...item, title: item.title || titles.get(item.finding_id) || item.finding_id,
    reason: item.reason || 'No canonical score recorded; severity and risk order are unavailable.',
  }]));
  const supported = [];
  const scoredIds = new Set();
  for (const score of priorities) {
    scoredIds.add(score.finding_id);
    const missingBasis = lacksSeverityBasis(score);
    if (score.risk == null || missingBasis || unscored.has(score.finding_id)) {
      const existing = unscored.get(score.finding_id);
      const reason = missingBasis
        ? 'Stored score lacks a severity basis: no CVSS score, vector or native-severity fallback was recorded. Stored values are retained for audit only; no supported severity or risk order is claimed.'
        : 'No canonical score recorded; severity and risk order are unavailable.';
      unscored.set(score.finding_id, {
        ...existing, finding_id: score.finding_id,
        title: existing?.title || titles.get(score.finding_id) || score.title || score.finding_id,
        reason: existing ? `${existing.reason}${missingBasis ? ` ${reason}` : ''}` : reason,
        storedScore: {...score},
      });
    } else {
      supported.push({...score, title: score.title || titles.get(score.finding_id) || score.finding_id});
    }
  }
  for (const item of findings) {
    if (!scoredIds.has(item.id) && !unscored.has(item.id)) unscored.set(item.id, {
      finding_id: item.id, title: item.title || item.id,
      reason: 'No canonical score recorded; severity and risk order are unavailable.',
    });
  }
  return {priorities: supported, unscoredFindings: [...unscored.values()]};
}

export function captureProvenanceLines(summary) {
  if (!summary) return [];
  const lines = [];
  if (summary.historical_capture) lines.push(summary.captured_at
    ? `Captured ${summary.captured_at} · retained evidence; not a new scan.`
    : 'Capture date unknown · retained evidence; not a new scan.');
  else if (summary.captured_at) lines.push(`Captured ${summary.captured_at}.`);
  if (summary.capture_time_source) lines.push(`Capture time source: ${readable(summary.capture_time_source)}.`);
  if (summary.capture_time_warning) lines.push(summary.capture_time_warning);
  if (summary.intelligence_refreshed_at) lines.push(`Intelligence refreshed ${summary.intelligence_refreshed_at}. This is a refresh time, not the capture date.`);
  else if (summary.historical_capture) lines.push('No intelligence refresh time was recorded; retained enrichment is not shown as fresh.');
  return lines;
}

export function buildInsightBrief({assessment, host = '', finding = '', live = {}, storedAnalysis = null}) {
  const preview = live.active && live.previewState && live.previewState !== 'idle';
  const active = live.active && !preview;
  const hosts = (assessment?.hosts || []).filter(item => !host || item.ip === host);
  const selected = hosts.length === 1 ? hosts[0].ip : '';
  const findings = (assessment?.findings || []).filter(item => (!host || item.host_ip === host) && (!finding || item.id === finding));
  const ids = new Set(findings.map(item => item.id));
  const scores = (assessment?.scores || []).filter(item => ids.has(item.finding_id));
  const synthetic = (assessment?.findings || []).some(item => String(item.provenance?.raw_path || '').toLowerCase().includes('synthetic'));
  const summary = active ? live.result?.assessment_summary || live.scan?.assessment_summary : null;
  const response = active ? live.result?.analyst : storedAnalysis?.status === 'complete' ? storedAnalysis.result : null;
  const frame = active ? live.result?.decision_frame || live.scan?.decision_frame || response?.decision_frame || response?.batches?.[0]?.decision_frame : storedAnalysis?.status === 'complete' ? response?.decision_frame : null;
  const context = preview ? {} : active ? frame?.context || summary?.context || {} : (assessment?.context || []).find(item => item.host_ip === selected) || {};
  const controls = Object.entries(context.controls || {}).map(([name, record]) => {
    const item = feature(record);
    if (item.value === null || (item.value === false && item.source === 'rule' && item.evidence === 'none observed')) item.value = null;
    return {name, ...item};
  });
  const recordedUnscored = (assessment?.unscored_findings || []).filter(item => (!host || ids.has(item.finding_id) || item.host_ip === host) && (!finding || item.finding_id === finding));
  const {priorities, unscoredFindings} = preview ? {priorities: [], unscoredFindings: []} : reviewFindingPriorities(
    active ? summary?.priorities || frame?.priorities || [] : scores,
    active ? summary?.unscored_findings || frame?.unscored_findings || [] : recordedUnscored,
    active ? (frame?.priorities || []).map(item => ({id: item.finding_id, title: item.title})) : findings,
  );
  const rejected = active ? Boolean(live.error || live.needsReview) : ['error', 'needs_review'].includes(storedAnalysis?.status);
  const allowed = !rejected && !preview ? response : null;
  const batches = allowed?.batches || [];
  const analysis = allowed?.analysis;
  const actions = preview || rejected ? [] : batches.length
    ? batches.flatMap((batch, index) => (batch.analysis?.recommended_actions || []).map(action => ({...action, batch: index + 1})))
    : summary?.next_actions || analysis?.recommended_actions || [];
  const coverage = preview ? ['Animation only. No scanner or model is called.'] : active
    ? summary?.coverage_gaps || frame?.coverage_review?.limits || ['Collection coverage will appear as evidence arrives.']
    : ['Stored records are being viewed; no scanner has run on this page.', ...(controls.some(item => item.value === null) ? ['Some controls are not established by the collected evidence.'] : []), ...(findings.length ? [] : ['No vulnerability finding was recorded. This is not proof the target is safe.'])];
  const serviceCount = preview ? null : active ? summary?.service_count ?? live.scan?.services?.length ?? null : hosts.reduce((total, item) => total + (item.services || []).length, 0);
  const findingCount = preview ? null : active ? summary?.finding_count ?? live.scan?.finding_count ?? null : findings.length;
  const status = preview ? 'Preview only' : rejected ? 'Needs review' : batches.length ? 'Validated batches' : analysis ? 'Validated' : active
    ? live.busy ? 'Awaiting validation' : live.result?.ai_status ? readable(live.result.ai_status) : 'Not available'
    : storedAnalysis?.status === 'running' ? 'Analyzing' : 'Not requested';
  return {
    source: preview ? 'Simulated preview' : active ? summary?.historical_capture ? 'Retained capture' : live.reuseRecent ? 'Recent evidence replay' : 'Live assessment' : synthetic ? 'Synthetic stored inputs' : 'Stored assessment',
    target: preview ? live.previewScenario?.label || 'Workflow preview' : active ? live.target || live.scan?.resolved_ip || 'Pending target' : selected || (host ? host : `${hosts.length} assets in view`),
    capturedAt: summary?.captured_at || '', captureDetails: captureProvenanceLines(summary), serviceCount, findingCount,
    scanStatus: active ? summary?.scan_status || live.result?.scan_status || live.scan?.scan_status || 'unknown' : 'not_requested',
    selfDefence: summary?.self_defence || null,
    conclusion: preview ? 'Preview shows the execution path, not assessment results.' : summary?.conclusion || (findingCount === null ? 'Collection has not produced a completed evidence case. No assessment conclusion is available.' : findingCount ? 'Review the supported findings and recorded deterministic priorities.' : 'No vulnerability findings recorded. This is not proof that the target is safe.'),
    role: feature(context.role), exposure: feature(context.exposure), controls,
    priorities: [...priorities].sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1)),
    unscoredFindings,
    coverage, actions, cves: summary?.cve_evidence || [],
    ai: {status, model: allowed?.model || '', confidence: analysis?.confidence || '',
      summary: batches.length ? `${batches.length} validated batches. No cross-batch synthesis is claimed.` : analysis?.summary || '',
      effect: analysis?.context_effect?.explanation || '', citations: analysis?.context_effect?.evidence_ids || [],
      uncertainties: batches.length ? [] : analysis?.uncertainties || [],
      error: rejected ? live.error || storedAnalysis?.error || 'Unsupported output withheld.' : ''},
  };
}

function node(tag, className = '', text = '') {
  const item = document.createElement(tag);
  item.className = className;
  item.textContent = text;
  return item;
}

function card(title, id) {
  const section = node('section', `brief-section brief-${id}`);
  section.append(node('h3', '', title));
  return section;
}

function contextFact(label, item) {
  const row = node('div', 'brief-fact');
  row.append(node('span', 'brief-label', label), node('strong', '', readable(item.value)));
  if (item.source) row.append(node('span', 'brief-provenance', `${readable(item.source)}${typeof item.confidence === 'number' ? ` / ${Math.round(item.confidence * 100)}% recorded confidence` : ''}`));
  if (item.evidence) {
    const detail = node('details', 'brief-evidence');
    detail.append(node('summary', '', 'Supporting observation'), node('blockquote', '', item.evidence));
    row.append(detail);
  }
  return row;
}

export function renderInsightHighlights(holder, brief, onInspect) {
  holder.replaceChildren();
  const context = node('button', 'highlight highlight-context');
  context.type = 'button';
  context.append(node('span', 'highlight-label', 'Deployment context'), node('strong', '', `${readable(brief.role.value)} / ${readable(brief.exposure.value)}`));
  context.append(node('span', 'highlight-detail', brief.controls.length ? `${brief.controls.filter(item => item.value === null).length} of ${brief.controls.length} controls unknown. Inspect evidence.` : 'Inspect recorded context and provenance.'));
  context.addEventListener('click', () => onInspect('context'));
  const priority = node('button', 'highlight highlight-priority');
  priority.type = 'button';
  const top = brief.priorities[0];
  const unscoredCount = brief.unscoredFindings?.length || 0;
  priority.append(node('span', 'highlight-label', 'Deterministic priority'), node('strong', '', top ? `${top.risk ?? 'Unscored'} / ${top.band || 'Unscored'}` : unscoredCount ? `${unscoredCount} unscored finding${unscoredCount === 1 ? '' : 's'}` : brief.findingCount === null ? 'Awaiting evidence' : 'No scored findings'));
  priority.append(node('span', 'highlight-detail', `${unscoredCount ? `${unscoredCount} unscored finding${unscoredCount === 1 ? ' needs' : 's need'} review. ` : ''}${top?.title || (unscoredCount ? 'Severity and risk order are unavailable.' : 'Services are verification candidates, not vulnerabilities.')}`));
  priority.addEventListener('click', () => onInspect('queue'));
  const ai = node('button', 'highlight highlight-analysis');
  ai.type = 'button';
  ai.append(node('span', 'highlight-label', `AI insights / ${brief.ai.status}`));
  ai.append(node('strong', '', brief.ai.effect || brief.ai.summary || (brief.ai.error ? 'AI output withheld. Collected evidence is available.' : 'Request an analysis to get a validated interpretation.')));
  ai.append(node('span', 'highlight-detail', brief.actions[0] ? `Next: ${brief.actions[0].action}` : brief.source === 'Simulated preview' ? 'Preview only. No actual conclusion.' : 'Open analysis, supporting citations and next steps.'));
  ai.addEventListener('click', () => onInspect('analyst'));
  holder.append(context, priority, ai);
}

export function renderInsightBrief(holder, brief, onInspect) {
  holder.replaceChildren();
  const header = node('div', 'brief-heading');
  header.append(node('span', 'brief-source', brief.source), node('h2', '', 'Assessment brief'), node('p', 'brief-target', brief.target));
  for (const line of brief.captureDetails || (brief.capturedAt ? [`Captured ${brief.capturedAt}. Not a new scan.`] : [])) header.append(node('p', 'brief-date', line));
  holder.append(header);
  if (brief.scanStatus === 'partial') {
    holder.append(node('p', 'brief-conclusion', 'Partial scan — requested checks failed; coverage is incomplete. Retained observations remain available.'));
  }
  const counts = node('dl', 'brief-counts');
  for (const [label, value] of [['Services', brief.serviceCount], ['Findings', brief.findingCount], ['Priorities', brief.priorities.length], ['Unscored findings', brief.unscoredFindings?.length || 0]]) {
    const group = node('div');
    group.append(node('dd', '', value == null || brief.findingCount === null || brief.source === 'Simulated preview' ? '—' : String(value)), node('dt', '', label));
    counts.append(group);
  }
  holder.append(counts);
  holder.append(node('p', 'brief-conclusion', brief.conclusion));
  const context = card('Deployment context', 'context');
  context.append(contextFact('Asset role', brief.role), contextFact('Exposure', brief.exposure));
  const controls = node('div', 'brief-controls');
  for (const item of brief.controls) {
    const value = item.value === null ? 'Unknown' : item.value === true ? 'Observed' : item.value === false ? 'Recorded absent' : readable(item.value);
    const row = node('div', 'brief-control');
    row.append(node('span', '', readable(item.name)), node('strong', item.value === null ? 'is-unknown' : '', value));
    row.title = item.evidence || 'No supporting observation recorded';
    controls.append(row);
  }
  context.append(controls, node('p', 'brief-note', 'A host observation is not proof of protection for every finding.'));
  const inspect = node('button', 'brief-link', 'Inspect context evidence');
  inspect.type = 'button';
  inspect.addEventListener('click', () => onInspect('context'));
  context.append(inspect);
  holder.append(context);
  const priorities = card('What needs attention', 'priorities');
  if (!brief.priorities.length) priorities.append(node('p', 'brief-empty', brief.findingCount === null ? 'Awaiting collected evidence. No risk order claimed.' : brief.findingCount ? 'No canonical scores recorded. No risk order claimed.' : 'No scored vulnerabilities. Observed services still need verification.'));
  for (const priority of brief.priorities.slice(0, 3)) {
    const row = node('div', 'brief-priority');
    row.append(node('span', 'brief-risk', priority.risk == null ? 'Unscored' : `${priority.risk}`), node('strong', '', priority.title || priority.finding_id || 'Finding'));
    row.append(node('span', 'brief-band', `${priority.band || 'Unscored'} / deterministic`), node('p', '', priority.reason || 'Inspect the stored score inputs for its rationale.'));
    priorities.append(row);
  }
  const riskButton = node('button', 'brief-link', brief.priorities.length > 3 ? `Inspect all ${brief.priorities.length} priorities` : 'Inspect score inputs');
  riskButton.type = 'button'; riskButton.addEventListener('click', () => onInspect('queue'));
  priorities.append(riskButton);
  holder.append(priorities);
  if (brief.unscoredFindings?.length) {
    const unscored = card('Unscored findings', 'unscored');
    unscored.append(node('p', 'brief-note', 'Severity review required. These findings have no supported risk order.'));
    for (const finding of brief.unscoredFindings) {
      const row = node('div', 'brief-priority');
      row.append(node('span', 'brief-band', 'Unscored'), node('strong', '', finding.title || finding.finding_id), node('span', 'brief-provenance', finding.finding_id), node('p', '', finding.reason));
      if (finding.storedScore?.risk != null) row.append(node('p', 'brief-note', `Stored values for audit only: risk ${finding.storedScore.risk} / band ${finding.storedScore.band || 'not recorded'}.`));
      unscored.append(row);
    }
    const button = node('button', 'brief-link', 'Inspect unscored findings');
    button.type = 'button'; button.addEventListener('click', () => onInspect('queue'));
    unscored.append(button);
    holder.append(unscored);
  }
  const ai = card('AI insights', 'ai');
  ai.append(node('span', 'brief-ai-state', brief.ai.status));
  if (brief.ai.model) ai.append(node('p', 'brief-provenance', `${brief.ai.model}${brief.ai.confidence ? ` / ${brief.ai.confidence} confidence` : ''}`));
  ai.append(node('p', '', brief.ai.summary || (brief.ai.error ? 'Rejected AI output is withheld. Scanner evidence remains available.' : 'No validated model conclusion for this selection. Use Run to request an analysis.')));
  if (brief.ai.effect) {
    ai.append(node('h4', '', 'How context changes the interpretation'), node('p', '', brief.ai.effect));
    ai.append(node('p', 'brief-citations', `Evidence ${brief.ai.citations.join(', ')}`));
  }
  if (brief.actions.length) {
    ai.append(node('h4', '', 'Next verification'));
    const list = node('ol', 'brief-actions');
    for (const action of brief.actions.slice(0, 3)) {
      const item = node('li');
      item.append(node('strong', '', action.action), node('p', '', action.reason), node('span', 'brief-citations', `${action.batch ? `Batch ${action.batch} / ` : ''}${(action.evidence_ids || []).join(', ')}`));
      list.append(item);
    }
    ai.append(list);
  }
  const aiButton = node('button', 'brief-link', 'Open analysis and citations');
  aiButton.type = 'button'; aiButton.addEventListener('click', () => onInspect('analyst'));
  ai.append(aiButton); holder.append(ai);
  const coverage = card('Coverage & unknowns', 'coverage');
  const list = node('ul');
  for (const gap of [...brief.coverage, ...brief.ai.uncertainties]) list.append(node('li', '', gap));
  coverage.append(list); holder.append(coverage);
}
