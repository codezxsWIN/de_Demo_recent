import {SIZE, NODE_SPECS, EDGES, ICONS, buildNodes, connectedNodeIds, nodeDetails, evidenceKind, evidenceBasis, finishFailedExecution, executionCounts, stageStateLabel, isLiveAssessmentResult, scanCompletionLabel, nodeExecutionEntry} from './workflow-data.js';
import {readLayout, moveNode, positionNodes, pathNodeIds} from './workflow-layout.js';
import {requestAnalystProgress} from './analyst-client.js';
import {PREVIEW_SCENARIOS} from './workflow-preview.js';
import {mountScanPlanner} from './scan-plan-client.js';
import {mountEvidenceRequests} from './evidence-request-client.js';
import {buildInsightBrief, renderInsightBrief, renderInsightHighlights, reviewFindingPriorities, captureProvenanceLines} from './workflow-insights.js';
import {renderAssessmentOverview} from './workflow-overview.js';
import {renderSelfDefence} from './self-defence.js';
import {renderWorkflowActivity, renderActivityContext} from './workflow-activity.js';

function showWorkspace(page) {
  document.body.dataset.workspace = page;
  document.querySelectorAll('[data-workspace-page]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.workspacePage === page)));
  document.getElementById('assessment-overview').hidden = page === 'workflow' || page === 'self-defence';
  document.getElementById('self-defence-workspace').hidden = page !== 'self-defence';
  document.querySelector('.flow-workspace').hidden = page !== 'workflow';
  document.getElementById('assessment-highlights').hidden = page !== 'workflow';
  const skip = document.querySelector('.skip');
  skip.href = page === 'workflow' ? '#viewport' : '#assessment-overview';
  skip.textContent = page === 'workflow' ? 'Skip to workflow canvas' : 'Skip to assessment overview';
  if (page === 'self-defence') { skip.href = '#self-defence-workspace'; skip.textContent = 'Skip to device assessment'; }
  if (page === 'workflow') requestAnimationFrame(fit);
}
document.querySelectorAll('[data-workspace-page]').forEach(button => button.addEventListener('click', () => showWorkspace(button.dataset.workspacePage)));

const runSelect = document.getElementById('workflow-run');
const hostSelect = document.getElementById('workflow-host');
const findingSelect = document.getElementById('workflow-finding');
const viewport = document.getElementById('viewport');
const graph = document.getElementById('graph');
const message = document.getElementById('loading-state');
const inspector = document.getElementById('node-inspector');
const content = document.getElementById('node-content');
const runPanel = document.getElementById('run-panel');
const runTargets = document.getElementById('run-targets');
const runProgress = document.getElementById('run-progress');
const runSearch = document.getElementById('run-target-search');
const providerSelect = document.getElementById('analyst-provider');
const svgNamespace = 'http://www.w3.org/2000/svg';
const narrowViewport = matchMedia('(max-width: 960px)');
const layoutKey = 'vulnassess.workflow.layout.v3';
function loadLayout() {
  try { return readLayout(JSON.parse(localStorage.getItem(layoutKey)), NODE_SPECS, SIZE); }
  catch { return {}; }
}
const view = {assessment: null, scope: null, weights: null, host: '', finding: '', node: '', mode: narrowViewport.matches ? 'stages' : 'canvas', modeChosen: false, scale: 1, panX: 0, panY: 0, load: 0, analyses: new Map(), layout: loadLayout()};
function saveLayout() {
  try { localStorage.setItem(layoutKey, JSON.stringify(view.layout)); }
  catch { document.getElementById('workflow-announcement').textContent = 'Layout changed for this session, but could not be saved in this browser.'; }
}
const analysisStages = [
  ['records', 'Read stored assessment'],
  ['model', 'Check AI configuration'],
  ['evidence', 'Gather target evidence'],
  ['coverage', 'Review coverage gaps'],
  ['prompt', 'Prepare grounded request'],
  ['generation', 'Generate response'],
  ['validation', 'Validate citations and scores'],
];
const runState = {busy: false, stop: false, targets: [], selected: new Set(), entries: new Map()};
const liveStages = [
  ['scope', 'Authorise target'], ['model', 'Prepare AI provider'], ['scanner', 'Discover services'],
  ['endpoint_scan', 'Verify requested port'], ['nikto', 'Run bounded Nikto checks'],
  ['canonical', 'Normalize evidence'], ['nvd', 'Look up NVD CVEs'],
  ['epss', 'Look up EPSS scores'], ['kev', 'Check CISA KEV catalog'],
  ['intel', 'Enrich findings'], ['context', 'Infer context'],
  ['score', 'Calculate deterministic risk'], ['queue', 'Prioritize findings'],
  ['rationale', 'Explain scores'],
  ...analysisStages.filter(([id]) => !['records', 'model'].includes(id)),
  ['report', 'Build live assessment summary'],
];
const liveState = {active: false, busy: false, previewState: 'idle', previewScenario: null, target: '', provider: '', reuseRecent: false, stages: new Map(), scan: null, result: null, error: '', needsReview: false};
const stageNode = {scope: 'scope', scanner: 'nmap', endpoint_scan: 'nmap', nikto: 'nikto', canonical: 'canonical', nvd: 'nvd', epss: 'epss', kev: 'kev', intel: 'intel', context: 'context', score: 'score', queue: 'queue', rationale: 'rationale', model: 'analyst', evidence: 'analyst', coverage: 'analyst', prompt: 'analyst', generation: 'analyst', validation: 'analyst', report: 'report'};
const retainedStages = new Set(['scanner', 'endpoint_scan', 'canonical', 'context']);
const displayStageState = (id, state) => liveState.savedCapture && state === 'complete' && retainedStages.has(id) ? 'Retained' : stageStateLabel(state);
let previewSequence = 0;
let briefSignature = '';
let activitySignature = '';
const executionSteps = () => liveState.previewState !== 'idle' && liveState.previewScenario
  ? liveState.previewScenario.steps
  : liveStages.map(([id, label]) => ({id, node: stageNode[id], label: liveState.reuseRecent && id === 'scanner' ? 'Reuse recent Nmap evidence' : liveState.reuseRecent && id === 'context' ? 'Reuse recorded context' : label}));

function appendInvestigation(holder, analyst) {
  const evidence = new Map((analyst.evidence || []).map(item => [item.id, item]));
  for (const investigation of analyst.analysis.investigations || []) {
    const section = element('section', 'ai-investigation');
    section.append(element('h3', '', 'AI investigation · unverified'));
    section.append(element('p', '', `Hypothesis: ${investigation.hypothesis}`));
    section.append(element('p', '', `Verify: ${investigation.verification}`));
    section.append(element('p', '', `Alternative: ${investigation.alternative}`));
    const citations = element('ul', 'ai-investigation-citations');
    for (const id of investigation.evidence_ids) {
      const item = evidence.get(id);
      citations.append(element('li', '', `${id} · ${item?.kind || 'evidence'}: ${item?.text || 'Citation unavailable'}`));
    }
    section.append(citations);
    holder.append(section);
  }
}

function appendUnscoredFindings(holder, findings) {
  if (!findings.length) return;
  holder.append(element('h3', '', 'Unscored findings · severity review required'));
  holder.append(element('p', 'boundary-note', 'These findings have no supported severity or risk order.'));
  const list = element('ul');
  for (const item of findings) {
    const row = element('li', '', `${item.title || item.finding_id} · Unscored · ${item.finding_id} · ${item.reason || 'No canonical score recorded.'}${item.finding_evidence_id ? ` [${item.finding_evidence_id}]` : ''}`);
    if (item.storedScore?.risk != null) row.append(element('p', 'boundary-note', `Stored values for audit only: risk ${item.storedScore.risk} / band ${item.storedScore.band || 'not recorded'}.`));
    list.append(row);
  }
  holder.append(list);
}

function appendDecisionFrame(holder, frame) {
  if (!frame) return;
  const section = element('section', 'decision-frame');
  section.append(element('h3', '', 'Context-aware priority boundary'));
  const context = frame.context || {};
  section.append(element('p', '', `Recorded role: ${String(context.role?.value || 'unknown').replaceAll('_', ' ')} · exposure: ${String(context.exposure?.value || 'unknown').replaceAll('_', ' ')}.`));
  const controls = Object.entries(context.controls || {}).map(([name, feature]) => `${name.replaceAll('_', ' ')}: ${feature.value === null ? 'unknown' : String(feature.value)}`);
  if (controls.length) section.append(element('p', '', `Recorded controls · ${controls.join(' · ')}`));
  const limits = frame.coverage_review?.limits || [];
  if (limits.length) {
    section.append(element('h3', '', 'Coverage and unknowns'));
    const coverageList = element('ul', '');
    for (const limit of limits) coverageList.append(element('li', '', limit));
    section.append(coverageList);
  }
  const scannerCoverage = Object.entries(frame.scanner_coverage || {});
  if (scannerCoverage.length) {
    section.append(element('h3', '', 'Scanner coverage'));
    const scanners = element('ul', '');
    for (const [tool, status] of scannerCoverage) scanners.append(element('li', '', `${tool}: ${status}`));
    section.append(scanners);
  }
  if (frame.mode === 'verification_only') {
    section.append(element('p', 'boundary-note', 'No vulnerability findings were recorded, so there is no scored finding-priority queue. The services below are verification candidates, not ranked vulnerabilities.'));
    const list = element('ul', '');
    for (const item of frame.verification_candidates || []) list.append(element('li', '', `${item.port}/${item.protocol} ${item.service || 'service'} · ${item.evidence_id}`));
    section.append(list);
  } else {
    const reviewed = reviewFindingPriorities(frame.priorities, frame.unscored_findings);
    section.append(element('p', '', reviewed.priorities.length ? 'Stored deterministic priority order · AI does not change these scores.' : 'Findings exist, but no supported risk scores are available. No risk order is claimed.'));
    const list = element('ol', '');
    for (const item of reviewed.priorities) {
      const cvss = item.base_score == null ? '' : ` · CVSS base ${item.base_score} → environmental ${item.env_score ?? 'unavailable'}`;
      const changes = Object.entries(item.env_modifications || {}).map(([metric, value]) => `${metric}:${value}`).join(', ');
      list.append(element('li', '', `${item.title} · ${item.band} ${item.risk}${cvss}${changes ? ` · recorded environmental changes ${changes}` : ''} · ${item.reason || 'No stored reason'} [${item.score_evidence_id}]`));
    }
    section.append(list);
    appendUnscoredFindings(section, reviewed.unscoredFindings);
  }
  holder.append(section);
}

function appendModelContextEffect(holder, analyst) {
  const effect = analyst?.analysis?.context_effect;
  if (!effect) return;
  const section = element('section', 'analysis-context-effect');
  section.append(element('h3', '', 'AI context effect · cited interpretation'));
  section.append(element('p', '', effect.explanation));
  const evidence = new Map((analyst.evidence || []).map(item => [item.id, item]));
  appendQuotes(section, effect.evidence_ids.map(id => ({label: `Citation ${id}`, quote: evidence.get(id)?.text || 'Citation unavailable', source: analyst.model})));
  holder.append(section);
}

function appendLiveSummary(holder, summary) {
  if (summary?.self_defence) renderSelfDefence(document.getElementById('device-results'), summary, liveState.busy);
  if (!summary) return;
  const section = element('section', 'decision-frame');
  const reviewed = reviewFindingPriorities(summary.priorities, summary.unscored_findings);
  if (summary.self_defence) {
    const device = summary.self_defence;
    section.append(element('h3', '', 'Your device · protection check'));
    section.append(element('p', '', device.boundary));
    section.append(element('p', '', `Checked ${device.checked_at}`));
    for (const check of device.checks) {
      const card = element('section', 'recorded-analysis-card');
      card.append(element('h4', '', `${check.title} · ${check.state}`));
      card.append(element('p', '', check.observation));
      card.append(element('p', '', `Precaution: ${check.precaution}`));
      section.append(card);
    }
    section.append(element('p', 'boundary-note', device.limitations));
  }
  if (summary.historical_capture) {
    section.append(element('h3', '', 'SAVED SCAN EVIDENCE — NOT A NEW SCAN'));
  }
  for (const line of captureProvenanceLines(summary)) section.append(element('p', 'boundary-note', line));
  section.append(element('h3', '', summary.validated_ai_summary ? summary.historical_capture ? 'Updated assessment summary' : 'Live assessment summary' : summary.ai_status ? `Evidence-only summary · AI ${summary.ai_status.replaceAll('_', ' ')}` : liveState.error ? 'Evidence-only summary · AI output rejected or unavailable' : 'Evidence-only summary · AI pending'));
  if (summary.ai_attempts?.length) {
    const names = {openrouter: 'DeepSeek / OpenRouter', google: 'Google Gemini', groq: 'Groq GPT-OSS', groq_qwen: 'Groq Qwen', ollama: 'Local Ollama'};
    section.append(element('h3', '', 'AI provider attempts'));
    const attempts = element('ol');
    for (const attempt of summary.ai_attempts) attempts.append(element('li', '', `${names[attempt.provider] || attempt.provider}: ${attempt.status.replaceAll('_', ' ')}${attempt.detail ? ` — ${attempt.detail}` : ''}`));
    section.append(attempts);
  }
  section.append(element('p', '', summary.conclusion));
  if (summary.saved_capture_id) {
    const saved = element('a', 'quiet-link', 'Open saved assessment · read-only');
    saved.href = `/captures/${encodeURIComponent(summary.saved_capture_id)}`;
    section.append(saved);
  }
  if (summary.persistence_warning) section.append(element('p', 'boundary-note', summary.persistence_warning));
  if (summary.ai_coverage) {
    const coverage = summary.ai_coverage;
    section.append(element('p', '', `AI coverage: ${coverage.findings_included}/${coverage.findings_total} findings included across ${coverage.batch_count} validated batches. Citations apply within each batch; cross-batch relationships were not assessed.`));
  }
  section.append(element('p', '', `${summary.service_count ?? 'Unknown'} observed services · ${summary.finding_count ?? 'Unknown'} vulnerability findings · ${reviewed.priorities.length} deterministic priorities · ${reviewed.unscoredFindings.length} unscored findings`));
  appendUnscoredFindings(section, reviewed.unscoredFindings);
  if (summary.cve_evidence?.length) {
    section.append(element('h3', '', 'Detected CVEs · evidence → intelligence → priority'));
    for (const row of summary.cve_evidence) {
      const card = element('section', 'recorded-analysis-card');
      card.append(element('h4', '', `${row.cve_id} · ${row.title}`));
      card.append(element('p', '', `Detection: ${row.tool}${row.port == null ? '' : ` · TCP/${row.port}`} · finding ${row.finding_id}`));
      card.append(element('blockquote', '', row.evidence || 'No evidence excerpt recorded'));
      const dates = row.feed_dates || {};
      const values = element('ul');
      values.append(element('li', '', `NVD CVSS base: ${row.cvss_base ?? 'unavailable'} · snapshot ${dates.nvd || 'unknown'}`));
      values.append(element('li', '', `FIRST EPSS probability: ${row.epss == null ? 'unavailable' : `${(row.epss * 100).toFixed(3)}%`} · snapshot ${dates.epss || 'unknown'}`));
      const kev = {listed: 'Listed', not_listed: 'Checked — not listed', not_checked: 'Not checked'}[row.kev_status] || 'Unknown';
      values.append(element('li', '', `CISA KEV: ${kev} · snapshot ${dates.kev || 'unknown'}`));
      const unscored = reviewed.unscoredFindings.find(item => item.finding_id === row.finding_id);
      const priority = reviewFindingPriorities(row.priority ? [{...row.priority, finding_id: row.finding_id}] : []).priorities[0];
      values.append(element('li', '', `Deterministic priority: ${!unscored && priority ? `${priority.risk} / ${priority.band}` : 'Unscored — no supported CVE-specific priority'}`));
      card.append(values);
      if (row.raw_path) card.append(element('p', 'boundary-note', `Raw evidence retained: ${row.raw_path}`));
      card.append(element('p', 'boundary-note', 'Intelligence enriches the detected finding; it does not prove exploitation. AI cannot change this priority.'));
      section.append(card);
    }
  }
  if (summary.scanner_coverage) {
    section.append(element('h3', '', summary.historical_capture ? 'Scanner coverage of the retained capture — not executed now' : 'What actually ran'));
    const scanners = element('ul');
    for (const [scanner, coverage] of Object.entries(summary.scanner_coverage)) scanners.append(element('li', '', `${scanner}: ${coverage}`));
    section.append(scanners);
  }
  section.append(element('p', '', `Context: ${String(summary.context?.role || 'unknown').replaceAll('_', ' ')} role · ${String(summary.context?.exposure || 'unknown').replaceAll('_', ' ')} exposure. This guides verification, not vulnerability certainty.`));
  const intel = summary.intelligence || {};
  const intelMode = {on_demand: 'on-demand public CVE lookup', offline: 'local offline snapshots', unavailable: 'unavailable', not_applicable: 'not applicable (no scanner-named CVE)'}[intel.mode] || 'unknown';
  section.append(element('p', '', `Intelligence: ${intelMode} · ${intel.checked_cves?.length || 0} CVE IDs checked · ${intel.matched_findings || 0} findings enriched. NVD lookups are not a full-catalog scan.`));
  section.append(element('h3', '', 'Coverage gaps'));
  const gaps = element('ul');
  for (const gap of summary.coverage_gaps || []) gaps.append(element('li', '', gap));
  section.append(gaps);
  if (summary.next_actions?.length) {
    section.append(element('h3', '', 'What to verify next'));
    const actions = element('ol');
    for (const action of summary.next_actions) actions.append(element('li', '', `${action.action} — ${action.reason} [${action.evidence_ids.join(', ')}]`));
    section.append(actions);
  }
  if (summary.uncertainties?.length) section.append(element('p', '', `Uncertainty: ${summary.uncertainties.join(' · ')}`));
  holder.append(section);
}

function appendBatchReview(holder, result) {
  if (!result?.batches?.length) return false;
  const coverage = result.batch_coverage;
  holder.append(element('h3', '', `AI review · ${coverage.findings_included}/${coverage.findings_total} findings · ${coverage.batch_count} validated batches`));
  holder.append(element('p', '', 'Each batch has its own evidence citations and confidence. No cross-batch synthesis is claimed.'));
  for (const [index, batch] of result.batches.entries()) {
    const section = element('section', 'recorded-analysis-card');
    section.append(element('h3', '', `Batch ${index + 1} · ${batch.finding_coverage.included_ids.length} findings · ${batch.model} · ${batch.analysis.confidence} confidence`));
    section.append(element('p', '', batch.analysis.summary));
    appendDecisionFrame(section, batch.decision_frame);
    appendModelContextEffect(section, batch);
    appendInvestigation(section, batch);
    const evidence = new Map(batch.evidence.map(item => [item.id, item]));
    for (const action of batch.analysis.recommended_actions) {
      const record = element('div', 'analysis-action');
      record.append(element('h4', '', action.action), element('p', '', action.reason));
      appendQuotes(record, action.evidence_ids.map(id => ({label: `Batch ${index + 1} · ${id}`, quote: evidence.get(id)?.text || 'Citation unavailable', source: batch.model})));
      section.append(record);
    }
    for (const item of batch.analysis.correlations || []) {
      section.append(element('p', '', item.observation));
      appendQuotes(section, item.evidence_ids.map(id => ({label: `Batch ${index + 1} · ${id}`, quote: evidence.get(id)?.text || 'Citation unavailable', source: batch.model})));
    }
    for (const uncertainty of batch.analysis.uncertainties) section.append(element('p', 'boundary-note', uncertainty));
    holder.append(section);
  }
  return true;
}

function renderLiveResult() {
  const holder = document.getElementById('live-result');
  holder.replaceChildren();
  holder.hidden = !(liveState.scan || liveState.result || liveState.error);
  const scan = liveState.scan || liveState.result;
  if (scan) {
    holder.append(element('h3', '', `Live scan · ${scan.target} (${scan.resolved_ip})`));
    const services = scan.services || [];
    holder.append(element('p', '', `${services.length} open services · ${scan.finding_count} findings from ${scan.scan_profile || 'the completed scanner path'}`));
    const list = element('ul');
    for (const service of services) {
      list.append(element('li', '', `${service.port}/${service.protocol} ${service.name || 'unknown'} · ${service.product || 'product unknown'} ${service.version || ''}`));
    }
    holder.append(list);
    if (!liveState.result?.analyst?.batches) appendDecisionFrame(holder, scan.decision_frame || liveState.result?.decision_frame);
  }
  if (liveState.result?.analyst && !appendBatchReview(holder, liveState.result.analyst)) {
    const analyst = liveState.result.analyst;
    holder.append(element('h3', '', `${analyst.model} · confidence ${analyst.analysis.confidence}`));
    holder.append(element('p', '', analyst.analysis.summary));
    appendModelContextEffect(holder, analyst);
    appendInvestigation(holder, analyst);
    if (!liveState.result.assessment_summary) {
      for (const action of analyst.analysis.recommended_actions) {
        holder.append(element('p', 'analysis-action', `${action.order}. ${action.action} — ${action.reason} [${action.evidence_ids.join(', ')}]`));
      }
      for (const uncertainty of analyst.analysis.uncertainties) holder.append(element('p', '', `Uncertainty: ${uncertainty}`));
    }
  }
  appendLiveSummary(holder, liveState.result?.assessment_summary || liveState.scan?.assessment_summary);
  const plan = liveState.result?.scan_plan;
  if (plan) {
    holder.append(element('h3', '', 'Approved scan plan'));
    holder.append(element('p', '', `Plan ${plan.state.replaceAll('_', ' ')} · SHA-256 ${plan.plan_hash}`));
    if (plan.state === 'needs_reapproval') holder.append(element('p', 'analysis-error', 'An approved step was not completed. Collected evidence is retained; review a fresh plan before another execution.'));
  }
  if (liveState.error) holder.append(element('p', 'analysis-error', liveState.error));
}

function renderLiveProgress() {
  const list = document.getElementById('live-progress');
  list.replaceChildren();
  for (const {id, label} of executionSteps()) {
    const entry = liveState.stages.get(id) || {state: 'pending', detail: 'Waiting'};
    const item = element('li', `run-progress-item state-${entry.state}`);
    item.append(element('strong', '', label), element('span', '', displayStageState(id, entry.state)));
    item.append(element('small', '', entry.detail));
    list.append(item);
  }
  document.getElementById('start-live-run').disabled = liveState.busy;
  document.getElementById('new-target').disabled = liveState.busy;
  providerSelect.disabled = liveState.busy;
  const previewButton = document.getElementById('preview-flow');
  previewButton.disabled = liveState.busy && liveState.previewState !== 'running';
  previewButton.setAttribute('aria-pressed', String(liveState.previewState === 'running'));
  previewButton.textContent = liveState.previewState === 'running' ? 'Stop preview' : ['complete', 'stopped', 'blocked'].includes(liveState.previewState) ? 'Replay preview' : 'Preview flow';
  document.getElementById('preview-scenario').disabled = liveState.busy;
}

function syncLiveSelection() {
  if (!liveState.active || liveState.previewState !== 'idle') return;
  const scan = liveState.result || liveState.scan;
  const ip = scan?.resolved_ip;
  const option = element('option', '', `${liveState.target}${ip ? ` · ${ip}` : ' · awaiting authorization'}`);
  option.value = ip || '';
  hostSelect.replaceChildren(option);
  hostSelect.disabled = true;
  // Live records are separate from the stored assessment; do not filter one
  // with the other's IDs or falsely claim the live capture has been imported.
  findingSelect.replaceChildren(element('option', '', 'Live findings · see assessment summary'));
  findingSelect.disabled = true;
  document.getElementById('canvas-caption').textContent = `${liveState.savedCapture ? 'Fresh review of saved evidence' : 'Live assessment'} / ${liveState.target}`;
  document.getElementById('data-kind').textContent = liveState.savedCapture ? 'SAVED EVIDENCE · FRESH REVIEW' : 'LIVE ASSESSMENT';
  const summary = liveState.result?.assessment_summary;
  document.getElementById('record-summary').textContent = scan
    ? `1 live target / ${scan.finding_count ?? 0} findings / ${summary?.priorities?.length ?? 0} scored`
    : 'Live target · awaiting scan evidence';
}

function renderLiveExecution() {
  syncLiveSelection();
  const rail = document.getElementById('live-execution');
  rail.hidden = !liveState.active;
  if (!liveState.active) return;
  const isPreview = liveState.previewState !== 'idle';
  const steps = executionSteps();
  document.getElementById('live-path-boundary').hidden = isPreview;
  document.getElementById('live-path-boundary').textContent = liveState.reuseRecent
    ? 'AI-only re-analysis of retained scan evidence. Capture hashes and current scope are checked when loading from disk. No scanner, publisher fetch or score recalculation is launched; observations keep their recorded age.'
    : liveState.savedCapture
    ? 'This review verifies saved capture hashes and current scope, then fetches fresh NVD, EPSS and CISA KEV data, recalculates deterministic priorities and validates a new AI response. No target scanner is launched. Scanner evidence and context retain their original capture date.'
    : 'This run performs light Nmap discovery, verifies an explicitly supplied URL port, and runs bounded Nikto checks only for an exact in-scope asset tagged environment:test. AI analyzes collected scanner evidence; scores remain deterministic. Nessus reports are imported, not launched.';
  const context = document.getElementById('live-execution-context');
  context.hidden = !isPreview;
  context.textContent = isPreview ? liveState.previewScenario.context : '';
  document.getElementById('live-execution-mode').textContent = isPreview ? 'SIMULATED PREVIEW / NO SCAN OR MODEL CALL' : liveState.reuseRecent ? 'AI RE-ANALYSIS / RETAINED SCAN EVIDENCE / NO SCAN' : liveState.savedCapture ? 'SAVED CVE EVIDENCE / FRESH INTELLIGENCE + AI / NO SCAN' : 'LIVE ASSESSMENT / SCANNER + AI EVENT STREAM';
  const current = [...liveState.stages.entries()].find(([, entry]) => entry.state === 'running');
  const counts = executionCounts(liveState.stages, steps.length);
  const retained = liveState.savedCapture ? [...liveState.stages].filter(([id, event]) => retainedStages.has(id) && event.state === 'complete').length : 0;
  const finished = counts.executed + counts.notApplicable + counts.failed;
  const currentLabel = current ? steps.find(step => step.id === current[0])?.label : liveState.error ? 'Run stopped' : liveState.result ? scanCompletionLabel(liveState.result, liveState.savedCapture) : isPreview && finished === steps.length ? 'Preview complete' : 'Preparing run';
  document.getElementById('live-execution-title').textContent = isPreview
    ? `${liveState.previewScenario.label} · ${liveState.previewState === 'complete' ? 'complete' : liveState.previewState === 'stopped' ? 'stopped' : liveState.previewState === 'blocked' ? 'blocked' : currentLabel}`
    : `${liveState.target} · ${currentLabel}`;
  document.getElementById('live-execution-count').textContent = isPreview
    ? `${finished} / ${steps.length} simulated stages`
    : `${counts.executed - retained} executed${retained ? ` · ${retained} retained` : ''} · ${counts.notApplicable} not applicable · ${counts.failed} failed · ${counts.waiting} waiting${counts.running ? ` · ${counts.running} running` : ''}`;
  const last = [...liveState.stages.values()].at(-1);
  document.getElementById('live-execution-detail').textContent = current?.[1].detail
    || (isPreview ? last?.detail || `Preview ${liveState.previewState}. No scan or model call was made.`
      : liveState.error || (liveState.result ? liveState.result.analyst ? `${scanCompletionLabel(liveState.result, liveState.savedCapture)}. AI output validated against the collected evidence.` : `${scanCompletionLabel(liveState.result, liveState.savedCapture)}. AI ${liveState.result.ai_status?.replaceAll('_', ' ') || 'unavailable'} — evidence-only summary attached.` : 'Waiting for the next stage.'));
  const list = document.getElementById('live-execution-steps');
  list.replaceChildren();
  for (const [index, {id, label}] of steps.entries()) {
    const event = liveState.stages.get(id);
    const state = event?.state || 'pending';
    const item = element('li', `live-execution-step state-${state}`);
    item.append(element('span', 'live-step-state', displayStageState(id, state)));
    item.append(element('strong', '', `${String(index + 1).padStart(2, '0')} · ${label}`));
    let detail = event?.detail || (index === 0 ? (isPreview ? 'Preview will start here' : 'Waiting for authorization check') : 'Waiting for previous stage');
    if (id === 'scanner' && liveState.scan) {
      const services = liveState.scan.services.map(service => `${service.port}/${service.protocol} ${service.name || 'unknown'}${service.product ? ` · ${service.product}${service.version ? ` ${service.version}` : ''}` : ''}`);
      if (services.length) detail = `${detail} · ${services.join(' / ')}`;
    }
    if (id === 'validation' && liveState.result?.analyst?.analysis?.summary) {
      detail = `${detail} · ${liveState.result.analyst.analysis.summary}`;
    }
    if (state === 'error' && liveState.error) detail = liveState.error;
    item.title = detail;
    item.append(element('small', '', detail));
    list.append(item);
  }
  const output = document.getElementById('live-execution-output');
  output.replaceChildren();
  const analysis = liveState.result?.analyst;
  const frame = liveState.scan?.decision_frame || liveState.result?.decision_frame;
  document.getElementById('live-execution-details').hidden = !analysis && !frame && !liveState.result?.assessment_summary && !liveState.scan?.assessment_summary;
  if (!analysis?.batches) appendDecisionFrame(output, frame);
  appendLiveSummary(output, liveState.result?.assessment_summary || liveState.scan?.assessment_summary);
  if (analysis && !appendBatchReview(output, analysis)) {
    output.append(element('h3', '', `${analysis.model} · ${analysis.analysis.confidence} confidence · validated output`));
    output.append(element('p', '', analysis.analysis.summary));
    appendModelContextEffect(output, analysis);
    appendInvestigation(output, analysis);
    const actions = element('ul');
    for (const action of analysis.analysis.recommended_actions) {
      actions.append(element('li', '', `${action.order}. ${action.action} — ${action.reason} [${action.evidence_ids.join(', ')}]`));
    }
    for (const uncertainty of analysis.analysis.uncertainties) actions.append(element('li', '', `Uncertainty: ${uncertainty}`));
    if (actions.children.length) output.append(actions);
  }
}

function applyLiveRunToNodes(nodes) {
  if (!liveState.active) return nodes;
  for (const node of nodes) {
    const stage = liveState.previewState !== 'idle'
      ? executionSteps().filter(step => step.node === node.id).map(step => step.id)
      : liveStages.map(([id]) => id).filter(id => stageNode[id] === node.id);
    if (!stage.length) {
      if (liveState.previewState === 'idle') {
        node.state = 'not_in_mode';
        node.status = 'Not in this run mode · not used in the live assessment path';
      }
      continue;
    }
    const entry = nodeExecutionEntry(liveState.stages, stage);
    node.state = entry?.state || 'pending';
    if ((liveState.previewState === 'idle' || liveState.previewScenario === PREVIEW_SCENARIOS.light) && node.id === 'canonical') node.title = 'Normalize evidence';
    if ((liveState.previewState === 'idle' || liveState.previewScenario === PREVIEW_SCENARIOS.light) && node.id === 'report') node.title = 'Live assessment summary';
    node.status = liveState.previewState !== 'idle'
      ? entry?.state === 'running' ? 'Simulated step running' : entry?.state === 'complete' ? 'Simulated step complete' : entry?.state === 'skipped' ? 'Skipped (preview)' : entry?.state === 'error' ? 'Blocked (preview)' : 'Waiting (preview)'
      : entry?.detail || 'Waiting for upstream stage';
    if (node.id === 'nmap' && liveState.scan) {
      node.status = `${liveState.scan.services.length} services ${liveState.savedCapture ? 'in retained capture' : 'discovered'}${liveState.reuseRecent ? ' · reused scan' : ''}`;
    }
    if (node.id === 'analyst' && liveState.result?.analyst) {
      node.state = 'complete';
      node.status = `Response validated · ${liveState.result.analyst.analysis.confidence} confidence`;
    }
    if (node.id === 'analyst' && liveState.result && !liveState.result.analyst) {
      node.state = 'error';
      node.status = `AI ${liveState.result.ai_status.replaceAll('_', ' ')} · ${scanCompletionLabel(liveState.result, liveState.savedCapture).toLowerCase()}; evidence summary available`;
    }
    if (node.id === 'analyst' && liveState.error && !entry) {
      node.state = 'error';
      node.status = liveState.error;
    }
  }
  return nodes;
}

function liveFlowEdges() {
  if (!liveState.active) return [];
  const current = [...liveState.stages.entries()].find(([, entry]) => entry.state === 'running')?.[0];
  if (liveState.previewState !== 'idle') return executionSteps().find(step => step.id === current)?.edges || [];
  if (current === 'scanner') return ['scope:nmap'];
  if (current === 'endpoint_scan') return ['scope:nmap'];
  if (current === 'nikto') return ['scope:nikto'];
  if (current === 'canonical') return ['nmap:canonical'];
  if (current === 'intel') return ['canonical:intel'];
  if (current === 'context') return ['canonical:context'];
  if (current === 'score') return ['context:score'];
  if (current === 'queue') return ['score:queue'];
  if (current === 'rationale') return ['score:rationale'];
  if (['model', 'evidence', 'coverage', 'prompt', 'generation', 'validation'].includes(current)) return ['context:analyst'];
  if (current === 'report') return ['analyst:report'];
  return [];
}

function completedFlowEdges() {
  if (!liveState.active) return [];
  if (liveState.previewState !== 'idle') return [...new Set(executionSteps()
    .filter(step => liveState.stages.get(step.id)?.state === 'complete')
    .flatMap(step => step.edges))];
  const completed = new Set();
  if (liveState.stages.get('scanner')?.state === 'complete') completed.add('scope:nmap');
  if (liveState.stages.get('nikto')?.state === 'complete') completed.add('scope:nikto');
  const done = id => liveState.stages.get(id)?.state === 'complete';
  if (done('canonical')) completed.add('nmap:canonical');
  if (done('canonical') && done('nikto')) completed.add('nikto:canonical');
  if (done('intel') && done('canonical')) completed.add('canonical:intel');
  if (done('context')) completed.add('canonical:context');
  if (done('score')) completed.add('context:score');
  if (done('queue')) completed.add('score:queue');
  if (done('rationale')) completed.add('score:rationale');
  if (done('context') && ['evidence', 'coverage', 'prompt', 'generation', 'validation'].some(id => liveState.stages.has(id))) completed.add('context:analyst');
  if (done('report')) {
    completed.add('canonical:report');
    if (done('queue')) completed.add('queue:report');
    if (done('rationale')) completed.add('rationale:report');
    if (done('validation')) completed.add('analyst:report');
  }
  return [...completed];
}

// ==================== RUN ANALYSIS: LIVE RUN HANDLER (START) ====================
async function startLiveRun(planBinding = null) {
  if (liveState.busy) return;
  const target = document.getElementById('live-run-mode').value === 'self' ? 'self' : document.getElementById('new-target').value.trim();
  const provider = providerSelect.value;
  const reuseRecent = document.getElementById('live-run-mode').value === 'reuse';
  const replaySaved = document.getElementById('live-run-mode').value === 'saved';
  if (!target) {
    document.getElementById('target-check-result').textContent = 'Enter a target address first.';
    return;
  }
  if (provider !== 'ollama' && !document.getElementById('share-evidence').checked) {
    document.getElementById('target-check-result').textContent = 'Confirm evidence sharing before using a cloud model.';
    return;
  }
  liveState.busy = true;
  if (target === 'self') {
    renderSelfDefence(document.getElementById('device-results'), null, true);
    document.getElementById('device-progress').textContent = 'Starting local device check…';
  }
  showWorkspace(target === 'self' ? 'self-defence' : 'workflow');
  previewSequence++;
  liveState.previewState = 'idle';
  liveState.previewScenario = null;
  liveState.active = true;
  liveState.target = target;
  liveState.provider = provider;
  liveState.reuseRecent = reuseRecent;
  liveState.savedCapture = replaySaved || reuseRecent;
  liveState.stages = new Map();
  liveState.scan = null;
  liveState.result = null;
  liveState.error = '';
  liveState.needsReview = false;
  renderLiveProgress();
  renderLiveExecution();
  renderLiveResult();
  fitPreviewPath();
  runPanel.hidden = true;
  document.getElementById('open-run').setAttribute('aria-expanded', 'false');
  if (target !== 'self') {
    viewport.focus({preventScroll: true});
  }
  const accept = event => {
    if (target === 'self' && event.type === 'stage') document.getElementById('device-progress').textContent = event.detail;
    if (event.type === 'stage' && liveStages.some(([id]) => id === event.stage)
        && ['pending', 'running', 'complete', 'skipped', 'error'].includes(event.state) && typeof event.detail === 'string') {
      liveState.stages.set(event.stage, {state: event.state, detail: event.detail});
      renderLiveProgress();
      renderLiveExecution();
      renderGraph();
    } else if (event.type === 'scan' && event.scan && Array.isArray(event.scan.services)) {
      liveState.scan = event.scan;
      renderLiveResult();
      renderLiveExecution();
      renderGraph();
    } else if (event.type === 'result' && isLiveAssessmentResult(event.result)) {
      liveState.result = event.result;
      renderLiveResult();
      renderLiveExecution();
      renderGraph();
    } else if (event.type === 'needs-review' && typeof event.message === 'string') {
      const failure = new Error(event.message);
      failure.name = 'NeedsReviewError';
      throw failure;
    } else if (event.type === 'error' && typeof event.message === 'string') {
      throw new Error(event.message);
    } else {
      throw new Error('Invalid live assessment event.');
    }
  };
  try {
    const response = await fetch('/api/live-assessment/events', {
      method: 'POST', cache: 'no-store', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-VulnAssess-Action': 'live-assessment'},
      body: JSON.stringify({target, provider, share_evidence: provider !== 'ollama', reuse_recent: reuseRecent, replay_saved: replaySaved, allow_fallback: document.getElementById('allow-fallback').checked, event_version: 3, ...(planBinding || {})}),
    });
    if (!response.ok) {
      const failure = await response.json().catch(() => null);
      throw new Error(failure?.error?.message || 'Live assessment request failed.');
    }
    if (!response.body) throw new Error('Live assessment stream is unavailable.');
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, {stream: true});
      if (buffer.length > 2_000_000) throw new Error('Live assessment response exceeded its size limit.');
      let newline;
      while ((newline = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (line) accept(JSON.parse(line));
      }
    }
    buffer += decoder.decode();
    if (buffer.trim()) accept(JSON.parse(buffer));
    if (!liveState.result) throw new Error('Live assessment ended without a scan result.');
  } catch (error) {
    liveState.error = error instanceof Error ? error.message : 'Live assessment failed.';
    liveState.needsReview = error instanceof Error && error.name === 'NeedsReviewError';
    liveState.stages = finishFailedExecution(liveState.stages, liveStages.map(([id]) => id), liveState.error);
    renderLiveResult();
    renderLiveExecution();
    renderGraph();
    document.getElementById('live-result').scrollIntoView({block: 'nearest'});
  } finally {
    liveState.busy = false;
    if (target === 'self') document.getElementById('device-progress').textContent = liveState.error || 'Device check complete. Review observed settings and the AI status below.';
    renderLiveProgress();
    renderLiveExecution();
    renderGraph();
    if (view.node === 'analyst') renderInspector();
    void refreshIntelStatus();
  }
}
// ==================== RUN ANALYSIS: LIVE RUN HANDLER (END) ======================

async function previewLiveFlow() {
  showWorkspace('workflow');
  if (liveState.previewState === 'running') {
    previewSequence++;
    const current = [...liveState.stages.entries()].find(([, entry]) => entry.state === 'running');
    if (current) liveState.stages.set(current[0], {state: 'pending', detail: 'Preview stopped here'});
    liveState.busy = false;
    liveState.previewState = 'stopped';
    renderLiveProgress();
    renderLiveExecution();
    renderGraph();
    return;
  }
  if (liveState.busy) return;
  const sequence = ++previewSequence;
  const scenario = PREVIEW_SCENARIOS[document.getElementById('preview-scenario').value] || PREVIEW_SCENARIOS.light;
  populateSelection();
  document.getElementById('canvas-caption').textContent = 'Simulated workflow preview / no live scan';
  document.getElementById('data-kind').textContent = 'SIMULATED PREVIEW';
  document.getElementById('record-summary').textContent = 'Preview data · not scan results';
  liveState.active = true;
  liveState.busy = true;
  liveState.previewState = 'running';
  liveState.previewScenario = scenario;
  liveState.target = '';
  liveState.provider = '';
  liveState.stages = new Map();
  liveState.scan = null;
  liveState.result = null;
  liveState.error = '';
  liveState.needsReview = false;
  renderLiveProgress();
  renderLiveExecution();
  renderLiveResult();
  fitPreviewPath();
  runPanel.hidden = true;
  document.getElementById('open-run').setAttribute('aria-expanded', 'false');
  document.getElementById('live-execution-title').focus({preventScroll: true});
  for (const step of scenario.steps) {
    if (sequence !== previewSequence) return;
    if (step.outcome === 'skipped') {
      liveState.stages.set(step.id, {state: 'skipped', detail: step.detail});
      renderLiveProgress();
      renderLiveExecution();
      renderGraph();
      continue;
    }
    liveState.stages.set(step.id, {state: 'running', detail: step.detail});
    renderLiveProgress();
    renderLiveExecution();
    renderGraph();
    await new Promise(resolve => setTimeout(resolve, 1250));
    if (sequence !== previewSequence) return;
    liveState.stages.set(step.id, {state: step.outcome, detail: step.detail});
    renderLiveProgress();
    renderLiveExecution();
    renderGraph();
    if (step.outcome === 'error') break;
  }
  if (sequence !== previewSequence) return;
  liveState.busy = false;
  liveState.previewState = [...liveState.stages.values()].some(entry => entry.state === 'error') ? 'blocked' : 'complete';
  renderLiveProgress();
  renderLiveExecution();
  renderGraph();
  document.getElementById('workflow-announcement').textContent = `${scenario.label} animation preview ${liveState.previewState}. No scan or model request was made.`;
}

function renderRunTargets() {
  const filter = runSearch.value.trim().toLowerCase();
  runTargets.replaceChildren();
  for (const host of view.assessment?.hosts || []) {
    const name = [host.ip, host.hostname].filter(Boolean).join(' · ');
    if (filter && !name.toLowerCase().includes(filter)) continue;
    const label = element('label', 'run-target');
    const input = element('input');
    input.type = 'checkbox';
    input.value = host.ip;
    input.checked = runState.selected.has(host.ip);
    input.disabled = runState.busy;
    label.append(input, element('span', '', name));
    runTargets.append(label);
  }
  if (!runTargets.children.length) runTargets.append(element('p', 'run-empty', 'No recorded target matches. Choose another assessment above to see its targets.'));
  document.getElementById('run-selection-note').textContent = `${runState.selected.size} selected · ${view.assessment?.hosts.length || 0} recorded in this assessment`;
}

function renderRunProgress() {
  runProgress.replaceChildren();
  const results = document.getElementById('recorded-analysis-results');
  results.replaceChildren();
  for (const host of runState.targets) {
    const entry = runState.entries.get(host) || {status: 'pending'};
    const item = element('li', `run-progress-item state-${entry.status}`);
    item.append(element('strong', '', host), element('span', '', entry.status === 'running' ? `${entry.stage || 'Preparing'} · ${entry.detail || 'Starting'}` : entry.status));
    if (entry.error) item.append(element('small', '', entry.error));
    runProgress.append(item);
    const analysis = view.analyses.get(`${view.assessment?.run.run_id}/${host}`)?.result;
    if (!analysis || !['complete', 'reused'].includes(entry.status)) continue;
    const card = element('section', 'recorded-analysis-card');
    card.append(element('h3', '', `Assessment · ${host}`));
    appendDecisionFrame(card, analysis.decision_frame);
    appendModelContextEffect(card, analysis);
    const actions = analysis.analysis?.recommended_actions || [];
    if (actions.length) {
      card.append(element('h3', '', analysis.decision_frame?.mode === 'verification_only' ? 'AI verification order · unscored' : 'AI remediation sequence · stored scores unchanged'));
      const actionList = element('ol', 'recorded-action-list');
      for (const action of actions) actionList.append(element('li', '', `${action.action} — ${action.reason} [${action.evidence_ids.join(', ')}]`));
      card.append(actionList);
    }
    const open = element('button', 'run-button', 'Open full context and AI assessment');
    open.type = 'button';
    open.addEventListener('click', () => {
      view.host = host;
      view.finding = '';
      hostSelect.value = host;
      populateFindings();
      updateLocation();
      runPanel.hidden = true;
      document.getElementById('open-run').setAttribute('aria-expanded', 'false');
      selectNode('analyst');
    });
    card.append(open);
    results.append(card);
  }
  document.getElementById('start-run').disabled = runState.busy;
  document.getElementById('stop-run').hidden = !runState.busy;
  if (!runState.busy) document.getElementById('stop-run').disabled = false;
}

async function startRun() {
  if (runState.busy || !view.assessment) return;
  const provider = providerSelect.value;
  if (provider !== 'ollama' && !document.getElementById('share-evidence').checked) {
    document.getElementById('run-selection-note').textContent = 'Confirm evidence sharing before using a cloud model.';
    return;
  }
  const hosts = [...runState.selected];
  if (!hosts.length) {
    document.getElementById('run-selection-note').textContent = 'Select at least one recorded target.';
    return;
  }
  runState.busy = true;
  runState.stop = false;
  runState.targets = hosts;
  runState.entries = new Map(hosts.map(host => [host, {status: 'pending'}]));
  renderRunTargets();
  renderRunProgress();
  const runId = view.assessment.run.run_id;
  for (const host of hosts) {
    if (runState.stop) {
      runState.entries.set(host, {status: 'stopped'});
      renderRunProgress();
      continue;
    }
    runState.entries.set(host, {status: 'running', stage: 'Read stored assessment'});
    renderRunProgress();
    if (view.assessment?.run.run_id === runId) {
      view.host = host;
      view.finding = '';
      hostSelect.value = host;
      populateFindings();
      updateLocation();
      renderGraph();
      renderInspector();
    }
    const cached = view.analyses.get(`${runId}/${host}`);
    const source = {openrouter: 'openrouter_deepseek_grounded_analysis', groq: 'groq_gpt_oss_120b_grounded_analysis', groq_qwen: 'groq_qwen3_8_27b_grounded_analysis', google: 'google_gemini_3_5_flash_lite_grounded_analysis', ollama: 'local_ollama_grounded_analysis'}[provider];
    const sameProvider = cached?.result?.source === source;
    const result = cached?.status === 'complete' && sameProvider ? cached : await analyzeTarget(host, runId, provider);
    runState.entries.set(host, result.status === 'complete' ? {status: sameProvider ? 'reused' : 'complete'} : {status: 'error', error: result.error});
    if (result.status !== 'complete') runState.stop = true;
    renderRunProgress();
  }
  runState.busy = false;
  renderRunTargets();
  renderRunProgress();
  const failed = [...runState.entries.values()].some(entry => entry.status === 'error');
  const providerLabel = {openrouter: 'DeepSeek', groq: 'Groq 120B', groq_qwen: 'Groq Qwen', google: 'Gemini', ollama: 'Local'}[provider];
  document.getElementById('workflow-announcement').textContent = `${providerLabel} analysis ${failed ? 'stopped after an error' : 'run finished'}. Scanner and stored scores were not changed.`;
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function svgElement(name, attributes = {}) {
  const node = document.createElementNS(svgNamespace, name);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  return node;
}

function icon(name) {
  const svg = svgElement('svg', {viewBox: '0 0 24 24', 'aria-hidden': 'true'});
  for (const path of ICONS[name] || ICONS.report) svg.append(svgElement('path', {d: path}));
  return svg;
}

async function getRecord(path) {
  const response = await fetch(path, {cache: 'no-store', credentials: 'same-origin'});
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error?.message || payload.reason || `Stored records unavailable: ${path}`);
  return payload;
}

function currentAnalysis() {
  return view.assessment ? view.analyses.get(`${view.assessment.run.run_id}/${view.host}`) : null;
}

function selection() { return {host: view.host, finding: view.finding}; }
function transform() {
  graph.style.transform = view.mode === 'stages' ? 'none' : `translate(${view.panX}px, ${view.panY}px) scale(${view.scale})`;
  document.getElementById('zoom-level').textContent = `${Math.round(view.scale * 100)}%`;
}

function setViewMode(mode) {
  view.mode = mode;
  viewport.dataset.view = mode;
  viewport.setAttribute('aria-label', mode === 'canvas' ? 'Assessment workflow canvas' : 'Assessment workflow stages');
  for (const button of document.querySelectorAll('[data-view-mode]')) button.setAttribute('aria-pressed', String(button.dataset.viewMode === mode));
  viewport.scrollTop = 0;
  fit();
}

function fit() {
  if (!view.assessment) return;
  const width = viewport.clientWidth;
  const height = viewport.clientHeight;
  // Filters sit above the canvas, so do not subtract their height a second time.
  const top = 20;
  const bottom = document.querySelector('.canvas-footer').offsetHeight + 40;
  const availableHeight = height - top - bottom;
  view.scale = Math.max(0.18, Math.min(1, (width - 52) / SIZE.width, availableHeight / SIZE.height));
  view.panX = (width - SIZE.width * view.scale) / 2;
  view.panY = top + Math.max(0, (availableHeight - SIZE.height * view.scale) / 2);
  transform();
}

async function refreshIntelStatus() {
  const status = document.getElementById('intel-cache-status');
  try {
    const payload = await getRecord('/api/intel-status');
    const labels = {cached: 'cached', stale: 'stale', fixture: 'test data only', offline_snapshot: 'local snapshot', missing: 'not cached', unavailable: 'unavailable'};
    const feeds = (payload.feeds || []).map(feed => `${feed.feed.toUpperCase()}: ${labels[feed.status] || 'unavailable'}${feed.status === 'cached' ? ` (${feed.rows} records, ${feed.date || 'date unknown'})` : ''}`);
    status.textContent = `Public intelligence · ${feeds.join(' · ')}. CVEs are looked up on demand only when scanner findings name them.`;
  } catch (_) {
    status.textContent = 'Public intelligence cache status unavailable; live lookups will report their own status.';
  }
}

function fitPreviewPath() {
  if (!view.assessment || view.mode !== 'canvas' || !liveState.active) return fit();
  const path = pathNodeIds(executionSteps(), ['scope', 'nmap', 'context', 'analyst']);
  const nodes = positionNodes(buildNodes(view.assessment, view.scope), view.layout).filter(node => path.has(node.id));
  if (!nodes.length) return fit();
  const left = Math.min(...nodes.map(node => node.x)) - 200;
  const right = Math.max(...nodes.map(node => node.x)) + 200;
  const topNode = Math.min(...nodes.map(node => node.y)) - 65;
  const bottomNode = Math.max(...nodes.map(node => node.y)) + 65;
  const width = viewport.clientWidth;
  const height = viewport.clientHeight;
  const top = 20;
  const bottom = document.querySelector('.canvas-footer').offsetHeight + 25;
  const availableHeight = height - top - bottom;
  view.scale = Math.max(.18, Math.min(1, (width - 40) / (right - left), availableHeight / (bottomNode - topNode)));
  view.panX = (width - (right - left) * view.scale) / 2 - left * view.scale;
  view.panY = top + Math.max(0, (availableHeight - (bottomNode - topNode) * view.scale) / 2) - topNode * view.scale;
  transform();
}

function zoom(factor, point = {x: viewport.clientWidth / 2, y: viewport.clientHeight / 2}) {
  const previous = view.scale;
  view.scale = Math.max(.18, Math.min(2.2, previous * factor));
  view.panX = point.x - (point.x - view.panX) * view.scale / previous;
  view.panY = point.y - (point.y - view.panY) * view.scale / previous;
  transform();
}

function edgePath(from, to) {
  const horizontal = Math.abs(to.x - from.x) > Math.abs(to.y - from.y) * .75;
  if (horizontal) {
    const direction = Math.sign(to.x - from.x) || 1;
    const start = {x: from.x + 52 * direction, y: from.y};
    const end = {x: to.x - 52 * direction, y: to.y};
    if (Math.abs(to.x - from.x) > 300 && Math.abs(to.y - from.y) < 60) {
      const lift = Math.min(from.y, to.y) - 120;
      return `M${start.x},${start.y} C${start.x},${lift} ${end.x},${lift} ${end.x},${end.y}`;
    }
    const middle = (start.x + end.x) / 2;
    return `M${start.x},${start.y} C${middle},${start.y} ${middle},${end.y} ${end.x},${end.y}`;
  }
  const side = Math.max(from.x, to.x) + 140;
  const start = {x: from.x + 52, y: from.y};
  const end = {x: to.x + 52, y: to.y};
  return `M${start.x},${start.y} C${side},${start.y} ${side},${end.y} ${end.x},${end.y}`;
}

function renderGraph() {
  if (!view.assessment) return;
  const brief = buildInsightBrief({assessment: view.assessment, host: view.host, finding: view.finding, live: liveState, storedAnalysis: currentAnalysis()});
  const activityServices = liveState.active
    ? liveState.result?.services || liveState.scan?.services || []
    : view.assessment.hosts.filter(host => !view.host || host.ip === view.host).flatMap(host => (host.services || []).map(service => ({...service, host_ip: host.ip})));
  const activityKey = JSON.stringify([brief, liveState.active, liveState.busy, liveState.error, [...liveState.stages], activityServices]);
  if (activityKey !== activitySignature) {
    renderWorkflowActivity(document.getElementById('workflow-activity'), brief, liveState, activityServices, selectNode);
    activitySignature = activityKey;
  }
  const signature = JSON.stringify(brief);
  if (signature !== briefSignature) {
    renderInsightBrief(document.getElementById('assessment-brief'), brief, selectNode);
    renderAssessmentOverview(document.getElementById('assessment-overview'), brief, selectNode);
    renderInsightHighlights(document.getElementById('assessment-highlights'), brief, selectNode);
    briefSignature = signature;
  }
  viewport.dataset.execution = liveState.active ? 'true' : 'false';
  viewport.dataset.preview = liveState.previewState !== 'idle' ? 'true' : 'false';
  const nodes = applyLiveRunToNodes(positionNodes(buildNodes(view.assessment, view.scope, selection(), currentAnalysis()), view.layout));
  const analysis = currentAnalysis();
  const currentLive = [...liveState.stages.entries()].find(([, entry]) => entry.state === 'running');
  document.getElementById('canvas-status').textContent = liveState.previewState !== 'idle'
    ? `Simulated preview / ${liveState.previewScenario.label} / ${currentLive ? executionSteps().find(step => step.id === currentLive[0])?.label : liveState.previewState}`
    : liveState.active
    ? `Live run / ${currentLive ? `${executionSteps().find(step => step.id === currentLive[0])?.label} · ${currentLive[1].detail}` : liveState.result ? `${scanCompletionLabel(liveState.result, liveState.savedCapture).toLowerCase()} · AI ${liveState.result.ai_status?.replaceAll('_', ' ') || 'validated'}` : liveState.needsReview ? 'Needs review · model output rejected' : liveState.error ? 'stopped · stage failed' : 'starting'}`
    : analysis?.status === 'running'
    ? `AI analyst / ${analysisStages.find(([id]) => id === analysis.stage)?.[1] || 'Starting'}`
    : analysis?.status === 'complete' ? 'AI analyst complete / stored scores unchanged'
    : analysis?.status === 'needs_review' ? 'Needs review / model output rejected / stored scores unchanged'
    : analysis?.status === 'error' ? 'AI analyst failed / stored scores unchanged'
    : 'Stored records / no pipeline execution';
  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  const connected = view.node ? connectedNodeIds(view.node) : null;
  const paths = document.getElementById('connections');
  paths.setAttribute('viewBox', `0 0 ${SIZE.width} ${SIZE.height}`);
  paths.replaceChildren();
  const definitions = svgElement('defs');
  const arrow = svgElement('marker', {id: 'flow-arrow', markerWidth: 6, markerHeight: 6, refX: 5, refY: 3, orient: 'auto', markerUnits: 'strokeWidth'});
  arrow.append(svgElement('path', {d: 'M0,0 L6,3 L0,6', class: 'arrow-fill'}));
  definitions.append(arrow);
  paths.append(definitions);
  const flowEdges = new Set(liveFlowEdges());
  const completedEdges = new Set(completedFlowEdges());
  const previewEdges = liveState.previewState !== 'idle'
    ? new Set(executionSteps().flatMap(step => step.edges)) : null;
  for (const edge of EDGES) {
    const from = nodeMap.get(edge.from);
    const to = nodeMap.get(edge.to);
    const missing = edge.optional || ['missing', 'optional'].includes(from.state) || ['missing', 'optional'].includes(to.state);
    const identity = `${edge.from}:${edge.to}`;
    const active = view.node === edge.from || view.node === edge.to;
    paths.append(svgElement('path', {d: edgePath(from, to), class: `connection${missing ? ' optional' : ''}${active ? ' highlighted' : ''}${view.node && !active && !liveState.active ? ' faded' : ''}${previewEdges && !previewEdges.has(identity) ? ' out-of-preview' : ''}`, 'marker-end': 'url(#flow-arrow)', 'data-edge': identity}));
    if (completedEdges.has(identity)) paths.append(svgElement('path', {d: edgePath(from, to), class: 'connection-flow-done', 'data-flow-complete': identity}));
    if (active) paths.append(svgElement('path', {d: edgePath(from, to), class: 'connection-trace', pathLength: 100}));
    if (flowEdges.has(identity)) paths.append(svgElement('path', {d: edgePath(from, to), class: 'connection-flow', pathLength: 100, 'data-live-edge': identity}));
  }
  for (const identity of ['nmap:context', 'context:analyst']) {
    if (!flowEdges.has(identity) && !completedEdges.has(identity)) continue;
    const [from, to] = identity.split(':');
    const flow = edgePath(nodeMap.get(from), nodeMap.get(to));
    paths.append(svgElement('path', {d: flow, class: 'connection optional', 'data-edge': identity}));
    if (completedEdges.has(identity)) paths.append(svgElement('path', {d: flow, class: 'connection-flow-done', 'data-flow-complete': identity}));
    if (flowEdges.has(identity)) paths.append(svgElement('path', {d: flow, class: 'connection-flow', pathLength: 100, 'data-live-edge': identity}));
  }
  const list = document.getElementById('node-list');
  list.replaceChildren();
  const previewPath = pathNodeIds(executionSteps(), ['scope', 'nmap', 'context', 'analyst']);
  for (const node of nodes) {
    const button = element('button', `flow-node group-${node.group} state-${node.state}`);
    button.type = 'button';
    button.dataset.node = node.id;
    if (previewPath.has(node.id)) button.dataset.executionPath = 'true';
    button.style.left = `${node.x}px`;
    button.style.top = `${node.y}px`;
    button.setAttribute('aria-label', `${node.title}: ${node.status}. Drag to arrange, or use Alt and arrow keys.`);
    button.title = `${node.title} / ${node.subtitle} / ${node.status} · Drag to arrange`;
    button.setAttribute('aria-pressed', String(view.node === node.id));
    if (view.node && !connected.has(node.id) && !liveState.active) button.classList.add('muted-node');
    const disc = element('span', 'node-disc');
    disc.append(icon(node.icon));
    const stateMark = element('span', 'node-state-mark');
    stateMark.setAttribute('aria-hidden', 'true');
    stateMark.textContent = node.state === 'error' ? '!' : node.state === 'complete' ? '✓' : '';
    disc.append(stateMark);
    button.append(disc, element('strong', 'node-title', node.title), element('span', 'node-subtitle', node.subtitle), element('span', 'node-status', node.status), element('span', 'node-inspect-hint', '↗'));
    button.addEventListener('keydown', event => {
      const offsets = {ArrowLeft: [-20, 0], ArrowRight: [20, 0], ArrowUp: [0, -20], ArrowDown: [0, 20]};
      if (view.mode !== 'canvas' || !event.altKey || !offsets[event.key]) return;
      event.preventDefault();
      const [dx, dy] = offsets[event.key];
      view.layout = moveNode(view.layout, node.id, node.x + dx, node.y + dy, SIZE);
      saveLayout();
      renderGraph();
      document.querySelector(`[data-node="${node.id}"]`)?.focus({preventScroll: true});
      document.getElementById('workflow-announcement').textContent = `${node.title} moved. Layout saved.`;
    });
    button.addEventListener('click', () => selectNode(node.id));
    list.append(button);
  }
  const lanes = document.getElementById('lanes');
  if (!lanes.children.length) {
    const labels = [
      {text: 'INTELLIGENCE & OPTIONAL CHECKS', x: 205, y: 15},
      {text: 'ASSESSMENT FLOW →', x: 5, y: 245},
      {text: 'SUPPORTING EVIDENCE & REASONING', x: 5, y: 485},
    ];
    for (const label of labels) {
      const item = element('span', 'lane-label', label.text);
      item.style.left = `${label.x}px`;
      item.style.top = `${label.y}px`;
      lanes.append(item);
    }
  }
}

function rows(items) {
  const list = element('dl', 'detail-rows');
  for (const item of items) list.append(element('dt', '', item.label), element('dd', 'evidence', item.value === null || item.value === undefined ? 'Not recorded' : String(item.value)));
  return list;
}

function appendQuotes(parent, items) {
  for (const item of items) {
    const group = element('div', 'evidence-item');
    group.append(element('span', 'detail-label', item.label));
    if (Object.hasOwn(item, 'value')) group.append(element('strong', 'feature-label', String(item.value).replaceAll('_', ' ')));
    if (item.confidence !== undefined) group.append(element('small', 'detail-hint', `Confidence ${item.confidence} · ${item.source}`));
    group.append(element('blockquote', 'evidence', item.quote));
    if (item.source) group.append(element('small', 'evidence-source', item.source));
    parent.append(group);
  }
}

function updateProjectLink() {
  if (!view.assessment) return;
  const parameters = new URLSearchParams();
  if (view.host) parameters.set('asset', view.host);
  if (view.finding) parameters.set('finding', view.finding);
  const section = view.finding ? 'project-doors' : 'project-workflow';
  document.getElementById('assessment-link').href = `/?run=${encodeURIComponent(view.assessment.run.run_id)}#${section}${parameters.size ? `?${parameters}` : ''}`;
}

function updateLocation() {
  const parameters = new URLSearchParams();
  if (view.node) parameters.set('node', view.node);
  if (view.host) parameters.set('host', view.host);
  if (view.finding) parameters.set('finding', view.finding);
  history.replaceState(null, '', `${location.pathname}${location.search}${parameters.size ? `#${parameters}` : ''}`);
  updateProjectLink();
}

function selectNode(identity) {
  showWorkspace('workflow');
  view.node = identity;
  updateLocation();
  inspector.hidden = false;
  document.getElementById('toggle-insights').setAttribute('aria-expanded', 'true');
  renderGraph();
  renderInspector();
  fit();
  content.querySelector('h2').focus({preventScroll: true});
  document.getElementById('workflow-announcement').textContent = `${content.querySelector('h2').textContent} selected`;
}

function renderInspector() {
  if (!view.node || !view.assessment) return;
  const nodes = applyLiveRunToNodes(buildNodes(view.assessment, view.scope, selection(), currentAnalysis()));
  const node = nodes.find(item => item.id === view.node);
  const details = nodeDetails(view.node, view.assessment, view.scope, view.weights, selection(), currentAnalysis());
  content.replaceChildren();
  const heading = element('div', 'node-detail-title');
  const glyph = element('span', `inspector-glyph group-${node.group}`);
  glyph.append(icon(node.icon));
  const title = element('h2', '', node.title);
  title.tabIndex = -1;
  heading.append(glyph, title);
  content.append(heading, element('p', 'node-description', node.subtitle), element('span', `detail-status state-${node.state}`, node.status));
  const logic = element('div', 'node-operation');
  logic.append(element('h3', '', 'Module internals'));
  for (const [label, value] of [['INPUT', details.input], ['OPERATION', details.operation], ['OUTPUT', details.output]]) {
    const section = element('div', 'operation-row');
    section.append(element('span', 'detail-label', label), element('p', '', value));
    logic.append(section);
  }
  logic.append(element('p', 'detail-hint', 'This describes the module. Its status and evidence show whether it actually ran.'));
  const module = element('div', 'module-path');
  module.append(element('span', 'detail-label', 'IMPLEMENTATION'), element('span', 'evidence', details.provenance));
  content.append(logic, module);
  if (liveState.active && liveState.previewState === 'idle' && view.node === 'analyst') {
    renderAnalyst();
    return;
  }
  if (liveState.active && liveState.previewState === 'idle' && ['context', 'nmap', 'nikto'].includes(view.node)) {
    const brief = buildInsightBrief({assessment: view.assessment, host: view.host, finding: view.finding, live: liveState});
    content.append(element('p', 'boundary-note', 'Current target evidence only. This panel does not substitute records from the selected stored assessment.'));
    if (view.node === 'context') renderActivityContext(content, brief);
    else {
      content.append(element('p', 'analyst-scope', `Target: ${brief.target}`));
      const scan = liveState.result || liveState.scan;
      const services = scan?.services || [];
      if (services.length) content.append(rows(services.map(service => ({label: `${service.port}/${service.protocol || 'tcp'}`, value: `${service.name || 'unknown'} ${service.product || ''} ${service.version || ''}`}))));
      else content.append(element('p', 'boundary-note', 'No service observations are available for this run.'));
      for (const gap of brief.coverage) content.append(element('p', 'boundary-note', gap));
      for (const line of brief.captureDetails) content.append(element('p', 'boundary-note', line));
    }
    return;
  }
  if (liveState.active && liveState.previewState === 'idle'
      && ['canonical', 'score', 'queue', 'rationale', 'report'].includes(view.node)) {
    content.append(element('p', 'boundary-note', 'Live run data is held in memory. This view does not claim a stored finding, stored score, or printable report artifact.'));
    if (view.node === 'report') appendLiveSummary(content, liveState.result?.assessment_summary || liveState.scan?.assessment_summary);
    else if (view.node !== 'canonical') appendDecisionFrame(content, liveState.scan?.decision_frame || liveState.result?.decision_frame);
    return;
  }
  if (liveState.active && ['skipped', 'not_in_mode'].includes(node.state) && liveState.previewState === 'idle') {
    content.append(element('p', 'boundary-note', 'This stage did not execute in the live run. Any records below belong to the selected stored assessment, not this run.'));
  }
  if (details.rows.length) content.append(rows(details.rows));
  appendQuotes(content, details.quotes);
  if (view.node === 'analyst') renderAnalyst();
  if (details.message) content.append(element('p', 'boundary-note', details.message));
  if (details.records.length) {
    const disclosure = element('details', 'raw-records');
    disclosure.append(element('summary', '', 'Raw records'), element('pre', 'evidence', JSON.stringify(details.records, null, 2)));
    content.append(disclosure);
  }
  const links = element('div', 'node-neighbours');
  for (const edge of EDGES.filter(edge => edge.from === view.node || edge.to === view.node)) {
    const other = nodes.find(item => item.id === (edge.from === view.node ? edge.to : edge.from));
    const button = element('button', 'neighbour-link', `${edge.from === view.node ? 'To' : 'From'} ${other.title}`);
    button.type = 'button';
    button.addEventListener('click', () => selectNode(other.id));
    links.append(button);
  }
  content.append(links);
}

function renderAnalyst() {
  const fromLiveRun = liveState.active && liveState.previewState === 'idle';
  const live = fromLiveRun ? {
    status: liveState.busy ? 'running' : liveState.result?.analyst ? 'complete' : 'error',
    result: liveState.result?.analyst,
    error: liveState.error || liveState.result?.ai_attempts?.at(-1)?.detail || 'No validated AI result is available for this run.',
    steps: Object.fromEntries(liveState.stages),
  } : currentAnalysis();
  const holder = element('section', 'analyst-action');
  holder.append(element('p', 'analyst-scope', fromLiveRun ? `Target: ${liveState.target} · retained scan evidence` : view.host ? `Target: ${view.host}` : 'Select a target above to analyze its stored evidence.'));
  const button = element('button', 'analyze-button', live?.status === 'running' ? 'Request in progress' : fromLiveRun ? 'Configure AI re-analysis · no scan' : 'Analyze target');
  button.type = 'button';
  button.id = 'workflow-analyze';
  button.disabled = live?.status === 'running' || (fromLiveRun ? !liveState.scan?.resolved_ip : !view.host);
  button.addEventListener('click', () => {
    if (!fromLiveRun) return analyzeTarget(view.host, view.assessment?.run.run_id, providerSelect.value);
    document.getElementById('new-target').value = liveState.target;
    document.getElementById('live-run-mode').value = 'reuse';
    runPanel.hidden = false;
    document.getElementById('open-run').setAttribute('aria-expanded', 'true');
    providerSelect.focus();
  });
  holder.append(button);
  const basis = fromLiveRun ? null : evidenceBasis(view.assessment, view.host);
  let ledger = null;
  if (basis) {
    ledger = element('div', 'analyst-basis');
    ledger.append(element('h3', '', 'Evidence-only view · no AI conclusion'));
    for (const [heading, lines] of [
      ['Observed', basis.observed.length ? basis.observed : ['No services recorded.']],
      ['Context effect', basis.context],
      ['Not established', basis.notChecked.length ? basis.notChecked : ['No specific coverage gap recorded.']],
      ['Next verification', [basis.nextVerification]],
    ]) {
      const section = element('section', 'analyst-basis-section');
      section.append(element('h4', '', heading));
      const list = element('ul', '');
      for (const line of lines) list.append(element('li', '', line));
      section.append(list);
      ledger.append(section);
    }
  }
  if (live) {
    const progress = element('ol', 'analysis-progress');
    progress.setAttribute('aria-label', 'AI analyst stages');
    for (const [id, label] of analysisStages) {
      if (fromLiveRun && id === 'records') continue;
      const state = live.steps?.[id]?.state || 'pending';
      const item = element('li', `analysis-progress-step state-${state}`);
      item.dataset.stage = id;
      item.append(element('span', 'analysis-progress-state', state.replace('-', ' ')), element('strong', '', label));
      const detail = element('span', 'analysis-progress-detail', live.steps?.[id]?.detail || 'Not started');
      detail.dataset.progressDetail = id;
      item.append(detail);
      progress.append(item);
    }
    holder.append(progress);
  }
  if (live?.status === 'running') holder.append(element('p', 'analysis-wait', 'AI analysis is running with the selected provider. Canonical scores are not changed.'));
  if (live?.status === 'error' || live?.status === 'needs_review') holder.append(element('p', 'analysis-error', live.error));
  if (live?.result && !appendBatchReview(holder, live.result)) {
    const result = live.result;
    appendDecisionFrame(holder, result.decision_frame);
    holder.append(element('p', 'analysis-summary', result.analysis.summary));
    appendModelContextEffect(holder, result);
    const evidenceMap = new Map(result.evidence.map(item => [item.id, item]));
    for (const action of result.analysis.recommended_actions) {
      const record = element('div', 'analysis-action');
      record.append(element('h3', '', action.action), element('p', '', action.reason));
      appendQuotes(record, action.evidence_ids.map(identity => ({label: `Citation ${identity}`, quote: evidenceMap.get(identity)?.text || 'Citation not present in response', source: result.model})));
      holder.append(record);
    }
    for (const correlation of result.analysis.correlations || []) {
      const record = element('div', 'analysis-action');
      record.append(element('h3', '', 'Correlated evidence'), element('p', '', correlation.observation));
      appendQuotes(record, correlation.evidence_ids.map(identity => ({label: `Citation ${identity}`, quote: evidenceMap.get(identity)?.text || 'Citation not present in response', source: result.model})));
      holder.append(record);
    }
    appendInvestigation(holder, result);
    for (const uncertainty of result.analysis.uncertainties) holder.append(element('p', 'boundary-note', uncertainty));
  }
  if (ledger) holder.append(ledger);
  content.append(holder);
}

async function analyzeTarget(hostIp = view.host, runId = view.assessment?.run.run_id, provider = 'ollama') {
  if (!hostIp || !runId || !view.assessment) return {status: 'error', error: 'No recorded target selected'};
  if (provider !== 'ollama' && !document.getElementById('share-evidence').checked) {
    const error = 'Confirm evidence sharing before using a cloud model.';
    document.getElementById('target-check-result').textContent = error;
    runPanel.hidden = false;
    document.getElementById('open-run').setAttribute('aria-expanded', 'true');
    return {status: 'error', error};
  }
  const key = `${runId}/${hostIp}`;
  if (view.analyses.get(key)?.status === 'running') return {status: 'error', error: 'Analysis already running for this target'};
  view.analyses.set(key, {runId, hostIp, status: 'running', stage: '', steps: {}});
  renderGraph();
  renderInspector();
  try {
    const response = await requestAnalystProgress(runId, hostIp, event => {
      const live = view.analyses.get(key);
      if (!live || live.status !== 'running' || !analysisStages.some(([id]) => id === event.stage)) return;
      const previousState = live.steps[event.stage]?.state;
      live.stage = event.stage;
      live.steps[event.stage] = {state: event.state, detail: event.detail};
      if (runState.entries.get(hostIp)?.status === 'running') {
        runState.entries.set(hostIp, {status: 'running', stage: analysisStages.find(([id]) => id === event.stage)[1], detail: event.detail});
        renderRunProgress();
      }
      if (view.assessment?.run.run_id === runId && view.host === hostIp) {
        if (previousState !== event.state) {
          renderGraph();
          renderInspector();
          document.getElementById('workflow-announcement').textContent = `${analysisStages.find(([id]) => id === event.stage)[1]}: ${event.state}`;
        } else {
          const detail = document.querySelector(`[data-progress-detail="${event.stage}"]`);
          if (detail) detail.textContent = event.detail;
        }
      }
    }, provider);
    const live = view.analyses.get(key);
    view.analyses.set(key, {...live, status: 'complete', result: response});
  } catch (error) {
    const live = view.analyses.get(key);
    const steps = {...live?.steps};
    steps[live?.stage || 'records'] = {state: 'error', detail: error.message};
    view.analyses.set(key, {...live, status: error.name === 'NeedsReviewError' ? 'needs_review' : 'error', steps, error: error.message});
  }
  if (view.assessment?.run.run_id === runId && view.host === hostIp) {
    renderGraph();
    renderInspector();
    document.getElementById('workflow-announcement').textContent = view.analyses.get(key).status === 'complete' ? 'Analyst response received. Stored scores unchanged.' : view.analyses.get(key).status === 'needs_review' ? 'Needs review. Model output rejected; no partial result shown.' : 'Analysis failed. No result substituted.';
  }
  return view.analyses.get(key);
}

function populateFindings() {
  const findings = view.assessment.findings.filter(finding => !view.host || finding.host_ip === view.host);
  findingSelect.replaceChildren(element('option', '', 'All findings'));
  findingSelect.options[0].value = '';
  for (const finding of findings) {
    const option = element('option', '', `${finding.host_ip} / ${finding.title}`);
    option.value = finding.id;
    findingSelect.append(option);
  }
  if (!findings.some(finding => finding.id === view.finding)) view.finding = '';
  findingSelect.value = view.finding;
  findingSelect.disabled = false;
}

function populateSelection() {
  hostSelect.replaceChildren(element('option', '', 'All recorded hosts'));
  hostSelect.options[0].value = '';
  for (const host of view.assessment.hosts) {
    const option = element('option', '', host.ip);
    option.value = host.ip;
    hostSelect.append(option);
  }
  if (!view.assessment.hosts.some(host => host.ip === view.host)) view.host = '';
  hostSelect.value = view.host;
  hostSelect.disabled = false;
  populateFindings();
}

async function loadWorkflow() {
  if ((liveState.busy && liveState.previewState === 'idle') || runState.busy) {
    document.getElementById('workflow-announcement').textContent = 'An assessment is running. Wait for it to finish before opening stored records.';
    return;
  }
  // Returning to stored records must discard the display overlay, not the
  // retained evidence. Invalidate a sleeping preview before clearing its state.
  previewSequence++;
  Object.assign(liveState, {
    active: false, busy: false, previewState: 'idle', previewScenario: null,
    target: '', provider: '', reuseRecent: false, savedCapture: false,
    stages: new Map(), scan: null, result: null, error: '', needsReview: false,
  });
  briefSignature = '';
  activitySignature = '';
  document.getElementById('workflow-activity').replaceChildren(element('p', 'activity-muted', 'Reading the selected assessment. No scan or model call is made.'));
  inspector.hidden = true;
  view.node = '';
  renderLiveProgress();
  renderLiveExecution();
  renderLiveResult();
  const sequence = ++view.load;
  message.hidden = false;
  message.querySelector('strong').textContent = 'Opening the assessment';
  message.querySelector('p').textContent = 'Reading local records.';
  graph.hidden = true;
  document.getElementById('data-kind').textContent = 'READING STORED RECORDS';
  document.getElementById('canvas-caption').textContent = 'Opening stored assessment / no new scan';
  document.getElementById('record-summary').textContent = '';
  document.getElementById('workflow-announcement').textContent = 'Opening stored records. No scanner or model request was made.';
  document.getElementById('refresh-workflow').disabled = true;
  try {
    const index = await getRecord('/api/runs');
    if (!index.runs.length) throw new Error('No stored runs. Import an authorized capture through the CLI, then refresh.');
    const requested = new URLSearchParams(location.search).get('run') || index.selected_run || index.runs[0].run_id;
    const [assessment, scope, weights] = await Promise.all([getRecord(`/api/run/${encodeURIComponent(requested)}`), getRecord('/api/scope'), getRecord('/api/weights')]);
    if (sequence !== view.load) return;
    view.assessment = assessment;
    view.scope = scope;
    view.weights = weights;
    runSelect.replaceChildren(...index.runs.map(run => { const option = element('option', '', run.run_id); option.value = run.run_id; return option; }));
    runSelect.value = requested;
    runSelect.disabled = false;
    const parameters = new URLSearchParams(location.hash.slice(1));
    view.host = parameters.get('host') || '';
    view.finding = parameters.get('finding') || '';
    populateSelection();
    if (!runState.busy) {
      runState.selected = new Set(view.host ? [view.host] : assessment.hosts.map(host => host.ip));
      renderRunTargets();
    }
    document.getElementById('canvas-caption').textContent = `Recorded assessment / ${assessment.run.run_id}`;
    document.getElementById('record-summary').textContent = `${assessment.hosts.length} assets / ${assessment.findings.length} findings / ${assessment.scores.length} scored`;
    document.getElementById('run-hash').textContent = `config ${assessment.run.config_hash}`;
    document.getElementById('data-kind').textContent = evidenceKind(assessment);
    updateProjectLink();
    graph.hidden = false;
    message.hidden = true;
    renderGraph();
    void refreshIntelStatus();
    if (buildNodes(assessment, scope).some(node => node.id === parameters.get('node'))) selectNode(parameters.get('node'));
    fit();
  } catch (error) {
    if (sequence !== view.load) return;
    view.assessment = null;
    inspector.hidden = true;
    hostSelect.disabled = true;
    findingSelect.disabled = true;
    message.querySelector('strong').textContent = 'Records unavailable';
    message.querySelector('p').textContent = error.message;
    document.getElementById('canvas-caption').textContent = 'The stored assessment could not be loaded.';
    document.getElementById('data-kind').textContent = 'RECORDS UNAVAILABLE';
    document.getElementById('record-summary').textContent = '';
    document.getElementById('assessment-overview').textContent = `Records unavailable: ${error.message}`;
    document.getElementById('workflow-activity').replaceChildren(element('p', 'activity-warning', `Records unavailable: ${error.message}. No conclusion is shown.`));
    briefSignature = '';
  } finally {
    if (sequence === view.load) document.getElementById('refresh-workflow').disabled = false;
  }
}

document.getElementById('refresh-workflow').addEventListener('click', loadWorkflow);
document.getElementById('toggle-insights').addEventListener('click', event => {
  const rail = document.getElementById('workflow-sidebar');
  const open = rail.hidden && inspector.hidden;
  inspector.hidden = true;
  rail.hidden = !open;
  view.node = '';
  updateLocation();
  event.currentTarget.setAttribute('aria-expanded', String(open));
  renderGraph();
  fit();
});
document.getElementById('toggle-theme').addEventListener('click', event => {
  const dark = document.documentElement.dataset.flowTheme !== 'dark';
  document.documentElement.dataset.flowTheme = dark ? 'dark' : 'light';
  event.currentTarget.textContent = dark ? 'Light theme' : 'Dark theme';
  event.currentTarget.setAttribute('aria-label', `Switch to ${dark ? 'light' : 'dark'} theme`);
});
// ==================== RUN ANALYSIS: PANEL OPEN/CLOSE CONTROLS (START) ====================
document.getElementById('open-run').addEventListener('click', () => {
  runPanel.hidden = !runPanel.hidden;
  document.getElementById('open-run').setAttribute('aria-expanded', String(!runPanel.hidden));
  if (!runPanel.hidden) { renderRunTargets(); void refreshIntelStatus(); runSearch.focus(); }
});
document.getElementById('close-run').addEventListener('click', () => {
  runPanel.hidden = true;
  document.getElementById('open-run').setAttribute('aria-expanded', 'false');
  document.getElementById('open-run').focus();
});
// ==================== RUN ANALYSIS: PANEL OPEN/CLOSE CONTROLS (END) ====================
document.getElementById('start-run').addEventListener('click', startRun);
document.getElementById('start-live-run').addEventListener('click', () => startLiveRun());
document.getElementById('open-device-check').addEventListener('click', () => {
  document.getElementById('open-run').click();
  const mode = document.getElementById('live-run-mode');
  mode.value = 'self';
  mode.dispatchEvent(new Event('change'));
});
document.getElementById('live-run-mode').addEventListener('change', event => {
  const self = event.target.value === 'self';
  document.getElementById('self-defence-help').hidden = !self;
  document.getElementById('new-target').disabled = self;
  document.getElementById('check-target').disabled = self;
  document.getElementById('start-live-run').textContent = self ? 'Check this device' : 'Run live target';
});
mountScanPlanner({
  getTarget: () => document.getElementById('new-target').value.trim(),
  getRunId: () => view.assessment?.run?.run_id,
  getProvider: () => providerSelect.value,
  canShare: () => document.getElementById('share-evidence').checked,
  onRun: startLiveRun,
});
mountEvidenceRequests({
  getTarget: () => document.getElementById('new-target').value.trim(),
  getRunId: () => view.assessment?.run?.run_id,
  getProvider: () => providerSelect.value,
  canShare: () => document.getElementById('share-evidence').checked,
});
document.getElementById('import-nessus').addEventListener('click', async () => {
  const status = document.getElementById('nessus-import-status');
  const button = document.getElementById('import-nessus');
  const file = document.getElementById('nessus-file').files[0];
  const target = document.getElementById('nessus-target').value.trim() || view.host;
  const newRun = document.getElementById('nessus-destination').value === 'new';
  const run = newRun ? `nessus-${Date.now()}-${crypto.randomUUID().slice(0, 8)}` : view.assessment?.run?.run_id;
  if (!run || !target || !file) { status.textContent = 'Enter an authorised target IP and choose a .nessus export.'; return; }
  if (!file.name.toLowerCase().endsWith('.nessus') || file.size > 16 * 1024 * 1024) { status.textContent = 'Choose a .nessus export smaller than 16 MB.'; return; }
  button.disabled = true;
  status.textContent = 'Checking the report and updating the assessment…';
  try {
    const response = await fetch('/api/nessus-import', {method: 'POST', headers: {
      'Content-Type': 'application/xml', 'X-VulnAssess-Action': 'nessus-import',
      'X-VulnAssess-Run': run, 'X-VulnAssess-Target': target, 'X-VulnAssess-New-Run': String(newRun),
    }, body: file});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error?.message || 'Report import failed');
    status.textContent = `${result.import.findings.nessus} Nessus findings stored; ${result.scores} priorities calculated. Opening assessment…`;
    location.href = `/workflow?run=${encodeURIComponent(result.run_id)}#host=${encodeURIComponent(target)}`;
  } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
});
document.getElementById('preview-flow').addEventListener('click', previewLiveFlow);
document.getElementById('stop-run').addEventListener('click', () => { runState.stop = true; document.getElementById('stop-run').disabled = true; });
providerSelect.addEventListener('change', () => {
  document.getElementById('cloud-consent').hidden = providerSelect.value === 'ollama';
  document.getElementById('share-evidence').checked = false;
});
runSearch.addEventListener('input', renderRunTargets);
runTargets.addEventListener('change', event => {
  if (event.target.type !== 'checkbox') return;
  if (event.target.checked) runState.selected.add(event.target.value);
  else runState.selected.delete(event.target.value);
  renderRunTargets();
});
// ==================== RUN ANALYSIS: TARGET SCOPE CHECK (START) ====================
document.getElementById('check-target').addEventListener('click', async () => {
  const input = document.getElementById('new-target');
  const output = document.getElementById('target-check-result');
  const target = input.value.trim();
  output.textContent = 'Checking the local authorization scope and Nmap readiness…';
  try {
    const result = await getRecord(`/api/target-check?target=${encodeURIComponent(target)}`);
    output.textContent = `${result.submitted || result.target}: ${result.reason}${result.missing?.length ? ` Missing: ${result.missing.join(', ')}.` : ''}`;
  } catch (error) {
    output.textContent = error.message;
  }
});
// ==================== RUN ANALYSIS: TARGET SCOPE CHECK (END) ======================
runSelect.addEventListener('change', () => { location.href = `/workflow?run=${encodeURIComponent(runSelect.value)}`; });
hostSelect.addEventListener('change', () => { view.host = hostSelect.value; view.finding = ''; populateFindings(); updateLocation(); renderGraph(); renderInspector(); });
findingSelect.addEventListener('change', () => {
  view.finding = findingSelect.value;
  if (view.finding) {
    view.host = view.assessment.findings.find(finding => finding.id === view.finding).host_ip;
    hostSelect.value = view.host;
    populateFindings();
  }
  updateLocation();
  renderGraph();
  renderInspector();
});
document.getElementById('close-node').addEventListener('click', () => {
  const identity = view.node;
  view.node = '';
  inspector.hidden = true;
  updateLocation();
  document.getElementById('toggle-insights').setAttribute('aria-expanded', String(!document.getElementById('workflow-sidebar').hidden));
  renderGraph();
  fit();
  document.querySelector(`[data-node="${identity}"]`)?.focus({preventScroll: true});
});
for (const button of document.querySelectorAll('[data-view-mode]')) button.addEventListener('click', () => {
  view.modeChosen = true;
  setViewMode(button.dataset.viewMode);
});
narrowViewport.addEventListener('change', event => { if (!view.modeChosen) setViewMode(event.matches ? 'stages' : 'canvas'); });
document.getElementById('fit-workflow').addEventListener('click', fit);
document.getElementById('reset-layout').addEventListener('click', () => {
  view.layout = {};
  try { localStorage.removeItem(layoutKey); } catch { /* The in-memory layout is still reset. */ }
  renderGraph();
  fit();
  document.getElementById('workflow-announcement').textContent = 'Workflow layout reset.';
});
document.getElementById('zoom-in').addEventListener('click', () => zoom(1.2));
document.getElementById('zoom-out').addEventListener('click', () => zoom(1 / 1.2));
let drag = null;
viewport.addEventListener('pointerdown', event => {
  if (view.mode !== 'canvas' || event.button !== 0) return;
  const button = event.target.closest('.flow-node');
  if (!button && event.target.closest('button, a, select, input')) return;
  const node = button && positionNodes(NODE_SPECS, view.layout).find(item => item.id === button.dataset.node);
  drag = {pointer: event.pointerId, x: event.clientX, y: event.clientY, panX: view.panX, panY: view.panY, node, moved: false};
  if (!node) viewport.setPointerCapture(event.pointerId);
  viewport.classList.add(node ? 'arranging' : 'panning');
});
viewport.addEventListener('pointermove', event => {
  if (!drag || drag.pointer !== event.pointerId) return;
  const dx = event.clientX - drag.x;
  const dy = event.clientY - drag.y;
  if (drag.node) {
    if (!drag.moved && Math.hypot(dx, dy) < 4) return;
    if (!drag.moved) viewport.setPointerCapture(event.pointerId);
    drag.moved = true;
    view.layout = moveNode(view.layout, drag.node.id, drag.node.x + dx / view.scale, drag.node.y + dy / view.scale, SIZE);
    renderGraph();
  } else {
    view.panX = drag.panX + dx;
    view.panY = drag.panY + dy;
    transform();
  }
});
function stopDrag() {
  if (drag?.node && drag.moved) {
    saveLayout();
    document.getElementById('workflow-announcement').textContent = `${drag.node.title} moved. Layout saved.`;
  }
  drag = null;
  viewport.classList.remove('panning', 'arranging');
}
viewport.addEventListener('pointerup', stopDrag);
viewport.addEventListener('pointercancel', stopDrag);
viewport.addEventListener('wheel', event => {
  if (view.mode !== 'canvas' || event.target.closest('select')) return;
  event.preventDefault();
  if (event.ctrlKey || event.metaKey) {
    const rect = viewport.getBoundingClientRect();
    zoom(event.deltaY < 0 ? 1.1 : 1 / 1.1, {x: event.clientX - rect.left, y: event.clientY - rect.top});
  } else { view.panX -= event.deltaX; view.panY -= event.deltaY; transform(); }
}, {passive: false});
viewport.addEventListener('keydown', event => {
  if (view.mode !== 'canvas' || event.target !== viewport) return;
  const offsets = {ArrowLeft: [60, 0], ArrowRight: [-60, 0], ArrowUp: [0, 60], ArrowDown: [0, -60]};
  if (offsets[event.key]) { event.preventDefault(); view.panX += offsets[event.key][0]; view.panY += offsets[event.key][1]; transform(); }
  if (event.key === '+' || event.key === '=') { event.preventDefault(); zoom(1.2); }
  if (event.key === '-') { event.preventDefault(); zoom(1 / 1.2); }
  if (event.key === '0') { event.preventDefault(); fit(); }
});
document.addEventListener('keydown', event => { if (event.key === 'Escape' && !inspector.hidden) document.getElementById('close-node').click(); });
window.addEventListener('resize', () => liveState.active ? fitPreviewPath() : fit());
new ResizeObserver(() => {
  if (viewport.clientHeight > 0) liveState.active ? fitPreviewPath() : fit();
}).observe(viewport);
setViewMode(view.mode);
loadWorkflow();
