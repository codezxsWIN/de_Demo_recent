'use strict';
let currentCoverage = null;
let coverageHistory = [];
let coverageSelection = 0;

function resetCoverage(value) {
  currentCoverage = null;
  coverageHistory = [];
  $('coverage-history').replaceChildren(new Option('No full assessment retained yet', ''));
  $('assess-all').textContent = `Assess all ${value === 'office' ? 'Office' : 'IoT'} services`;
  $('coverage-download').hidden = true;
  $('coverage-content').replaceChildren(el('p', 'No full assessment selected for this environment. Run all services to measure the known lab conditions.', 'empty'));
}

async function inspectCoverageCase(identifier, focus = true) {
  if (!/^live-[a-f0-9]{32}$/.test(identifier || '')) return;
  const request = ++coverageSelection;
  try {
    const item = await json(`/api/network-live/evidence/${identifier}.json`);
    if (item.environment !== environment || request !== coverageSelection) return;
    selected = item;
    if (focus) {
      showWindow = true;
      $('show-window').setAttribute('aria-pressed', 'true');
      $('show-window').textContent = 'Show live traffic';
    }
    renderCase();
    if (focus) $('investigation-title').scrollIntoView({behavior: 'smooth', block: 'start'});
  } catch (error) {
    setBusy(false, error.message, true);
  }
}

function selectCoverage(suite) {
  renderCoverage(suite);
  const identifier = suite.findings?.[0]?.case_id || suite.checks?.find(row => row.case_id)?.case_id;
  if (identifier) inspectCoverageCase(identifier, false);
}

function coverageTable(headings, rows) {
  const table = el('table');
  const head = el('thead');
  const header = el('tr');
  for (const label of headings) header.append(el('th', label));
  head.append(header);
  const body = el('tbody');
  for (const values of rows) {
    const row = el('tr');
    for (const value of values) {
      const cell = el('td');
      cell.append(typeof value === 'string' ? document.createTextNode(value) : value);
      row.append(cell);
    }
    body.append(row);
  }
  table.append(head, body);
  return table;
}

function coverageEvidence(identifier, text = 'Inspect evidence & AI') {
  const button = el('button', text, 'quiet');
  button.disabled = !identifier;
  button.addEventListener('click', () => inspectCoverageCase(identifier));
  return button;
}

function renderCoverage(suite) {
  if (!suite || suite.environment !== environment) return;
  currentCoverage = suite;
  const parent = $('coverage-content');
  parent.replaceChildren();
  const c = suite.coverage || {};
  const m = suite.metrics;
  const grounded = suite.ground_truth?.status === 'verified';
  parent.append(el('p', `${date(suite.finished_at)} · ${suite.ground_truth?.profile || 'profile unverified'} · ${suite.status} · ${suite.id}`, 'muted'));
  const published = suite.main_assessment;
  const actions = el('div', undefined, 'packet-controls');
  if (published?.status === 'saved' && /^assessment-lab-[a-f0-9]{32}$/.test(published.capture_id || '')) {
    for (const [label, href] of [
      ['Open assessment report ↗', `/captures/${published.capture_id}/report`],
      ['Findings & remediation ↗', `/vulnerabilities?capture=${published.capture_id}`],
    ]) {
      const a = el('a', label, 'quiet'); a.href = href; a.target = '_blank'; a.rel = 'noopener'; actions.append(a);
    }
    parent.append(el('p', `Saved in the assessment database as ${published.run_id}. These views reuse retained evidence; they do not launch another scan.`, 'muted'));
  } else {
    if (published?.error) parent.append(el('p', 'Main assessment publication: ' + published.error, 'error'));
    const button = el('button', 'Prepare main report from this evidence · no scan', 'quiet');
    button.addEventListener('click', async () => {
      setBusy(true, 'Publishing retained evidence to the main findings, database and report…');
      try {
        const saved = await post('publish', {assessment_id: suite.id}); renderCoverage(saved);
        setBusy(false, saved.main_assessment?.status === 'saved' ? 'Assessment report and database record are ready.' : 'Publication remains unresolved; retained lab evidence is preserved.', saved.main_assessment?.status !== 'saved');
      } catch (error) { setBusy(false, error.message, true); }
    });
    actions.append(button);
  }
  parent.append(actions);
  const metrics = el('div', undefined, 'coverage-metrics');
  const cells = [
    ['Endpoints attempted', `${c.attempted_endpoints ?? '—'} / ${c.declared_endpoints ?? '—'}`],
    ['Known conditions tested', `${c.tested_conditions ?? '—'} / ${c.known_conditions ?? '—'}`],
    ['Known weaknesses detected', grounded && m ? `${m.true_positive} / ${(suite.conditions||[]).filter(row=>row.expected===true).length}` : 'Unverified'],
    ['Missed known weaknesses', grounded && m ? String(m.false_negative) : 'Unverified'],
    ['Untested known weaknesses', grounded && m ? String(m.missed_untested) : 'Unverified'],
    ['False positives', grounded && m ? String(m.false_positive) : 'Unverified'],
  ];
  for (const [label, value] of cells) {
    const cell = el('div');
    cell.append(el('span', label), el('strong', value));
    metrics.append(cell);
  }
  parent.append(metrics);
  parent.append(el('p', grounded
    ? 'Compared with independently reviewed conditions in this specific lab configuration. This is not a general scanner accuracy or complete-security claim.'
    : 'Ground truth is not verified for this runtime. Precision, recall and correctness counts are withheld; actual checks and findings remain visible.', grounded ? 'muted' : 'error'));
  for (const issue of suite.ground_truth?.issues || []) parent.append(el('p', String(issue), 'error'));
  const findings = [...(suite.findings || [])].sort((a,b)=>(Number(b.score?.risk)||0)-(Number(a.score?.risk)||0));
  const findingDetails = el('details', undefined, 'coverage-details');
  findingDetails.open = true;
  findingDetails.append(el('summary', `${findings.length} recorded findings, ranked by the existing scoring policy`));
  if (findings.length) findingDetails.append(coverageTable(['Endpoint / finding', 'Priority', 'Evidence'], findings.map(row => [
    `${row.finding.host_ip}:${row.finding.port} · ${row.finding.title}`,
    Number.isFinite(row.score?.risk)?`${row.score.risk}/100 · ${row.score.band}`:'Unscored',
    coverageEvidence(row.case_id),
  ])));
  else findingDetails.append(el('p', 'No finding was recorded by the completed checks. Inspect the coverage and failed checks before interpreting that result.'));
  parent.append(findingDetails);
  if(suite.unexpected_findings?.length)parent.append(el('p',`${suite.unexpected_findings.length} finding(s) fall outside the reviewed condition inventory. Review them separately; they are not counted as verified correct detections.`,'error'));
  const checks = el('details', undefined, 'coverage-details');
  checks.append(el('summary', 'Endpoint coverage, failures and inventory-only services'));
  checks.append(coverageTable(['Endpoint / operation', 'Outcome', 'Evidence'], (suite.checks || []).map(row => [
    `${row.port}/${row.transport} · ${row.action||'Unsupported operation'}`,
    row.error ? `${row.state}: ${row.error}` : (suite.endpoints||[]).find(e=>e.action===row.action)?.state==='identity_only' ? 'Identity only · CVEs not tested' : String(row.state||'untested').replaceAll('_', ' '),
    coverageEvidence(row.case_id, row.case_id ? 'Inspect check' : 'No completed evidence'),
  ])));
  checks.append(el('p', 'Redis INFO identifies a service version. These live policy checks do not establish Redis CVE applicability or exploitability. Passive FTP data ports are auxiliary transfer channels.', 'muted'));
  parent.append(checks);
  const conditions = el('details', undefined, 'coverage-details');
  conditions.append(el('summary', 'Expected versus detected: each known condition and control'));
  conditions.append(coverageTable(['Condition', 'Expected', 'Detected', 'Evaluation'], (suite.conditions || []).map(row => [
    `${row.port} · ${row.description}`,
    row.expected === true ? 'Weakness present' : row.expected === false ? 'Control / no tested weakness' : 'Unverified',
    row.predicted === true ? 'Finding recorded' : row.predicted === false ? 'No finding recorded' : 'Not established',
    String(row.state || 'untested').replaceAll('_', ' '),
  ])));
  parent.append(conditions);
  $('coverage-download').hidden = !/^full-[a-f0-9]{32}$/.test(suite.id || '');
  if (!$('coverage-download').hidden) $('coverage-download').href = `/api/network-live/assessment/${suite.id}.json`;
}

function refreshCoverage(data, requested) {
  if (requested !== environment) return;
  coverageHistory = data.assessments || [];
  const menu = $('coverage-history');
  const selection = currentCoverage?.id;
  menu.replaceChildren(...coverageHistory.map(suite => new Option(
    `${date(suite.finished_at)} · ${suite.ground_truth?.profile || 'unverified profile'} · ${suite.status}`,
    suite.id
  )));
  if (selection && !coverageHistory.some(row => row.id === selection)) menu.add(new Option(`Selected retained run · ${selection}`, selection));
  if (!menu.options.length) menu.add(new Option('No full assessment retained yet', ''));
  const latest = coverageHistory[0];
  if (!currentCoverage && latest) selectCoverage(latest);
  menu.value = currentCoverage?.id || '';
  if (data.assessment_progress?.running && data.assessment_progress.environment === environment) {
    $('action-status').textContent = `Full assessment: ${data.assessment_progress.completed ?? 0} / ${data.assessment_progress.total ?? '—'} checks finished · ${data.assessment_progress.action || 'preparing'}`;
  }
}

$('coverage-history').addEventListener('change', () => {
  const suite = coverageHistory.find(row => row.id === $('coverage-history').value);
  if (suite) selectCoverage(suite);
});

$('assess-all').addEventListener('click', async () => {
  const requested = environment;
  setBusy(true, 'Assessing all declared services. Each completed check retains its own proof and capture; failures remain explicit.');
  try {
    const suite = await post('assess', {environment: requested});
    if (requested === environment) selectCoverage(suite);
    setBusy(false, `Full ${requested} assessment retained at ${time(suite.finished_at)}. Review its coverage before relying on the findings.`);
  } catch (error) {
    setBusy(false, error.message, true);
  }
  refresh();
});
resetCoverage(environment);
