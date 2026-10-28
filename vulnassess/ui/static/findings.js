// This page reviews the latest integrity-checked capture. It never starts work.
const $ = id => document.getElementById(id);
const text = value => value == null ? 'Not retained' : typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
const node = (tag, className = '', value) => {
  const element = document.createElement(tag);
  element.className = className;
  if (value != null) element.textContent = text(value);
  return element;
};
const cves = row => Array.isArray(row.cves) ? row.cves : [];
const scored = row => typeof row.priority === 'number' && Number.isFinite(row.priority);
const unsupported = row => !scored(row) || row.severity_basis_missing === true || ['Unknown', 'Unscored'].includes(row.band);
const host = row => row.host ?? 'Unknown target';
const endpoint = row => `${host(row)}${row.port == null ? '' : `:${row.port}`}${row.protocol ? ` / ${String(row.protocol).toUpperCase()}` : ''}`;
const association = row => !cves(row).length ? 'none' : cves(row).some(cve => cve.match_method === 'explicit') ? 'explicit' : 'candidate';
const associationLabels = {explicit: 'Scanner-named · verify applicability', candidate: 'Candidate association · verify applicability', none: 'No CVE associated'};
const colors = {explicit: 'var(--findings-color-8de3ef)', candidate: 'var(--findings-color-ffdd8c)', none: 'var(--findings-color-afbed0)'};
let assessment = null;
let visible = [];
let opener = null;

// Quote every field and neutralize formula prefixes, including after whitespace
// or control characters. Quoting alone does not prevent spreadsheet evaluation.
function csvCell(value) {
  let field = value == null ? '' : text(value);
  if (/^[\s\u0000-\u001f\u007f]*[=+\-@]/u.test(field) || /^[\t\r\n]/u.test(field)) field = `'${field}`;
  return `"${field.replaceAll('"', '""')}"`;
}

function safeLink(element, href, fallback = '/workflow') {
  element.href = fallback;
  if (typeof href !== 'string') return;
  try {
    const url = new URL(href, window.location.href);
    if (url.origin === window.location.origin && ['http:', 'https:'].includes(url.protocol)) element.href = url.href;
  } catch { /* Keep the safe local fallback. */ }
}

function emptyTable(message) {
  const row = node('tr');
  const cell = node('td', 'empty', message);
  cell.colSpan = 5;
  row.append(cell);
  $('finding-rows').replaceChildren(row);
}

function closeDetail() {
  if ($('detail-dialog').open) $('detail-dialog').close();
}

function section(title, value, pre = false) {
  $('detail-body').append(node('h3', '', title), node(pre ? 'pre' : 'p', '', text(value)));
}

function guidanceList(title, items) {
  $('detail-body').append(node('h3', '', title));
  if (!Array.isArray(items) || !items.length) {
    $('detail-body').append(node('p', '', 'No reviewed guidance retained.'));
    return;
  }
  const list = node('ol');
  for (const item of items) list.append(node('li', '', text(item)));
  $('detail-body').append(list);
}

function openFinding(row, trigger) {
  opener = trigger;
  $('detail-title').textContent = text(row.title);
  $('detail-body').replaceChildren();
  const facts = node('div', 'fact-grid');
  for (const [label, value] of [
    ['Target / scanner', `${endpoint(row)} · ${row.tool ?? 'Unknown scanner'}`],
    ['Recorded priority', scored(row) ? `${row.band} · ${row.priority}/100 · rank ${row.rank ?? 'unavailable'}` : 'Unscored'],
    ['Score basis', row.score_basis], ['Native severity', row.native_severity],
  ]) {
    const fact = node('div', 'fact');
    fact.append(node('span', '', label), node('strong', '', text(value)));
    facts.append(fact);
  }
  $('detail-body').append(facts, node('p', 'caveat', row.observation_status ?? 'Scanner observation; exploitation and remediation are not established.'));
  if (unsupported(row)) $('detail-body').append(node('p', 'caveat', 'Unscored or unsupported severity basis: owner review is required. Scanner defaults are not measured CVSS severity.'));
  section('Score reasoning', row.score_reason);
  section('Original scanner evidence', row.evidence ?? 'No original evidence text retained.', true);
  section('Observed path', row.path);
  section('CVE associations', cves(row).length ? cves(row) : 'No CVE associated.', true);
  section('Endpoint context', row.endpoint_context, true);
  section('Retained scoring inputs', row.scoring_context, true);
  section('Retained score records', row.scores, true);
  if (row.assurance) section('Evidence assurance', row.assurance, true);
  const guidance = row.guidance ?? {};
  section('Reviewed conditional guidance', guidance.source ?? 'No reviewed guidance retained.');
  section('What this observation means', guidance.meaning);
  section('Conditional attack scenario', guidance.scenario);
  guidanceList('Prerequisites requiring verification', guidance.prerequisites);
  section('Potential impact', guidance.impact);
  guidanceList('Patch / configuration guidance', guidance.patch);
  if (guidance.example) section('Configuration example · adapt and test', guidance.example, true);
  guidanceList('Exposure mitigations', guidance.mitigations);
  guidanceList('Verify and retain before / after evidence', guidance.verify);
  section('Validated finding-linked AI claims', row.ai?.length ? row.ai : `No validated claims retained. Assessment AI status: ${assessment.ai_status ?? 'unknown'}.`, true);
  safeLink($('trace-link'), row.report_url);
  $('trace-link').textContent = 'Open original finding report ↗';
  $('detail-dialog').showModal();
}

function renderTable() {
  if (!assessment) return;
  const query = $('search').value.trim().toLocaleLowerCase();
  visible = assessment.findings.filter(row => {
    const searchable = [row.title, row.host, row.port, row.protocol, row.tool, row.path, ...cves(row).map(cve => cve.id)].join(' ').toLocaleLowerCase();
    const risk = $('risk-filter').value;
    const cve = $('cve-filter').value;
    return (!query || searchable.includes(query))
      && (risk === 'all' || (risk === 'unscored' ? unsupported(row) : row.band === risk))
      && (cve === 'all' || (cve === 'candidate' ? cves(row).some(item => item.match_method !== 'explicit') : association(row) === cve))
      && ($('host-filter').value === 'all' || host(row) === $('host-filter').value);
  });
  $('result-count').textContent = `${visible.length} of ${assessment.findings.length} recorded findings`;
  $('download').disabled = visible.length === 0;
  $('finding-rows').replaceChildren();
  if (!visible.length) {
    emptyTable(assessment.findings.length ? 'No findings match these filters. Clear filters to see all recorded findings.' : 'No findings recorded in this capture. Review coverage before drawing conclusions about safety.');
    return;
  }
  for (const finding of visible) {
    const row = node('tr');
    row.tabIndex = 0;
    row.setAttribute('aria-label', `Inspect finding: ${finding.title}`);
    const target = node('td', 'mono', endpoint(finding));
    target.append(node('span', 'subline', finding.tool ?? 'Unknown scanner'));
    const title = node('td');
    title.append(node('span', 'f-title', finding.title), node('span', 'f-description', finding.observation_status ?? 'Recorded scanner observation'));
    const linked = node('td');
    linked.append(node('span', `association ${association(finding)}`, associationLabels[association(finding)]), node('span', 'subline mono', cves(finding).map(cve => cve.id).join(', ') || '—'));
    const priority = node('td');
    const band = scored(finding) ? finding.band : 'Unscored';
    const bandClass = ['Critical', 'High', 'Medium', 'Low'].includes(band) ? band.toLowerCase() : 'unknown';
    priority.append(node('span', `pill ${bandClass}`, band), node('span', 'subline', scored(finding) ? `${finding.priority}/100${finding.tie_count > 1 ? ' · tied rank' : ''}` : 'Severity review required'));
    if (finding.severity_basis_missing) priority.append(node('span', 'subline', 'Severity basis needs review'));
    row.append(target, title, linked, priority, node('td', '', finding.evidence == null || finding.evidence === '' ? 'No raw evidence retained' : 'Inspect original evidence →'));
    row.addEventListener('click', () => openFinding(finding, row));
    row.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openFinding(finding, row); }
    });
    $('finding-rows').append(row);
  }
}

function renderSummary(rows) {
  $('metric-total').textContent = String(rows.length);
  $('metric-attention').textContent = String(rows.filter(row => scored(row) && ['Critical', 'High'].includes(row.band)).length);
  $('metric-cve').textContent = String(rows.filter(row => cves(row).length).length);
  $('metric-unscored').textContent = String(rows.filter(unsupported).length);
  $('distribution-total').textContent = `${rows.length} recorded findings`;
  $('distribution-track').replaceChildren();
  $('distribution-legend').replaceChildren();
  const descriptions = [];
  for (const type of ['explicit', 'candidate', 'none']) {
    const count = rows.filter(row => association(row) === type).length;
    const label = `${associationLabels[type]}: ${count}`;
    descriptions.push(label);
    const segment = node('span');
    segment.style.width = `${rows.length ? count / rows.length * 100 : 0}%`;
    segment.style.backgroundColor = colors[type];
    segment.title = label;
    $('distribution-track').append(segment);
    const legend = node('span', 'legend');
    const marker = node('i');
    marker.style.backgroundColor = colors[type];
    legend.append(marker, node('span', '', label));
    $('distribution-legend').append(legend);
  }
  $('distribution-track').setAttribute('aria-label', descriptions.join('; '));
}

async function load() {
  $('finding-table').setAttribute('aria-busy', 'true');
  try {
    const response = await fetch('/api/vulnerability-findings', {cache: 'no-store', headers: {Accept: 'application/json'}});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || 'The latest completed assessment could not be verified.');
    if (!['ready', 'empty'].includes(data.state) || !Array.isArray(data.findings)) throw new Error('Unexpected findings response. No unverified results displayed.');
    if (data.state === 'empty') {
      renderSummary([]);
      $('run-select').replaceChildren(node('option', '', 'No completed live capture'));
      $('notice').textContent = data.message || 'No completed live assessment is available.';
      $('result-count').textContent = '0 recorded findings';
      emptyTable('No completed live assessment is available.');
      return;
    }
    assessment = data;
    $('run-select').replaceChildren(node('option', '', `${data.target ?? 'Unknown target'} · ${data.capture_id}`));
    const date = data.captured_at ? new Date(data.captured_at) : null;
    $('run-meta').textContent = `Latest completed live capture · ${date && !Number.isNaN(date.valueOf()) ? date.toLocaleString() : 'Capture date unavailable'} · AI: ${data.ai_status ?? 'unknown'}. Historical selection is available in Saved captures.`;
    $('notice').textContent = [data.scoring_note || 'Showing retained priorities and original evidence.', `${data.excluded_partial_captures ?? 0} partial captures excluded; ${data.unverified_captures ?? 0} unverified captures.`, ...(data.coverage_gaps ?? [])].join(' ');
    const targets = [...new Set(data.findings.map(host))].sort();
    $('host-filter').replaceChildren();
    const all = node('option', '', 'All targets'); all.value = 'all';
    $('host-filter').append(all);
    for (const target of targets) { const option = node('option', '', target); option.value = target; $('host-filter').append(option); }
    renderSummary(data.findings);
    renderTable();
  } catch (error) {
    assessment = null;
    visible = [];
    $('download').disabled = true;
    closeDetail();
    for (const id of ['metric-total', 'metric-attention', 'metric-cve', 'metric-unscored']) $(id).textContent = '—';
    $('run-select').replaceChildren(node('option', '', 'Assessment unavailable'));
    $('notice').classList.add('error');
    $('notice').textContent = `Unable to load findings: ${error.message} Reload the page to retry.`;
    $('result-count').textContent = 'No verified findings displayed';
    emptyTable('Assessment unavailable. Reload the page to retry.');
  } finally {
    $('finding-table').setAttribute('aria-busy', 'false');
  }
}

for (const id of ['risk-filter', 'cve-filter', 'host-filter']) $(id).addEventListener('change', renderTable);
$('search').addEventListener('input', renderTable);
$('reset').addEventListener('click', () => {
  $('search').value = '';
  for (const id of ['risk-filter', 'cve-filter', 'host-filter']) $(id).value = 'all';
  renderTable();
});
for (const id of ['close-detail', 'dismiss']) $(id).addEventListener('click', closeDetail);
$('detail-dialog').addEventListener('close', () => opener?.focus());
$('download').addEventListener('click', () => {
  if (!assessment || !visible.length) return;
  const fields = [['Capture', 'Target', 'Port', 'Protocol', 'Scanner', 'Finding', 'CVE IDs', 'Association', 'Priority', 'Band', 'Score basis', 'Evidence', 'Reviewed guidance source', 'Patch guidance', 'Verification guidance']];
  for (const row of visible) fields.push([assessment.capture_id, row.host, row.port, row.protocol, row.tool, row.title, cves(row).map(cve => cve.id).join('; '), associationLabels[association(row)], row.priority, row.band, row.score_basis, row.evidence, row.guidance?.source, row.guidance?.patch, row.guidance?.verify]);
  const blob = new Blob(['\uFEFF', fields.map(row => row.map(csvCell).join(',')).join('\r\n')], {type: 'text/csv;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const anchor = node('a');
  anchor.href = url;
  anchor.download = 'vulnassess-visible-findings.csv';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
load();
