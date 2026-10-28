import {bands, normalizedBand, displayNumber, displayEpss, endpoint, kevLabel, filterFindings} from './findings-model.js';

const $ = id => document.getElementById(id);
const node = (tag, className, text) => { const el = document.createElement(tag); if (className) el.className = className; if (text != null) el.textContent = String(text); return el; };
let assessment = null, selected = null, activeTab = 'risk', opener = null, loading = false;
const requestedCapture = new URLSearchParams(location.search).get('capture');
const tabs = [['risk', 'Risk & impact'], ['attack', 'Attack scenario'], ['patch', 'Patch & verify'], ['evidence', 'Evidence & AI']];
const fmtDate = value => { const date = new Date(value); return Number.isNaN(date.valueOf()) ? 'Date unavailable' : date.toLocaleString(); };
const factValue = fact => typeof fact === 'string' ? fact.replaceAll('_', ' ') : fact?.value == null ? 'Unknown' : typeof fact.value === 'boolean' ? fact.value ? 'Observed enabled' : 'Observed disabled' : String(fact.value).replaceAll('_', ' ');
function badge(band) { const el = node('span', 'badge', normalizedBand(band)); el.dataset.band = normalizedBand(band); return el; }
function meter(value, max, band) { const el = node('meter'); el.min = 0; el.max = Math.max(1, max); el.value = value ?? 0; el.dataset.band = normalizedBand(band); el.setAttribute('aria-label', `${band}: ${value ?? 'unscored'} of ${max}`); return el; }
function list(parent, title, items, ordered = false) { parent.append(node('h3', '', title)); const el = node(ordered ? 'ol' : 'ul'); for (const item of items) el.append(node('li', '', item)); parent.append(el); }
function link(label, href) { const el = node('a', '', label); el.href = href; return el; }
function detailFact(title, value) { const el = node('div', 'detail-fact'); el.append(node('small', '', title), node('strong', '', value)); return el; }
function callout(title, text) { const el = node('div', 'detail-callout'); el.append(node('strong', '', title), node('span', '', text)); return el; }
function openFinding(row, trigger) {
  opener = trigger ?? opener; selected = row.id; activeTab = 'risk'; $('detail').hidden = false; document.body.classList.add('detail-open'); renderDetail(row); $('close-detail').focus();
}
function closeDetail() { $('detail').hidden = true; document.body.classList.remove('detail-open'); selected = null; opener?.focus(); }
function renderDetail(row) {
  const heading = $('detail-heading'); heading.replaceChildren(badge(row.band), node('h2', '', row.title), node('span', 'endpoint', endpoint(row)));
  heading.append(callout(row.priority == null ? 'Unscored · review required' : `Priority ${displayNumber(row.priority)}/100 · rank #${row.rank}${row.tie_count > 1 ? ` · tied with ${row.tie_count - 1} other findings` : ''}`, `${row.score_basis}. ${row.score_reason ?? ''}`));
  const tablist = $('detail-tabs'); tablist.replaceChildren();
  tabs.forEach(([key, label], index) => { const button = node('button', '', label); button.type = 'button'; button.id = `detail-tab-${key}`; button.setAttribute('role', 'tab'); button.setAttribute('aria-selected', String(activeTab === key)); button.setAttribute('aria-controls', 'detail-content'); button.tabIndex = activeTab === key ? 0 : -1; button.addEventListener('click', () => {activeTab = key; renderDetail(row); $(`detail-tab-${key}`).focus();}); button.addEventListener('keydown', event => { if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) return; event.preventDefault(); const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length; activeTab = tabs[next][0]; renderDetail(row); $(`detail-tab-${activeTab}`).focus(); }); tablist.append(button); });
  const content = $('detail-content'); content.replaceChildren(); content.setAttribute('aria-labelledby', `detail-tab-${activeTab}`);
  if (activeTab === 'risk') {
    content.append(callout('What was actually established', row.observation_status), node('p', '', row.guidance.meaning));
    if (row.severity_basis_missing) content.append(callout('Severity basis needs review', 'The retained scanner default is a triage policy, not measured vulnerability severity. Do not treat this score as CVSS.'));
    const facts = node('div', 'detail-grid'); facts.append(detailFact('CVSS base', displayNumber(row.cvss)), detailFact('CISA KEV', kevLabel(row.cves))); content.append(facts);
    if (!row.cves.length) content.append(node('p', '', 'No CVE association was retained. NVD, EPSS and KEV values are not invented for this observation.'));
    for (const cve of row.cves) {
      content.append(node('h3', '', cve.id), node('p', '', cve.status));
      if (cve.description) content.append(node('p', '', `Retained publisher description: ${cve.description}`));
      const values = node('div', 'detail-grid');
      values.append(detailFact(`CVSS ${cve.cvss_version || ''} base`, displayNumber(cve.cvss)), detailFact('EPSS', displayEpss(cve.epss)), detailFact('KEV', cve.kev === true ? 'Listed' : cve.kev === false ? 'Not listed' : 'Unknown'));
      content.append(values, node('p', 'footnote', `Feed dates: ${Object.entries(cve.feed_dates).map(([name, date]) => `${name}: ${date}`).join(' · ') || 'not retained'}`));
      if (cve.publisher_evidence) content.append(link('Inspect exact retained CVE / EPSS / KEV evidence ↗', cve.publisher_evidence.report_url), node('br'));
      for (const url of new Set(cve.references)) { const a = link('Retained vendor / advisory reference ↗', url); a.target = '_blank'; a.rel = 'noopener noreferrer'; content.append(a, node('br')); }
    }
    content.append(node('h3', '', 'Endpoint-specific context'));
    if (row.endpoint_context) { content.append(node('p', '', `Role candidate: ${factValue(row.endpoint_context.role_candidate)}. Exposure: ${factValue(row.endpoint_context.exposure)}.`)); for (const [control, fact] of Object.entries(row.endpoint_context.controls)) content.append(node('p', '', `${control.replaceAll('_', ' ')}: ${fact.scope === 'not_applicable' ? 'Not applicable to this protocol' : factValue(fact)}`)); } else content.append(node('p', '', 'No matched endpoint context was retained.'));
    const inputs = node('details'); inputs.append(node('summary', '', 'Recorded scoring inputs & derivation'), node('pre', '', JSON.stringify(row.scoring_context, null, 2))); content.append(node('p', 'footnote', 'Scoring inputs below may include host-level context; they are not endpoint-specific observations.'), inputs);
    if (row.scores.length > 1) {const all = node('details'); all.append(node('summary', '', `All ${row.scores.length} retained score records · highest priority shown`), node('pre', '', JSON.stringify(row.scores, null, 2))); content.append(all);}
  } else if (activeTab === 'attack') {
    content.append(callout('Conditional scenario · not an executed exploit', row.guidance.scenario)); list(content, 'What an attacker would need', row.guidance.prerequisites); content.append(node('h3', '', 'Potential impact'), node('p', '', row.guidance.impact), node('p', 'footnote', 'A scanner observation, candidate CVE and successful exploitation are different claims. This page does not demonstrate compromise.'));
  } else if (activeTab === 'patch') {
    content.append(callout('Remediation plan · not automatically applied', row.guidance.source)); list(content, 'Patch / configuration steps', row.guidance.patch, true);
    for (const cve of row.cves) {
      if (!cve.references.length && !cve.publisher_evidence?.kev_required_action) continue;
      content.append(node('h3', '', `${cve.id} · advisory evidence for fix selection`));
      if (cve.description) content.append(node('p', '', `Retained publisher advisory: ${cve.description}`));
      if (cve.publisher_evidence?.kev_required_action) content.append(node('p', '', `CISA required action: ${cve.publisher_evidence.kev_required_action}`));
      for (const url of new Set(cve.references)) {const advisory = link('Retained vendor / advisory reference ↗', url); advisory.target = '_blank'; advisory.rel = 'noopener noreferrer'; content.append(advisory, node('br'));}
    }
    if (row.guidance.example) content.append(node('h3', '', 'Suggested configuration · adapt and test'), node('pre', '', row.guidance.example));
    list(content, 'Mitigate exposure', row.guidance.mitigations); list(content, 'Verify the fix', row.guidance.verify, true); content.append(callout('Decision after verification', 'If the observation persists, keep the item open and investigate the actual endpoint/configuration. Close it only after retaining successful before/after evidence; this page does not mark fixes as complete.'));
  } else {
    content.append(node('h3', '', 'Retained scanner evidence'), node('p', '', `Scanner: ${row.tool ?? 'Unknown'} · path: ${row.path ?? 'not retained'}`), node('pre', '', row.evidence || 'No raw evidence text was retained. Open the original evidence ledger for details.'));
    content.append(link('Open this finding in the original report ↗', row.report_url));
    for (const cve of row.cves) {
      const proof = cve.publisher_evidence;
      if (!proof) continue;
      content.append(node('h3', '', `${cve.id} · retained publisher evidence`), node('p', '', `NVD retrieved: ${proof.nvd_fetched_at || 'not retained'} · EPSS score date: ${proof.epss_score_date || 'not retained'}`), node('p', 'footnote', `Assessment intelligence SHA-256: ${proof.snapshot_sha256}`));
      if (proof.kev_required_action) content.append(node('p', '', `CISA required action: ${proof.kev_required_action}`));
      const hashes = node('details'); hashes.append(node('summary', '', 'Publisher record hashes'), node('pre', '', JSON.stringify(proof.record_sha256, null, 2)));
      content.append(hashes, link('Open frozen publisher records in the assessment ↗', proof.report_url));
    }
    content.append(node('h3', '', 'Validated AI conclusions for this finding'));
    if (!row.ai.length) content.append(node('p', '', `No currently validated, finding-linked AI claims are available. Assessment AI status: ${assessment.ai_status}. Reviewed conditional guidance remains separate from AI output.`));
    for (const claim of row.ai) {const block = node('section'); block.append(node('span', 'badge', `${claim.label} · batch ${claim.batch}`), node('p', '', claim.text)); for (const quote of claim.quotes) block.append(node('blockquote', '', `${quote.evidence_id}: ${quote.text}`)); block.append(node('p', 'footnote', `${claim.path} · ${claim.evidence_ids.join(', ')}`)); content.append(block);}
  }
}
function renderTable() {
  if (!assessment) return;
  const rows = filterFindings(assessment.findings, {query: $('search').value, band: $('severity').value, kev: $('kev-only').checked}); $('result-count').textContent = `${rows.length} of ${assessment.findings.length} findings`; $('no-matches').hidden = rows.length > 0; $('findings').replaceChildren();
  for (const row of rows) {
    const tr = node('tr'); const rank = node('td', '', row.rank == null ? '—' : `#${row.rank}`); if (row.tie_count > 1) rank.append(node('span', 'cell-note', 'Tied'));
    const title = node('td'); const button = node('button', 'finding-title', row.title); button.type = 'button'; button.addEventListener('click', () => openFinding(row, button)); title.append(button, node('span', 'endpoint', endpoint(row)), node('span', 'cell-note', `${row.tool ?? 'Scanner'} · ${row.tool === 'nvd-cpe' ? 'product/version candidate' : 'observed condition'}`));
    const cves = node('td', '', row.cves.map(cve => cve.id).join(', ') || 'No CVE linked'); if (row.cves.length) cves.append(node('span', 'cell-note', 'Candidate · verify applicability'));
    const epss = row.cves.map(cve => cve.epss).filter(value => value != null); const priority = node('td', 'priority'); priority.append(node('strong', '', row.priority == null ? 'Unscored' : `${displayNumber(row.priority)}/100`)); if (row.priority != null) priority.append(meter(row.priority, 100, row.band)); priority.append(badge(row.band), node('span', 'cell-note', row.score_basis));
    const open = node('td'); const arrow = node('button', 'open-detail', '↗'); arrow.type = 'button'; arrow.setAttribute('aria-label', `Details: ${row.title}`); arrow.addEventListener('click', () => openFinding(row, arrow)); open.append(arrow);
    tr.append(rank, title, cves, node('td', '', displayNumber(row.cvss ?? row.cves.find(cve => cve.cvss != null)?.cvss)), node('td', '', epss.length ? displayEpss(Math.max(...epss)) : '—'), node('td', '', kevLabel(row.cves)), priority, open); $('findings').append(tr);
  }
}
function render(data) {
  const previous = assessment?.capture_id; assessment = data.state === 'ready' ? data : null; $('dashboard').hidden = !assessment; $('empty').hidden = !!assessment;
  if (!assessment) {closeDetail(); $('target').textContent = 'No completed live assessment'; $('snapshot-meta').textContent = 'No findings fabricated'; $('ai-status').textContent = ''; $('empty-title').textContent = 'No completed live assessment yet'; $('empty-message').textContent = data.message; return;}
  if (previous !== data.capture_id) closeDetail();
  $('target').textContent = data.target; $('snapshot-meta').textContent = `${fmtDate(data.captured_at)} · ${data.capture_id}`; $('ai-status').textContent = `AI: ${data.ai_status.replaceAll('_', ' ')} · collection ${data.collection_status}`; $('report-link').href = data.report_url;
  $('selection-label').textContent = data.selection_mode === 'selected' ? 'SELECTED SAVED ASSESSMENT' : 'LATEST COMPLETED ASSESSMENT';
  const cveCount = data.findings.filter(row => row.cves.length).length;
  $('cve-context').textContent = cveCount ? `${cveCount} findings have CVE associations. Product/version matches are candidates that require applicability checks.` : 'No CVE associations were recorded for these findings. Configuration weaknesses can be real without a CVE; check coverage before drawing conclusions.';
  const rows = data.findings, scored = rows.filter(row => row.priority != null); $('metrics').replaceChildren();
  for (const [value, label, note] of [[rows.length, 'Total findings', ''], [rows.filter(row => ['Critical', 'High'].includes(row.band)).length, 'Critical / high priority', ''], [scored.length ? `${displayNumber(scored[0].priority)}/100` : '—', 'Highest priority', scored[0]?.band ?? 'Unscored'], [new Set(rows.map(row => `${row.host}:${row.port}/${row.protocol}`)).size, 'Affected endpoints', '']]) { const item = node('div', 'metric'); item.append(node('strong', '', value), node('span', '', label)); if (note) item.append(node('small', '', note)); $('metrics').append(item); }
  $('fix-first').replaceChildren(); for (const row of (scored.length ? scored : rows).slice(0, 3)) {const card = node('button', 'fix-card'); card.type = 'button'; const top = node('span', 'fix-top'); top.append(badge(row.band), node('span', 'fix-score', row.priority == null ? '—' : displayNumber(row.priority))); card.append(top, node('b', '', row.title), node('small', '', endpoint(row)), node('small', '', row.rank == null ? 'Requires scoring review →' : `Rank #${row.rank}${row.tie_count > 1 ? ` · ${row.tie_count} tied` : ''} · view fix plan →`)); card.addEventListener('click', () => openFinding(row, card)); $('fix-first').append(card); }
  if (!rows.length) $('fix-first').append(node('p', '', 'No vulnerability findings recorded. Review coverage before drawing conclusions about safety.'));
  $('rank-note').textContent = `${data.scoring_note}${scored[0]?.tie_count > 3 ? ` Showing three of ${scored[0].tie_count} equally ranked top findings; all are listed below.` : ''}`;
  $('distribution').replaceChildren(); for (const band of bands) { const count = rows.filter(row => normalizedBand(row.band) === band).length; if (!count && !['Critical', 'High', 'Medium', 'Low'].includes(band)) continue; const bar = node('div', 'distribution-row'); bar.append(node('span', '', band), meter(count, rows.length, band), node('strong', '', count)); $('distribution').append(bar); }
  $('coverage').replaceChildren(); for (const [tool, coverage] of Object.entries(data.coverage ?? {})) $('coverage').append(node('p', '', `${tool}: ${typeof coverage === 'string' ? coverage : JSON.stringify(coverage)}`)); list($('coverage'), 'Retained coverage gaps', data.coverage_gaps ?? []); $('coverage').append(node('p', '', data.selection_mode === 'selected' ? 'Showing the requested saved assessment; another capture was not substituted.' : `${data.excluded_partial_captures} partial captures excluded from latest-completed selection. ${data.unverified_captures} unverified captures in history.`), link('Original assessment evidence ↗', data.evidence_url)); renderTable();
  if (selected) {const row = rows.find(row => row.id === selected); if (row) renderDetail(row); else closeDetail();}
}
async function refresh() {
  if (loading) return; loading = true; $('refresh').disabled = true;
  try { const query = requestedCapture == null ? '' : `?capture=${encodeURIComponent(requestedCapture)}`; const response = await fetch(`/api/vulnerability-findings${query}`, {cache: 'no-store'}); const data = await response.json(); if (!response.ok) throw new Error(data.error?.message || 'Saved assessment could not be verified.'); render(data); $('status').textContent = `Updated ${new Date().toLocaleTimeString()}`; }
  catch (error) {assessment = null; closeDetail(); $('dashboard').hidden = true; $('empty').hidden = false; $('empty-title').textContent = 'Assessment unavailable'; $('empty-message').textContent = error.message; $('target').textContent = 'Unable to verify latest assessment'; $('ai-status').textContent = ''; $('snapshot-meta').textContent = 'No unverified results displayed'; $('status').textContent = 'Refresh failed. No scan, AI request or evidence change was made.'; }
  finally {loading = false; $('refresh').disabled = false;}
}
$('refresh').addEventListener('click', refresh); $('search').addEventListener('input', renderTable); $('severity').addEventListener('change', renderTable); $('kev-only').addEventListener('change', renderTable); $('close-detail').addEventListener('click', closeDetail); document.addEventListener('keydown', event => {if (event.key === 'Escape' && selected) closeDetail();});
setInterval(() => {if (!document.hidden) refresh();}, 60000);
refresh();
