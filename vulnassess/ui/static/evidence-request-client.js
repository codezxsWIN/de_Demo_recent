// Typed requests use server-owned identity, approval and immutable capture records.
export function mountEvidenceRequests({getTarget, getRunId, getProvider, canShare}) {
  const byId = id => document.getElementById(id);
  const status = byId('evidence-request-status'), review = byId('evidence-request-review');
  const detail = byId('evidence-request-detail'), result = byId('evidence-request-result');
  const propose = byId('propose-evidence-request'), approve = byId('approve-evidence-request');
  const reject = byId('reject-evidence-request'), analyze = byId('analyze-follow-up');
  let record = null, captured = false, busy = false, revision = 0;
  const text = (tag, content) => { const element = document.createElement(tag); element.textContent = content; return element; };
  const controls = () => {
    propose.disabled = busy; approve.disabled = busy || record?.state !== 'proposed';
    reject.disabled = approve.disabled; analyze.disabled = busy || !captured;
    review.hidden = !record;
  };
  const input = () => {
    const provider = getProvider();
    if (!getTarget() || !getRunId()) throw new Error('Enter an authorised target and select an assessment first.');
    if (provider !== 'ollama' && !canShare()) throw new Error('Confirm evidence sharing with the selected provider first.');
    return {target: getTarget(), run_id: getRunId(), provider, share_evidence: provider !== 'ollama'};
  };
  const request = async (action, body) => {
    const response = await fetch(`/api/evidence-requests/${action}`, {method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'X-VulnAssess-Action': 'evidence-request'}, body: JSON.stringify(body)});
    const value = await response.json();
    if (!response.ok) throw new Error(value.error?.message || 'Evidence request failed. Existing scan evidence is preserved.');
    return value;
  };
  const action = async task => {
    const started = revision;
    busy = true; controls();
    try { await task(started); } catch (error) { if (started === revision) status.textContent = error.message; }
    finally { busy = false; controls(); }
  };
  for (const id of ['new-target', 'workflow-run', 'analyst-provider', 'share-evidence']) {
    byId(id).addEventListener('input', () => {
      revision++; record = null; captured = false; detail.replaceChildren(); result.replaceChildren(); controls();
      status.textContent = 'Selection changed. Propose a request for this target and assessment.';
    });
  }
  propose.addEventListener('click', () => action(async started => {
    const body = input(); record = null; controls(); detail.replaceChildren();
    status.textContent = 'AI is reviewing the observed services. No probe is running.';
    const value = await request('propose', body);
    if (started !== revision) return;
    record = value;
    const item = record.request;
    detail.append(text('strong', `${item.kind.replaceAll('_', ' ')} · ${item.target_ip}:${item.port}`),
      text('p', item.reason), text('p', `Expected information gain: ${item.expected_information_gain}`),
      text('p', `Limit ${item.timeout_seconds}s · approval expires in 10 minutes · SHA-256 ${record.request_hash}`));
    for (const claim of item.claims) {
      detail.append(text('p', `${claim.label} · ${Math.round(claim.confidence * 100)}% confidence · ${claim.evidence_ids.join(', ')}`));
      for (const quote of claim.quotes) detail.append(text('blockquote', `${quote.evidence_id}: ${quote.text}`));
    }
    status.textContent = 'Review the exact target, operation and reason. Approving performs this one check.';
  }));
  approve.addEventListener('click', () => action(async started => {
    record.state = 'executing';
    status.textContent = 'Collecting the approved observation…';
    const value = await request('approve', {request_id: record.request_id, request_hash: record.request_hash});
    if (started !== revision) return;
    record = value; captured = true;
    const evidence = value.evidence;
    result.replaceChildren(text('strong', 'Follow-up evidence saved'), text('pre', evidence.observation),
      text('p', `AI-requested · ${evidence.kind} · ${evidence.captured_at}`),
      text('p', `Evidence ${evidence.id} · retained evidence SHA-256 ${evidence.raw_sha256}`));
    status.textContent = 'Observation saved. Analyze it alongside the scan; existing findings and scores remain unchanged.';
  }));
  reject.addEventListener('click', () => action(async started => {
    const value = await request('reject', {request_id: record.request_id, request_hash: record.request_hash, reason: byId('evidence-rejection-reason').value.trim()});
    if (started !== revision) return;
    record = value; status.textContent = 'Rejected. Your reason is recorded; no probe ran.';
  }));
  analyze.addEventListener('click', () => action(async started => {
    status.textContent = 'Analyzing the captured observations with citation and score validation…';
    const value = await request('analyze', input());
    if (started !== revision) return;
    result.append(text('h4', 'Validated follow-up analysis'), text('p', value.analysis.summary));
    for (const item of value.analysis.recommended_actions || []) result.append(text('p', `${item.action} — ${item.reason} [${item.evidence_ids.join(', ')}]`));
    const details = document.createElement('details'); details.append(text('summary', 'Validated response and evidence provenance'), text('pre', JSON.stringify(value, null, 2))); result.append(details);
    status.textContent = `${value.model} · validated · canonical scores unchanged`;
  }));
  controls();
}
