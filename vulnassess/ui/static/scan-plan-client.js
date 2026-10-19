// The server owns approval; browser state only presents the exact plan for review.
export function validatePlanRecord(record) {
  if (!record || !/^[a-f0-9]{32}$/.test(record.plan_id) || !/^[a-f0-9]{64}$/.test(record.plan_hash)
      || !['draft', 'approved', 'executing', 'completed', 'needs_reapproval'].includes(record.state)
      || record.plan?.schema_version !== 'scan_plan.v1' || typeof record.plan.target_ip !== 'string'
      || !Array.isArray(record.plan.steps) || record.plan.steps.length < 1 || record.plan.steps.length > 2
      || !Array.isArray(record.plan.claims) || !Array.isArray(record.evidence)) {
    throw new Error('Scan plan response has an invalid approval binding.');
  }
  for (const [index, step] of record.plan.steps.entries()) {
    const tool = index === 0 ? 'nmap' : 'nikto';
    if (step.tool !== tool || step.profile !== (index ? 'nikto_web_bounded' : 'nmap_light')
        || !Number.isInteger(step.timeout_seconds) || step.timeout_seconds < 30 || step.timeout_seconds > (index ? 150 : 180)
        || typeof step.reason !== 'string' || !Number.isFinite(step.confidence) || step.confidence < 0 || step.confidence > 1) {
      throw new Error('Scan plan contains an unsupported tool or profile.');
    }
  }
  if (record.evidence.some(item => !item || typeof item.id !== 'string' || typeof item.text !== 'string')) {
    throw new Error('Scan plan evidence is malformed.');
  }
  return record;
}

export function editedPlan(record, durations, includeNikto) {
  const plan = structuredClone(validatePlanRecord(record).plan);
  const count = includeNikto ? plan.steps.length : 1;
  plan.steps = plan.steps.slice(0, count).map((step, index) => {
    const timeout = Number(durations[index]);
    if (!Number.isInteger(timeout) || timeout < 30 || timeout > (index ? 150 : 180)) {
      throw new Error('Choose a timeout within the displayed range.');
    }
    return {...step, timeout_seconds: timeout};
  });
  plan.claims = plan.claims.filter(claim => plan.steps.some((_, index) => claim.path === `steps[${index}].reason`));
  return plan;
}

async function request(action, body) {
  const response = await fetch(`/api/scan-plans/${action}`, {
    method: 'POST', cache: 'no-store', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-VulnAssess-Action': 'scan-plan'},
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error?.message || 'Scan plan request failed. Quick scan remains available.');
  return validatePlanRecord(result);
}

export function mountScanPlanner({getTarget, getRunId, getProvider, canShare, onRun}) {
  const panel = document.getElementById('scan-plan-review');
  const status = document.getElementById('scan-plan-status');
  const list = document.getElementById('scan-plan-steps');
  const propose = document.getElementById('propose-scan-plan');
  const save = document.getElementById('save-scan-plan');
  const approve = document.getElementById('approve-scan-plan');
  const run = document.getElementById('run-scan-plan');
  let draft = null, busy = false, dirty = false, revision = 0;
  const controls = () => {
    propose.disabled = busy;
    save.disabled = busy || !draft || !dirty;
    approve.disabled = busy || !draft || dirty || draft.state !== 'draft';
    run.disabled = busy || !draft || dirty || draft.state !== 'approved';
    panel.setAttribute('aria-busy', String(busy));
  };
  const text = (tag, value) => { const node = document.createElement(tag); node.textContent = value; return node; };
  const render = () => {
    list.replaceChildren();
    panel.hidden = !draft;
    if (!draft) { controls(); return; }
    const total = draft.plan.steps.reduce((sum, step) => sum + step.timeout_seconds, 0);
    document.getElementById('scan-plan-binding').textContent = `Pinned IP ${draft.plan.target_ip} · ${draft.state.replaceAll('_', ' ')} · scanner budget ${total}s · approval expires after 30 minutes or server restart · SHA-256 ${draft.plan_hash}`;
    for (const [index, step] of draft.plan.steps.entries()) {
      const row = document.createElement('li');
      row.append(text('strong', `${index + 1}. ${step.tool === 'nmap' ? 'Nmap discovery' : 'Nikto web checks'}`),
        text('p', `${step.profile} · ${Math.round(step.confidence * 100)}% planning confidence`), text('p', step.reason));
      const label = text('label', 'Time limit (seconds)');
      const timeout = document.createElement('input');
      timeout.type = 'number'; timeout.min = '30'; timeout.max = index ? '150' : '180';
      timeout.value = step.timeout_seconds; timeout.dataset.planTimeout = String(index);
      label.append(timeout); row.append(label);
      if (index) {
        const include = document.createElement('input'); include.type = 'checkbox'; include.checked = true; include.id = 'scan-plan-include-nikto';
        const choice = text('label', ' Include this web step'); choice.prepend(include); row.append(choice);
      }
      const claim = draft.plan.claims.find(item => item.path === `steps[${index}].reason`);
      const details = document.createElement('details'); details.append(text('summary', `Evidence · ${(claim?.evidence_ids || []).join(', ')}`));
      for (const id of claim?.evidence_ids || []) {
        const evidence = draft.evidence.find(item => item.id === id);
        if (evidence) details.append(text('pre', `${id}: ${evidence.text}`));
      }
      row.append(details); list.append(row);
    }
    controls();
  };
  const invalidate = () => {
    revision++; draft = null; dirty = false; render();
    status.textContent = 'Target, hints or model changed. Propose a fresh plan; quick scan is still available.';
  };
  for (const id of ['new-target', 'analyst-provider', 'scan-plan-hints', 'live-run-mode', 'workflow-run', 'share-evidence']) {
    document.getElementById(id).addEventListener('input', invalidate);
  }
  list.addEventListener('input', () => {
    dirty = true; status.textContent = 'Unsaved edits: approval is disabled until the server pins the new plan.'; controls();
  });
  const action = async (task) => {
    busy = true; controls();
    try { await task(); }
    catch (error) { status.textContent = error.message; }
    finally { busy = false; controls(); }
  };
  propose.addEventListener('click', () => action(async () => {
    const target = getTarget(), provider = getProvider(), started = ++revision;
    draft = null; dirty = false; render();
    if (!target) throw new Error('Enter an authorised target first.');
    if (document.getElementById('live-run-mode').value !== 'new') throw new Error('Choose a new live assessment to plan scanner execution.');
    if (provider !== 'ollama' && !canShare()) throw new Error('Confirm evidence sharing before requesting a cloud plan.');
    status.textContent = 'AI is reviewing prior target evidence and proposing tools. No scan is running.';
    const result = await request('propose', {target, provider, share_evidence: provider !== 'ollama', run_id: getRunId() || '', hints: document.getElementById('scan-plan-hints').value});
    if (started !== revision) return;
    draft = result; render(); status.textContent = 'Plan proposed. Review the evidence and time limits, then approve. Nothing has been scanned.';
  }));
  save.addEventListener('click', () => action(async () => {
    const started = revision;
    const durations = [...list.querySelectorAll('[data-plan-timeout]')].map(input => input.value);
    const plan = editedPlan(draft, durations, document.getElementById('scan-plan-include-nikto')?.checked ?? false);
    const result = await request('edit', {plan_id: draft.plan_id, plan_hash: draft.plan_hash, plan});
    if (started !== revision) return;
    draft = result;
    dirty = false; render(); status.textContent = 'Edits saved with a new hash. Previous approval is invalid; review and approve this revision.';
  }));
  approve.addEventListener('click', () => action(async () => {
    const started = revision;
    const result = await request('approve', {plan_id: draft.plan_id, plan_hash: draft.plan_hash});
    if (started !== revision) return;
    draft = result;
    render(); status.textContent = 'Approved for one execution. The runner will check scope and this exact plan before each tool.';
  }));
  run.addEventListener('click', () => action(async () => {
    const binding = {plan_id: draft.plan_id, plan_hash: draft.plan_hash};
    draft.state = 'executing'; render();
    status.textContent = 'Executing the approved plan. Follow the live assessment for scanner and AI outcomes.';
    await onRun(binding);
    draft = null; render();
    status.textContent = 'Execution request finished. Review the live result; a repeat run needs a new plan.';
  }));
  render();
}
