// Read-only presentation: observations stay separate from validated model advice.
const el = (tag, text, cls = '') => {
  const node = document.createElement(tag); node.textContent = text; node.className = cls; return node;
};
let selectedAction = 0;
const rechecks = new Map();
export function renderSelfDefence(holder, summary, busy) {
  holder.replaceChildren();
  const data = summary?.self_defence;
  if (!data) {
    holder.append(el('p', busy ? 'Checking this computer. Results appear as evidence arrives.' : 'Start a device check to inspect local protection and service exposure. No settings will be changed.'));
    return;
  }
  holder.append(el('p', `Checked ${data.checked_at}. ${data.boundary}`, 'overview-muted'));
  if (summary.saved_capture_id) {
    const report = el('a', 'Open your device security report · print / save PDF', 'quiet-link');
    report.href = `/captures/${encodeURIComponent(summary.saved_capture_id)}/report`;
    holder.append(report);
  } else {
    holder.append(el('p', summary.persistence_warning || 'Report download becomes available when this assessment has a saved checkpoint.', 'overview-muted'));
  }
  const queue = el('section', '', 'overview-section');
  queue.append(el('h3', 'What to do first'), el('p', 'Evidence-based verification order. These are precautions, not vulnerability severity scores.'));
  const layout = el('div', '', 'device-action-layout');
  const inspector = el('aside', '', 'device-action-inspector overview-section');
  inspector.ariaLabel = 'Selected precaution and evidence';
  const buttons = [];
  function select(index) {
    selectedAction = index;
    const item = data.action_queue[index];
    inspector.replaceChildren(el('span', item.kind, 'overview-muted'), el('h3', item.title), el('h4', 'Why this is here'), el('p', item.reason), el('h4', 'What you can do'), el('p', item.action), el('h4', 'Supporting observations'));
    for (const id of item.basis) {
      const record = data.checks.find(check => check.id === id);
      inspector.append(el('p', record?.observation || (id === 'active_profiles' ? `Active profiles: ${data.active_profiles?.join(', ') || 'not established'}` : 'Network listener observations are listed below.')));
      if (record) {
        const recheck = el('button', `Recheck ${record.title}`, 'tool-text'); recheck.type = 'button';
        const status = el('p', '', 'overview-muted'); status.role = 'status';
        const history = el('ol', '', 'device-recheck-history');
        const cacheKey = `${data.checked_at}:${record.id}`;
        function showResult(result) {
          const observed = result.checks.find(check => check.id === record.id);
          if (!observed) throw new Error('The recheck returned no matching observation');
          const meaning = observed.state === 'unknown' ? 'Current setting could not be verified.' : record.state === observed.state ? 'No setting change observed.' : 'Setting observation changed; threat removal is not established.';
          status.textContent = `${record.state} → ${observed.state} · checked ${result.checked_at}. ${meaning} AI advice still refers to the original assessment.`;
          history.replaceChildren();
          for (const row of (result.history || []).slice(0, 10)) history.append(el('li', `${row.checked_at} · ${row.state}`));
        }
        if (rechecks.has(cacheKey)) showResult(rechecks.get(cacheKey));
        recheck.addEventListener('click', async () => {
          recheck.disabled = true; status.textContent = 'Reading this setting again…';
          try {
            const response = await fetch('/api/device-recheck', {method:'POST', headers:{'Content-Type':'application/json','X-VulnAssess-Action':'device-recheck'}, body:JSON.stringify({check:record.id})});
            const result = await response.json();
            if (!response.ok) throw new Error(result.error?.message || 'Recheck failed');
            showResult(result);
            rechecks.set(cacheKey, result);
            if (rechecks.size > 100) rechecks.delete(rechecks.keys().next().value);
          } catch (error) { status.textContent = error.message || 'Recheck unavailable'; }
          finally { recheck.disabled = false; }
        });
        inspector.append(recheck, status, history);
      }
    }
    for (const observation of item.supporting_observations || []) inspector.append(el('p', observation));
    inspector.append(el('p', 'Manual guidance only. Review dependencies before changing settings. A changed setting does not prove a threat was removed.', 'overview-muted'));
    buttons.forEach((button, i) => { button.ariaPressed = String(i === index); });
  }
  for (const [index, item] of (data.action_queue || []).entries()) {
    const button = el('button', '', 'device-action-row'); button.type = 'button';
    button.append(el('span', String(index + 1).padStart(2, '0'), 'device-action-number'), el('strong', item.title), el('small', item.kind));
    button.addEventListener('click', () => select(index)); buttons.push(button); queue.append(button);
  }
  if (buttons.length) select(Math.min(selectedAction, buttons.length - 1));
  else inspector.append(el('h3', 'No queued precautions'), el('p', 'Review coverage and unknown checks before drawing conclusions.'));
  if (!data.action_queue?.length) queue.append(el('p', 'No actions were triggered by these checks. This is not proof of complete protection.'));
  const comparison = data.comparison;
  queue.append(el('h3', 'Changes since your last check'));
  if (comparison?.status === 'compared') {
    queue.append(el('p', `Compared with ${comparison.previous_at}. Changes describe settings, not confirmed threat removal.`));
    for (const change of comparison.changes) queue.append(el('p', `${change.check}: ${change.before} → ${change.after}`));
    if (!comparison.changes.length) queue.append(el('p', 'No changes in comparable protection settings.'));
  } else queue.append(el('p', 'First retained check: this establishes a baseline for your next device check.'));
  layout.append(queue, inspector); holder.append(layout);
  const checks = el('div', '', 'device-check-grid');
  for (const check of data.checks) {
    const card = el('article', '', 'overview-section');
    card.append(el('span', check.attention === 'review' ? 'REVIEW SETTING' : check.state === 'unknown' ? 'NOT VERIFIED' : 'OBSERVED', 'overview-muted'), el('h3', check.title), el('p', check.state), el('p', check.precaution));
    checks.append(card);
  }
  const checkDetails = el('details', '', 'device-check-details');
  checkDetails.append(el('summary', `All ${data.checks.length} protection checks`), checks);
  holder.append(checkDetails);
  const exposure = el('section', '', 'overview-section');
  exposure.append(el('h3', 'Applications accepting connections'), el('p', 'Network bindings show where an application listens, not whether it is reachable from the internet. Up to 64 listeners are collected.'));
  const list = el('ul', '');
  for (const item of data.listeners || []) list.append(el('li', `${item.application} · TCP ${item.port} · ${item.binding}`));
  exposure.append(list);
  if (!data.listeners?.length) exposure.append(el('p', 'Listener inventory unavailable or empty. No absence of exposure is claimed.'));
  exposure.append(el('h3', 'Antivirus & updates'), el('p', `Registered antivirus: ${data.antivirus_providers?.join(', ') || 'not verified'}. Registration alone does not establish active protection.`), el('p', `Latest recorded hotfix: ${data.last_recorded_update || 'unknown'}. This does not establish that every update is installed.`));
  holder.append(exposure);
  const ai = el('section', '', 'overview-section');
  ai.append(el('h3', 'AI explanation & next steps'), el('p', summary.validated_ai_summary || `AI ${summary.ai_status || 'pending'}. The checks above are direct observations and fixed precaution guidance.`));
  for (const action of summary.next_actions || []) ai.append(el('p', `${action.action} — ${action.reason}`));
  holder.append(ai, el('p', data.limitations, 'overview-muted'));
}
