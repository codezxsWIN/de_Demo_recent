// A reference-only cache reader. It never enriches a target or executes a model.
export function mountCachedIntelligence(holder, preferred = '', source = 'intel') {
  const names = {nvd: 'NIST NVD · CVSS & CPE Match', epss: 'FIRST EPSS · exploitation probability', kev: 'CISA KEV · known exploitation', intel: 'Available intelligence cache'};
  if (!Object.hasOwn(names, source)) source = 'intel';
  const make = (tag, value = '') => {
    const node = document.createElement(tag); node.textContent = value; return node;
  };
  const panel = make('section');
  panel.append(make('h3', names[source]), make('p',
    'Reference lookup only — not evidence that this CVE affects the selected target. This does not change workflow stage status or recorded scores.'));
  const label = make('label', 'Cached CVE identifier ');
  const input = make('input'); input.placeholder = 'CVE-2022-0543'; input.maxLength = 28;
  input.value = preferred; label.append(input);
  const button = make('button', 'Read cached data'); button.type = 'button';
  const status = make('p', 'Reading cache index…'); status.setAttribute('role', 'status');
  const output = make('div');
  const availability = make('p', 'Current cache availability: checking…');
  panel.append(label, button, status, output, availability); holder.append(panel);
  const showAvailability = cache => {
    const labels = {cached: 'cached', stale: 'stale', offline_snapshot: 'local snapshot', fixture: 'test data only', missing: 'not cached', unavailable: 'unavailable'};
    const feeds = (Array.isArray(cache?.feeds) ? cache.feeds : []).filter(feed => source === 'intel' || feed.feed === source);
    availability.textContent = feeds.length
      ? `Current cache availability: ${feeds.map(feed => `${String(feed.feed).toUpperCase()}: ${labels[feed.status] || 'unavailable'}${feed.date ? ` (publisher date ${feed.date})` : ''}`).join(' · ')}. Cache availability does not establish use in this run.`
      : 'Current cache availability: unavailable. Cache availability does not establish use in this run.';
  };
  const get = async path => {
    const response = await fetch(path, {cache: 'no-store'});
    const data = await response.json();
    if (!response.ok) throw Error(data.error?.message || 'Cache unavailable');
    return data;
  };
  async function lookup() {
    const cve = input.value.trim().toUpperCase();
    if (!/^CVE-[0-9]{4}-[0-9]{4,19}$/.test(cve)) { status.textContent = 'Enter a valid CVE identifier.'; return; }
    button.disabled = true;
    try {
      const data = await get(`/api/intelligence?cve=${encodeURIComponent(cve)}`);
      if (!panel.isConnected) return;
      showAvailability(data.cache);
      output.replaceChildren();
      if (!data.record || data.state !== 'cached') {
        status.textContent = 'No usable record in this cache. No network lookup was launched.'; return;
      }
      const record = data.record;
      status.textContent = `${cve} · cached publisher data, not target validation`;
      const fields = [
        ['CVSS 3.1', record.nvd?.cvss31_base ?? 'Not available'],
        ['CVSS vector', record.nvd?.cvss31_vector ?? 'Not available'],
        ['EPSS probability', record.epss?.epss ?? 'Not available'],
        ['EPSS percentile', record.epss?.percentile ?? 'Not available'],
        ['EPSS scoring date', record.epss?.score_date ?? 'Not available'],
        ['CISA KEV', record.kev_listed === true ? 'Listed' : record.kev_listed === false ? 'Not listed in the recorded catalog' : 'Not checked'],
        ['KEV date added', record.kev?.dateAdded ?? 'Not available'],
        ['KEV vulnerability', record.kev?.vulnerabilityName ?? 'Not available'],
        ['KEV vendor / product', record.kev ? `${record.kev.vendorProject || 'Unknown'} / ${record.kev.product || 'Unknown'}` : 'Not available'],
        ['Required action', record.kev?.requiredAction ?? 'Not available'],
        ['CISA due date', record.kev?.dueDate ?? 'Not available'],
        ['Known ransomware campaign use', record.kev?.knownRansomwareCampaignUse ?? 'Not available'],
      ];
      const visible = source === 'nvd' ? fields.slice(0, 2) : source === 'epss' ? fields.slice(2, 5) : source === 'kev' ? fields.slice(5) : fields;
      for (const [name, value] of visible) output.append(make('p', `${name}: ${value}`));
      if (source === 'epss' || source === 'intel') output.append(make('p',
        'EPSS estimates exploitation of a CVE in the next 30 days; it is not the probability this host is compromised. Percentile is relative to other CVEs.'));
      if (source === 'kev' || source === 'intel') output.append(make('p',
        'KEV records known exploitation in the wild, not confirmed compromise of this target. A catalog due date is not a locally assigned remediation deadline.'));
      const cpe = record.cpe_match;
      if (source === 'nvd' || source === 'intel') {
        output.append(make('h4', 'NVD product/version applicability'));
        output.append(make('p', cpe
          ? `CPE Match: ${cpe.returned} of ${cpe.total_results} criteria · ${cpe.coverage} page coverage · retrieved ${cpe.fetched_at}`
          : 'No CPE Match response cached. This is not a negative applicability result.'));
        if (cpe) output.append(make('p', cpe.notice));
        for (const item of cpe?.records || []) {
          const criterion = make('details');
          criterion.append(make('summary', `${item.status} · ${item.criteria}`));
          criterion.append(make('p', `Match criteria ID: ${item.matchCriteriaId}`));
          for (const key of ['versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding']) {
            if (item[key] != null) criterion.append(make('p', `${key}: ${item[key]}`));
          }
          criterion.append(make('p', `NVD last modified: ${item.lastModified || 'Unknown'}`));
          output.append(criterion);
        }
      }
      const feeds = (data.cache?.feeds || []).filter(feed => source === 'intel' || feed.feed === source);
      output.append(make('p', feeds.map(feed => `${feed.feed}: ${feed.status}, publisher date ${feed.date || 'unknown'}`).join(' · ')));
      for (const feed of feeds) {
        const provenance = data.sources?.[feed.feed];
        if (!provenance) continue;
        output.append(make('p', `Retrieved: ${provenance.loaded_at || 'Unknown'}`));
        if (provenance.url) {
          const link = make('a', `Official ${feed.feed.toUpperCase()} source`);
          link.href = provenance.url; link.target = '_blank'; link.rel = 'noopener noreferrer';
          output.append(link);
        }
      }
      const details = make('details');
      const scopedRecord = source === 'nvd' ? {cve, nvd: record.nvd, cpe_match: cpe}
        : source === 'epss' ? {cve, epss: record.epss}
        : source === 'kev' ? {cve, kev: record.kev, kev_listed: record.kev_listed} : record;
      const sources = source === 'intel' ? data.sources : {[source]: data.sources?.[source]};
      details.append(make('summary', 'Full cached record and source provenance'),
        make('pre', JSON.stringify({record: scopedRecord, sources}, null, 2)));
      output.append(details);
    } catch (error) { if (panel.isConnected) status.textContent = error.message; }
    finally { button.disabled = false; }
  }
  button.addEventListener('click', lookup);
  input.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); if (!button.disabled) lookup(); } });
  get('/api/intelligence').then(data => {
    if (!panel.isConnected) return;
    showAvailability(data.cache);
    const ids = data.cve_ids || [];
    status.textContent = ids.length ? `Available: ${ids.join(', ')}${data.index_truncated ? ' (index limited to 100; type another known ID)' : ''}` : 'No operational CVEs cached. No network request to publishers was made.';
    if (!input.value && ids.length) input.value = ids[0];
    if (input.value) return lookup();
  }).catch(error => { if (panel.isConnected) { status.textContent = error.message; showAvailability(null); } });
}
