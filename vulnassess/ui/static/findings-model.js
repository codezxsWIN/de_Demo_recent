export const bands = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown', 'Unscored'];
export const normalizedBand = value => value === 'Informational' ? 'Info' : value;
export const displayNumber = value => typeof value === 'number' && Number.isFinite(value) ? String(Math.round(value * 100) / 100) : '—';
export const displayEpss = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1 ? `${(value * 100).toFixed(3)}%` : '—';
export const endpoint = row => `${row.host ?? 'Unknown host'}${row.port == null ? '' : `:${row.port}`}${row.protocol ? ` / ${row.protocol.toUpperCase()}` : ''}`;
export const kevLabel = cves => cves.some(cve => cve.kev === true) ? 'Listed' : cves.length && cves.every(cve => cve.kev === false) ? 'Not listed' : 'Unknown';
export function filterFindings(rows, {query = '', band = 'all', kev = false} = {}) {
  const text = query.trim().toLocaleLowerCase();
  return rows.filter(row => (band === 'all' || normalizedBand(row.band) === band)
    && (!kev || row.cves.some(cve => cve.kev === true))
    && (!text || [row.title, row.host, row.port, row.tool, row.path, ...row.cves.map(cve => cve.id)].join(' ').toLocaleLowerCase().includes(text)));
}
