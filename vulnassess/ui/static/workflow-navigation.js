// Keep the live event reader and canvas mounted when opening saved evidence.
// Native link navigation is retained, including keyboard and modifier clicks.
export function preserveWorkflowNavigation(event, origin = window.location.origin) {
  const link = event.target?.closest?.('a[href]');
  if (!link || link.hasAttribute('download')) return;
  let destination;
  try { destination = new URL(link.href, origin); } catch { return; }
  const reviewPage = ['/', '/findings', '/vulnerabilities', '/environment', '/captures', '/website-check'].includes(destination.pathname);
  const savedEvidence = /^\/captures\/assessment-[A-Za-z0-9_-]+(?:\/report(?:\/download)?)?$/.test(destination.pathname);
  if (destination.origin !== origin || (!reviewPage && !savedEvidence)) return;
  link.target = '_blank';
  const relations = new Set((link.getAttribute('rel') || '').split(/\s+/).filter(Boolean));
  relations.add('noopener');
  relations.add('noreferrer');
  link.setAttribute('rel', [...relations].join(' '));
  link.title = 'Opens separately; the workflow stays running in this tab';
}
