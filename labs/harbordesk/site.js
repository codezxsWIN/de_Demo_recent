// API values render as text. The intentional HTML sink remains on /search.
'use strict';
const byId = id => document.getElementById(id);
const panels = [...document.querySelectorAll('.panel')];
const loaded = new Set();
const versions = new Map();
let ticketRows = [];
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function status(target, message, kind = '') { target.replaceChildren(element('p', message, `status ${kind}`)); }
async function request(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(path, {...options, credentials:'same-origin', signal:controller.signal, headers:{Accept:'application/json', ...options.headers}});
    const body = await response.text();
    let data;
    try { data = JSON.parse(body); }
    catch { throw new Error(`Non-JSON response for ${path} (HTTP ${response.status}). Check the local lab backend.`); }
    if (!data || typeof data !== 'object') throw new Error('The server returned an unexpected response format.');
    if (!response.ok || data.error) {
      const hint = {401:'Sign in with a training account and retry.',403:'The current session is not allowed to access this record.',404:'Check the record ID and that the expanded lab backend is running.'}[response.status];
      throw new Error([`HTTP ${response.status}`, printable(data.error || 'Request failed.'), hint].filter(Boolean).join(' · '));
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('The local lab took too long to respond. Check the server and retry.');
    if (error instanceof TypeError) throw new Error('Cannot reach the local lab. Check that its server is running, then retry.');
    throw error;
  } finally { clearTimeout(timeout); }
}
async function renderRequest(id, action, render) {
  const target = byId(id);
  const version = (versions.get(id) || 0) + 1;
  versions.set(id, version); target.setAttribute('aria-busy', 'true');
  status(target, 'Loading from the local server…');
  try {
    const data = await action();
    if (versions.get(id) !== version) return;
    target.replaceChildren(); render(target, data);
  } catch (error) {
    if (versions.get(id) === version) status(target, error.message, 'error');
  } finally {
    if (versions.get(id) === version) target.setAttribute('aria-busy', 'false');
  }
}
function printable(value) { return value === null || value === undefined ? '—' : typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value); }
function details(target, record, title) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error(`No ${title.toLowerCase()} record was returned.`);
  target.append(element('h3', title));
  const list = element('dl');
  Object.entries(record).forEach(([key, value]) => list.append(element('dt', key.replaceAll('_', ' ')), element('dd', printable(value))));
  target.append(list);
  const raw = element('details');
  raw.append(element('summary', 'View API record'), element('pre', JSON.stringify(record, null, 2))); target.append(raw);
}
function table(target, rows, columns, caption, onSelect) {
  if (!rows.length) { target.append(element('p', 'No matching records. Change the search or filter and retry.', 'status')); return; }
  const wrapper = element('div', undefined, 'table-wrap');
  const grid = element('table');
  grid.append(element('caption', `${caption} · ${rows.length} ${rows.length === 1 ? 'record' : 'records'}`));
  const head = element('thead'); const headings = element('tr');
  for (const [, title] of columns) { const th = element('th', title); th.scope = 'col'; headings.append(th); }
  if (onSelect) { const th = element('th', 'Details'); th.scope = 'col'; headings.append(th); }
  head.append(headings); const body = element('tbody');
  rows.forEach(row => {
    const tr = element('tr');
    columns.forEach(([key]) => tr.append(element('td', printable(row[key]))));
    if (onSelect) {
      const cell = element('td'); const button = element('button', 'View details', 'text-button'); button.type = 'button';
      button.setAttribute('aria-label', `View details for ${row.name || row.subject || row.title || row.id || 'record'}`);
      button.addEventListener('click', () => onSelect(row)); cell.append(button); tr.append(cell);
    }
    body.append(tr);
  });
  grid.append(head, body); wrapper.append(grid); target.append(wrapper);
}
function recordFrom(data, key) { return Object.hasOwn(data, key) ? data[key] : data; }
function loadCustomers(event) {
  event?.preventDefault(); byId('customer-detail').hidden = true;
  return renderRequest('customer-result', () => request('/api/customers?q=' + encodeURIComponent(byId('customer-query').value)), (target, data) => {
    if (!Array.isArray(data.customers)) throw new Error('The customer response did not include a customer list.');
    table(target, data.customers, [['name','Name'],['email','Email'],['account','Account']], 'Customer directory', row => {
      const detail = byId('customer-detail'); detail.replaceChildren(); detail.hidden = false; details(detail, row, 'Customer details');
    });
  });
}
const recordKinds = {
  order:{path:'orders', title:'Order', list:'orders-list', ids:[2001,2002], columns:[['id','Order'],['owner','Account owner'],['item','Item'],['total','Total']]},
  ticket:{path:'tickets', title:'Ticket'},
  document:{path:'documents', title:'Document', list:'documents-list', ids:[4001,4002], columns:[['id','Document'],['title','Title'],['owner','Account owner']]}
};
function loadRecord(kind, id) {
  const config = recordKinds[kind]; byId(`${kind}-id`).value = id;
  return renderRequest(`${kind}-result`, async () => {
    if (!/^\d+$/.test(String(id)) || Number(id) < 1) throw new Error('Enter a positive whole-number record ID.');
    return request(`/api/${config.path}/${encodeURIComponent(id)}`);
  }, (target, data) => details(target, recordFrom(data, kind), `${config.title} ${id}`));
}
function loadFixtureList(kind) {
  const config = recordKinds[kind];
  return renderRequest(config.list, () => Promise.allSettled(config.ids.map(id => request(`/api/${config.path}/${id}`))), (target, results) => {
    const rows = [];
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        const row = recordFrom(result.value, kind);
        if (row && typeof row === 'object') rows.push({id:config.ids[index], ...row});
        else target.append(element('p', `${config.title} ${config.ids[index]}: no record returned.`, 'status error'));
      } else target.append(element('p', `${config.title} ${config.ids[index]}: ${result.reason.message}`, 'status error'));
    });
    if (rows.length) table(target, rows, config.columns, `${config.title} fixtures`, row => loadRecord(kind, row.id));
  });
}
function showTickets() {
  const target = byId('tickets-list'); const query = byId('ticket-filter').value.toLowerCase(); target.replaceChildren();
  table(target, ticketRows.filter(row => Object.values(row).some(value => printable(value).toLowerCase().includes(query))), [['id','Ticket'],['subject','Subject'],['owner','Account owner'],['status','Status']], 'Support tickets', row => loadRecord('ticket', row.id));
}
function loadTickets() {
  return renderRequest('tickets-list', () => request('/api/tickets'), (target, data) => {
    const rows = Array.isArray(data) ? data : data.tickets;
    if (!Array.isArray(rows)) throw new Error('The response did not include a ticket list.');
    ticketRows = rows; showTickets();
  });
}
function displaySession(user) {
  const signedIn = user && typeof user === 'object' && user.username;
  byId('session-label').textContent = signedIn ? `${user.username} · ${user.role || 'account'}` : 'Guest session';
  document.querySelector('.session a').textContent = signedIn ? 'Account settings' : 'Sign in';
  byId('overview-session').textContent = signedIn ? `Signed in as ${user.username}${user.role ? ` (${user.role})` : ''}. Open Settings to refresh the server profile.` : 'Browsing as a guest. Sign in with a fictional account to inspect session behavior.';
}
function loadProfile() {
  return renderRequest('profile-result', async () => {
    try { return await request('/api/profile'); }
    catch (error) { if (error.message.startsWith('HTTP 401')) displaySession(null); throw error; }
  }, (target, data) => {
    const profile = data.profile ?? data.user ?? data;
    details(target, profile, 'Server profile');
  });
}
function loadNetwork() {
  byId('network-detail').hidden = true;
  return renderRequest('network-result', () => request('/__lab__/inventory'), (target, data) => {
    if (typeof data.network_enabled !== 'boolean' || !Array.isArray(data.services)) throw new Error('Expected network_enabled and services in the local inventory response.');
    target.append(element('p', data.network_enabled ? 'Network services enabled in backend configuration. Reachability and findings require separate checks.' : 'Network services disabled. Start the backend with --network, then refresh inventory.', 'status'));
    if (data.boundary) target.append(element('p', printable(data.boundary), 'muted'));
    table(target, data.services, [['name','Service'],['port','Loopback port'],['transport','Transport'],['mode','Declared mode'],['endpoint','Local endpoint']], 'Declared configuration · not scanner evidence', row => {
      const detail = byId('network-detail'); detail.replaceChildren(); detail.hidden = false;
      details(detail, row, 'Declared service configuration');
    });
  });
}
function loadGuide() {
  return renderRequest('case-list', () => request('/__lab__/ground-truth'), (target, data) => {
    if (!Array.isArray(data.cases)) throw new Error('The answer key did not include test cases.');
    for (const item of data.cases) {
      const row = element('article', undefined, 'case');
      row.append(element('strong', `${item.id} · ${item.name}`), element('p', item.endpoint), element('p', item.expected || item.current_scanner_coverage || 'Consult the machine-readable answer key.')); target.append(row);
    }
  });
}
function comparisonLinks(event) {
  event?.preventDefault(); const query = encodeURIComponent(byId('comparison-query').value);
  const target = byId('comparison-links'); target.replaceChildren();
  for (const [title, path] of [['Portal search','/search'],['Customer API','/api/customers']]) {
    const item = element('article'); item.append(element('h3', title));
    for (const [label, prefix] of [['Vulnerable',''],['Secure','/secure']]) {
      const link = element('a', `${label} ${title.toLowerCase()} →`); link.href = `${prefix}${path}?q=${query}`; item.append(link);
    }
    target.append(item);
  }
}
const loaders = {
  network:loadNetwork, customers:loadCustomers,
  orders:() => Promise.all([loadFixtureList('order'), loadRecord('order', byId('order-id').value)]),
  support:() => Promise.all([loadTickets(), loadRecord('ticket', byId('ticket-id').value)]),
  documents:() => Promise.all([loadFixtureList('document'), loadRecord('document', byId('document-id').value)]),
  settings:loadProfile, 'lab-guide':loadGuide
};
function navigate() {
  const requested = location.hash.slice(1);
  const id = panels.some(panel => panel.id === requested) ? requested : 'overview';
  panels.forEach(panel => { panel.hidden = panel.id !== id; });
  document.querySelectorAll('[data-tab]').forEach(link => {
    if (link.dataset.tab === id) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current');
  });
  byId('breadcrumb').textContent = byId(id).querySelector('h1').textContent;
  if (!loaded.has(id) && loaders[id]) { loaded.add(id); loaders[id](); }
}
byId('customer-form').addEventListener('submit', loadCustomers);
byId('customer-all').addEventListener('click', () => { byId('customer-query').value = ''; loadCustomers(); });
for (const kind of Object.keys(recordKinds)) byId(`${kind}-form`).addEventListener('submit', event => { event.preventDefault(); loadRecord(kind, byId(`${kind}-id`).value); });
document.querySelectorAll('[data-record]').forEach(button => button.addEventListener('click', () => loadRecord(button.dataset.record, button.dataset.id)));
byId('orders-refresh').addEventListener('click', () => loadFixtureList('order'));
byId('documents-refresh').addEventListener('click', () => loadFixtureList('document'));
byId('tickets-refresh').addEventListener('click', loadTickets);
byId('ticket-filter').addEventListener('input', showTickets);
byId('profile-refresh').addEventListener('click', loadProfile);
byId('network-refresh').addEventListener('click', loadNetwork);
byId('guide-refresh').addEventListener('click', loadGuide);
byId('comparison-form').addEventListener('submit', comparisonLinks);
byId('login-form').addEventListener('submit', async event => {
  event.preventDefault(); const button = event.currentTarget.querySelector('button'); button.disabled = true;
  await renderRequest('login-result', () => request('/api/login', {method:'POST', body:new URLSearchParams({username:byId('username').value,password:byId('password').value})}), (target, data) => {
    if (!data.user?.username) throw new Error('Sign-in failed: the server did not return an authenticated user.');
    displaySession(data.user); status(target, `Signed in as ${data.user.username} (${data.user.role || 'account'}).`, 'success');
    ['orders','support','documents'].forEach(id => loaded.delete(id)); loadProfile();
  });
  button.disabled = false;
});
window.addEventListener('hashchange', navigate);
// This lab deliberately uses a readable session cookie. Restore only its display
// name; server endpoints, not this UI label, decide access to records.
const sessionCookie = document.cookie.split(';').map(part => part.trim()).find(part => part.startsWith('lab_session='));
if (sessionCookie) {
  try { displaySession({username:decodeURIComponent(sessionCookie.slice('lab_session='.length))}); }
  catch { displaySession(null); }
}
comparisonLinks(); navigate();
