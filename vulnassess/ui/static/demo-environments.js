// Fixed demo shortcuts use the ordinary scope check and live-assessment path.
export const DEMO_ENVIRONMENTS = Object.freeze([
  Object.freeze({id: 'harbordesk', target: 'http://127.0.0.1:8787/', url: 'http://127.0.0.1:8787/', name: 'HarborDesk', description: 'Web application and local network extensions. Scan target: http://127.0.0.1:8787/.'}),
  Object.freeze({id: 'office', target: '127.0.0.2', url: 'http://127.0.0.1:8798/office', name: 'Office network', description: 'FTP, SSH, SMB and a versioned Redis service. Scan target: 127.0.0.2; the console URL is not the scan target. CVE version matches require verification.'}),
  Object.freeze({id: 'iot', target: '127.0.0.3', url: 'http://127.0.0.1:8798/iot', name: 'IoT network', description: 'MQTT, SNMP, TLS and a versioned Redis service. Scan target: 127.0.0.3; the console URL is not the scan target. CVE version matches require verification.'}),
]);

export function demoFromHash(hash) {
  if (hash === '#demo-environments') return '';
  const match = /^#demo-environments=(harbordesk|office|iot)$/.exec(hash);
  return match ? match[1] : null;
}

export function mountDemoEnvironments({getBusy = () => false, onSelect = () => {}} = {}) {
  const select = document.getElementById('demo-environment');
  const input = document.getElementById('new-target');
  const mode = document.getElementById('live-run-mode');
  const description = document.getElementById('demo-environment-description');
  const link = document.getElementById('open-demo-environment');
  const choices = [...document.querySelectorAll('[data-demo-choice]')];
  let selected = '';
  function updateChoices() { choices.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.demoChoice === selected))); }
  choices.forEach(button => button.addEventListener('click', () => {
    if (getBusy()) return;
    select.value = button.dataset.demoChoice;
    select.dispatchEvent(new Event('change', {bubbles: true}));
  }));
  function reset() {
    selected = '';
    updateChoices();
    select.value = '';
    link.hidden = true;
    link.removeAttribute('href');
    description.textContent = 'Choose a demo to fill its correct target, then check scope and run. Selection does not launch a scan or start containers.';
  }
  select.addEventListener('change', () => {
    if (getBusy()) { select.value = selected; return; }
    const demo = DEMO_ENVIRONMENTS.find(item => item.id === select.value);
    if (!demo) { reset(); return; }
    selected = demo.id;
    updateChoices();
    input.value = demo.target;
    mode.value = 'new';
    mode.dispatchEvent(new Event('change', {bubbles: true}));
    input.dispatchEvent(new Event('input', {bubbles: true}));
    description.textContent = demo.description + ' Use Run live target to assess it. ' + (demo.id === 'harbordesk' ? 'The local HarborDesk runtime must be running.' : 'Docker Desktop, the lab containers and the console must be running.');
    link.href = demo.url;
    link.textContent = `Open ${demo.name} environment ↗`;
    link.hidden = false;
    onSelect(demo);
  });
  input.addEventListener('input', () => {
    if (!DEMO_ENVIRONMENTS.some(item => item.id === selected && item.target === input.value.trim())) reset();
  });
  mode.addEventListener('change', () => { if (mode.value !== 'new') reset(); });
  reset();
  return {setBusy: value => { select.disabled = Boolean(value); choices.forEach(button => { button.disabled = Boolean(value); }); }};
}
