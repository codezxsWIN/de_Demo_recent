'use strict';
const iot = location.pathname === '/iot';
document.title = iot ? 'IoT telemetry | Live lab' : 'Office network | Live lab';
document.getElementById('scan-target').textContent = iot ? '127.0.0.3' : '127.0.0.2';
const localTime = value => `${new Intl.DateTimeFormat('en-IN',{timeZone:'Asia/Kolkata',dateStyle:'medium',timeStyle:'medium'}).format(new Date(value))} IST`;
document.getElementById('title').textContent = iot ? 'IoT telemetry lab' : 'Office network lab';
document.getElementById('intro').textContent = iot ? 'Interact with the running MQTT, SNMP and TLS services, then compare their assessment report.' : 'Use real FTP, SMB and SSH connections to understand what the assessment detects.';
document.getElementById(iot ? 'iot-panel' : 'office-panel').hidden = false;
let busy = false;
async function json(url, options) {
  const response = await fetch(url, {cache:'no-store', ...options});
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || 'The lab operation did not complete');
  return value;
}
for (const button of document.querySelectorAll('[data-action]')) {
  button.addEventListener('click', async () => {
    if (busy) return;
    busy = true;
    for (const control of document.querySelectorAll('[data-action]')) control.disabled = true;
    document.getElementById('operation-state').textContent = 'Connecting to the actual lab service…';
    document.getElementById('decision').textContent = '';
    document.getElementById('decision-limit').textContent = '';
    try {
      const result = await json('/api/action', {method:'POST',headers:{'Content-Type':'application/json','X-VulnAssess-Lab':'service-demo'},body:JSON.stringify({action:button.dataset.action})});
      document.getElementById('operation-state').textContent = `${result.destination} · response observed at ${localTime(result.observed_at)}`;
      document.getElementById('response').textContent = JSON.stringify(result.proof,null,2);
      document.getElementById('decision').textContent = result.decision.inconclusive ? 'Inconclusive: this check could not establish the required control.' : result.decision.violations.length ? result.decision.violations.join('. ') : 'No violation of the tested endpoint policy was observed in this operation.';
      document.getElementById('decision-limit').textContent = result.decision.limit;
      document.getElementById('operation-state').scrollIntoView({behavior:'smooth',block:'center'});
    } catch (error) {
      document.getElementById('operation-state').textContent = 'Operation did not complete';
      document.getElementById('response').textContent = error.message;
    } finally {
      busy = false;
      for (const control of document.querySelectorAll('[data-action]')) control.disabled = false;
      refresh();
    }
  });
}
let refreshing = false;
async function refresh() {
  if (refreshing || document.hidden) return;
  refreshing = true;
  try {
    const status = await json('/api/status');
    document.getElementById('sensor-state').textContent = status.sensor_error || `${status.sensor_packets_sent} real MQTT publications sent by the simulated sensor.`;
    const link = status.reports[iot ? 'iot' : 'office'];
    const report = document.getElementById('report-link');
    const download = document.getElementById('download-link');
    report.hidden = download.hidden = !link;
    if (link) { report.href = link; download.href = `${link}/download`; }
    const list = document.getElementById('events'); list.replaceChildren();
    for (const event of status.events.filter(e => iot ? e.destination.startsWith('127.0.0.3:') : e.destination.startsWith('127.0.0.2:')).slice(0,10)) {
      const row = document.createElement('li');
      const title = document.createElement('strong'); title.textContent = event.operation;
      const detail = document.createElement('p'); detail.textContent = `${event.destination} · ${localTime(event.at)}`;
      row.append(title,detail); list.append(row);
    }
    if (iot && !busy) {
      const reading = await json('/api/telemetry');
      document.getElementById('temperature').textContent = `${reading.temperature_c} °C`;
      document.getElementById('humidity').textContent = `${reading.humidity_pct}%`;
      document.getElementById('sequence').textContent = reading.sequence;
      document.getElementById('telemetry-state').textContent = `Broker delivered ${reading.device} · published ${localTime(reading.sent_at)}`;
    }
  } catch (error) {
    document.getElementById(iot ? 'telemetry-state' : 'sensor-state').textContent = error.message;
  } finally { refreshing = false; }
}
refresh(); setInterval(refresh,5000);
