"""A simple side-by-side view of the two network labs and their verified captures."""

import json

from vulnassess import capture_history
from vulnassess.errors import ConfigError
from vulnassess.network_policy_facts import observation
from vulnassess.ui import vulnerability_findings
from vulnassess.ui.environment import text

LABS = {
    "office": {
        "ip": "127.0.0.2",
        "title": "Office network",
        "private_ip": "172.30.41.2",
        "purpose": "Test logins, shared-file access and mandatory SMB signing.",
        "ports": "FTP 2121/2122 · SSH 2222/2223 · SMB 1445/1446",
    },
    "iot": {
        "ip": "127.0.0.3",
        "title": "IoT network",
        "private_ip": "172.30.42.2",
        "purpose": "Test broker access, device-management reads and TLS certificate expiry.",
        "ports": "MQTT 1883/1884 · TLS 8883 · SNMP 1161/1162 UDP",
    },
}


def latest_records(root, targets=None):
    targets = set(targets) if targets is not None else {lab["ip"] for lab in LABS.values()}
    selected = {}
    for page in range(1, 6):
        listing = capture_history.listing(root, page)
        for row in listing["captures"]:
            ip = row.get("target")
            if ip not in targets or ip in selected:
                continue
            try:
                record = capture_history.load(root, row["capture_id"])
            except (ConfigError, OSError):
                continue
            if any(host.get("ip") == ip for host in record["payload"].get("hosts", [])):
                selected[ip] = record
        if len(selected) == len(targets) or page * listing["page_size"] >= listing["total"]:
            break
    return selected


def render(records, deployment=None, remediation=None, remediation_error=None):
    body = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Network labs side by side · VulnAssess</title>"
        '<link rel="stylesheet" href="/static/environment.css"></head>'
        '<body class="lab-comparison"><header><a href="/">VulnAssess</a>'
        '<nav><a href="/workflow">Assessment workflow</a><a href="/environment">Environment evidence</a>'
        '<a href="/network-labs">Refresh view</a></nav></header><main>'
        '<p><a href="/cve-lab">Open affected-versus-reference-patch CVE validation →</a></p>'
        "<h1>Two network labs, side by side</h1>"
        "<p>Read each column from the scanner through its gateway to the service container, "
        "then compare the checks and findings below.</p>"
    )
    body += '<section aria-label="Open the running environments"><div class="lab-grid">'
    for name, lab in LABS.items():
        body += (
            f'<article class="lab-card"><h2><a href="http://127.0.0.1:8798/{name}" target="_blank" rel="noopener">Open {text(lab["title"])} environment ↗</a></h2>'
            f"<p>{text(lab['purpose'])}</p><p><strong>Scan target: {text(lab['ip'])}</strong><br>{text(lab['ports'])}</p>"
            "<p>Interact with the service controls and read their actual protocol responses. Assessment reports are separate saved results.</p></article>"
        )
    body += "</div></section>"
    if deployment:
        body += f'<p class="notice">Deployment verification passed at {text(deployment["verified_at"])}. '
        body += "Own-segment protocol exchanges succeeded; the two tested cross-segment TCP paths did not connect. This timestamped receipt is not live status.</p>"
    else:
        body += '<p class="notice">No verified container-deployment receipt is available. Saved scan results below remain separate.</p>'
    body += (
        '<section aria-label="Network topology"><h2>Network topology</h2>'
        '<div class="lab-topology"><p class="lab-origin">This PC · scanner and service console</p>'
        '<div class="lab-grid"><div class="lab-path">↓ TCP · 127.0.0.2<br><strong>Office gateway</strong>'
        "<br>↓ Fixed service ports<br>172.30.41.2 · internal Office segment</div>"
        '<div class="lab-path">↓ TCP + UDP · 127.0.0.3<br><strong>IoT gateway</strong>'
        "<br>↓ Fixed service ports<br>172.30.42.2 · internal IoT segment</div></div></div>"
        '<p class="muted">Declared wiring. The dated deployment receipt above records the two tested '
        "cross-segment connections; this diagram does not establish additional routes or live availability.</p></section>"
    )
    if remediation:
        body += (
            '<section id="remediation"><h2>Same-endpoint remediation experiment</h2>'
            f"<p>Verified {text(remediation['verified_at'])} · receipt {text(remediation['filename'])}</p>"
            "<p>The same endpoint and owner policy were checked before, after a real configuration "
            "change, and after restoring the training baseline. These are dated protocol checks, not a new full assessment.</p>"
            '<div class="scroll"><table><thead><tr><th>Endpoint</th><th>Before</th><th>After change</th>'
            "<th>Restored for training</th></tr></thead><tbody>"
        )
        for name, label in (("office", "FTP · 127.0.0.2:2121"), ("iot", "MQTT · 127.0.0.3:1883")):
            body += f"<tr><th>{text(label)}</th>"
            for stage in ("before", "after", "restored"):
                row = remediation["stages"][stage][name]
                outcome = (
                    "Anonymous access accepted · policy violation"
                    if row["violations"]
                    else "Anonymous access explicitly refused"
                )
                body += f"<td>{text(outcome)}<details><summary>Raw protocol proof</summary><pre>{text(json.dumps(row['proof'], indent=2))}</pre></details></td>"
            body += "</tr>"
        body += (
            "</tbody></table></div><p>Named-user FTP login also succeeded after the change. "
            "MQTT was temporarily closed to all clients: this is containment, not a completed authenticated broker deployment.</p>"
            "<p><strong>Remaining risks:</strong> this experiment does not remediate SMB signing or share access, "
            "SSH credentials, SNMP community access, or TLS expiry. The intentionally insecure baseline was restored.</p></section>"
        )
    elif remediation_error:
        body += '<p class="notice">The latest remediation experiment could not be verified. No successful fix is claimed.</p>'
    else:
        body += '<p class="notice">No verified same-endpoint remediation experiment is available yet. Protected comparison ports below are separate endpoints.</p>'
    body += '<div class="lab-grid">'
    for name, lab in LABS.items():
        body += (
            f'<article class="lab-card"><h2>{text(lab["title"])}</h2><p>{text(lab["purpose"])}</p>'
        )
        body += f'<p><a href="http://127.0.0.1:8798/{name}" target="_blank" rel="noopener">Open interactive {text(name)} lab site ↗</a></p><h3>Declared connection path</h3>'
        body += '<ol class="lab-path">'
        for step in (
            f"Windows scanner → {lab['ip']}",
            "Fixed-port gateway · IP forwarding disabled",
            f"Internal service container → {lab['private_ip']}",
        ):
            body += f"<li>{text(step)}</li>"
        body += f"</ol><p><strong>Declared service ports:</strong> {text(lab['ports'])}</p>"
        record = records.get(lab["ip"])
        if record is None:
            body += "<p>No verified saved assessment for this lab. Enter its IP in the assessment workflow to run it.</p></article>"
            continue
        payload = record["payload"]
        view = vulnerability_findings.build(record)
        body += f"<p><strong>Saved scan: {text(view['collection_status'])} · AI: {text(view['ai_status'])} · {len(view['findings'])} findings</strong><br>Collected {text(record['captured_at'])}</p>"
        profile = next(
            (row for row in payload.get("context", []) if row.get("host_ip") == lab["ip"]), {}
        )
        role = profile.get("role", {}).get("value")
        exposure = profile.get("exposure", {}).get("value")
        environment = profile.get("manual", {}).get("environment", {}).get("value")
        body += f"<p><strong>Recorded context:</strong> {text(role)} · {text(exposure)} · {text(environment)}</p>"
        source = {row["id"]: row for row in payload.get("findings", [])}
        body += '<h3>What the checks established</h3><ul class="lab-findings">'
        for finding in view["findings"]:
            fact = observation(source[finding["id"]])
            statement = fact["statement"] if fact else finding["title"]
            body += f"<li><strong>{text(statement)}</strong><br><span>Port {text(finding['port'])} · triage {text(finding['priority'])} / 100</span>"
            if fact:
                body += f"<details><summary>Proof limits and next step</summary><p>{text(fact['limit'])}</p>"
                for action in finding["guidance"]["patch"]:
                    body += f"<p>{text(action)}</p>"
                body += "</details>"
            body += "</li>"
        body += '</ul><p class="muted">Triage values use a local policy hypothesis, not CVSS or exploit probability.</p>'
        if view["ai_status"] == "validated":
            summary = next(
                (
                    claim["text"]
                    for row in view["findings"]
                    for claim in row["ai"]
                    if claim["path"] == "summary"
                ),
                None,
            )
            if summary:
                body += f"<h3>AI interpretation · highest-priority observation</h3><p>{text(summary)}</p>"
        body += f'<p><a href="{text(view["report_url"])}" target="_blank" rel="noopener">Open full report ↗</a> · <a href="{text(view["report_url"])}/download" download>Download HTML report</a> · <a href="{text(view["evidence_url"])}" target="_blank" rel="noopener">Open raw evidence ↗</a></p></article>'
    body += (
        "</div><p>To repeat an assessment, open the workflow and enter the IP shown at the top of its column. "
        "This comparison page only reads saved evidence.</p>"
        "<p>These are real protocol services with fictional data. Containers use separate network namespaces "
        "and share the Docker/WSL Linux kernel.</p></main></body></html>"
    )
    return body
