"""Environment inventory from one verified capture, without inferred network links."""

from html import escape


def text(value):
    return escape(str(value if value is not None else "Not established"), quote=True)


def render(record):
    payload = record["payload"]
    result = record["result"]
    identity = text(record["capture_id"])
    findings = payload.get("findings", [])
    hosts = payload.get("hosts", [])
    services = sum(len(host.get("services", [])) for host in hosts)
    body = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Environment overview · VulnAssess</title>"
        '<link rel="stylesheet" href="/static/environment.css"></head><body>'
        '<header><a href="/">VulnAssess</a><nav><a href="/workflow">Workflow</a>'
        '<a href="/captures">Choose another assessment</a></nav></header><main>'
        "<h1>Environment overview</h1><p>Observed hosts, services and assessment coverage. "
        "This view reads saved evidence; it does not scan the network.</p>"
        f"<p><strong>Target:</strong> {text(result.get('target'))} · "
        f"<strong>Capture:</strong> {identity} · <strong>Collected:</strong> "
        f"{text(record.get('captured_at'))}</p>"
        f"<p><strong>{len(hosts)} observed hosts · {services} service records · "
        f"{len(findings)} recorded findings</strong></p>"
        '<p class="notice">An observed host is not a complete network inventory. '
        "Service records do not prove host-to-host connectivity, firewall rules, "
        "segmentation or attack paths. No such connections are invented here.</p>"
        "<section><h2>Assessment environments</h2><ul>"
        "<li><strong>Website:</strong> HTTP/TLS services and bounded web checks; "
        "not a view of the organisation’s internal network.</li>"
        "<li><strong>Host / OS:</strong> existing Windows self-defence checks read firewall, "
        "antivirus, remote access, encryption, updates and listeners on the computer "
        "running VulnAssess. Remote Linux/Windows authenticated audits are not implemented.</li>"
        "<li><strong>Service lab:</strong> HarborDesk HTTP, FTP, TLS and management fixtures "
        "run on one loopback host; they are not separate network machines.</li>"
        "<li><strong>Protocol environments:</strong> SMTP mail, Memcached-text cache and "
        "Modbus TCP telemetry are custom local training services at 127.0.0.1:8800. "
        "Their receipt records actual socket request/response bytes, not packet captures "
        "or vendor CVEs. Availability must be checked locally.</li>"
        "<li><strong>Multi-host network:</strong> requires an isolated VM/container network "
        "with independently assessed hosts. A single website scan does not establish it.</li>"
        "</ul></section><section><h2>Observed hosts and services</h2>"
    )
    for host in hosts:
        ip = host.get("ip")
        related = [item for item in findings if item.get("host_ip") == ip]
        body += (
            f"<article><h3>{text(ip)} · {text(host.get('hostname'))}</h3>"
            f"<p>OS fingerprint / guess: <strong>{text(host.get('os_guess'))}</strong>. "
            "A remote fingerprint is not authenticated OS or patch verification.</p>"
            '<div class="scroll"><table><caption>Scanner → host → observed endpoint '
            "(observation relationship, not network topology)</caption>"
            "<thead><tr><th>Endpoint</th><th>Service fingerprint</th>"
            "<th>Finding records</th></tr></thead><tbody>"
        )
        for service in host.get("services", []):
            port, protocol = service.get("port"), service.get("protocol")
            linked = [
                item
                for item in related
                if item.get("port") == port and item.get("protocol") == protocol
            ]
            fingerprint = " · ".join(
                str(service[key])
                for key in ("name", "product", "version", "banner")
                if service.get(key)
            )
            body += (
                f"<tr><td>{text(port)}/{text(protocol)}</td>"
                f"<td>{text(fingerprint or None)}</td><td>{len(linked)}</td></tr>"
            )
        body += "</tbody></table></div><details><summary>Host findings and affected endpoints</summary><ul>"
        for finding in related:
            index = findings.index(finding) + 1
            body += (
                f'<li><a href="/captures/{identity}/report#finding-{index}">'
                f"{text(finding.get('title'))}</a> · {text(finding.get('port'))}/"
                f"{text(finding.get('protocol'))}</li>"
            )
        body += "</ul></details></article>"
    body += "</section><section><h2>Coverage and device evidence</h2>"
    for tool, coverage in payload.get("scanner_coverage", {}).items():
        body += f"<p><strong>{text(tool)}:</strong> {text(coverage)}</p>"
    for gap in result.get("assessment_summary", {}).get("coverage_gaps", []):
        body += f"<p>{text(gap)}</p>"
    device = payload.get("self_defence") or result.get("self_defence")
    if device:
        body += "<h3>Recorded device protection checks</h3><ul>"
        for check in device.get("checks", []):
            body += f"<li>{text(check.get('title'))}: {text(check.get('observation'))}</li>"
        body += "</ul>"
    else:
        body += "<p>No authenticated local device checks were retained in this capture.</p>"
    body += (
        f'</section><p><a href="/captures/{identity}/report">Full assessment report</a> · '
        f'<a href="/captures/{identity}">Original evidence</a></p></main></body></html>'
    )
    return body
