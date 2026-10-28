"""Read-only comparison of observed versions and discovered candidate CVEs."""

from vulnassess.cve_comparison import compare
from vulnassess.cve_discovery import candidate_facts
from vulnassess.schema import Service
from vulnassess.ui.environment import text


def comparison(records):
    return compare(records.get("127.0.0.4"), records.get("127.0.0.5"))


def _priority(side):
    if side is None:
        return "No candidate recorded"
    return (
        f"{text(side['priority'])} / 100"
        if side["priority"] is not None
        else "Candidate · unscored"
    )


def _comparison_table(rows):
    body = '<div class="scroll"><table><caption>Recorded priorities and a frozen-range check against the reference version</caption><thead><tr><th scope="col">Candidate / endpoint</th><th scope="col">Affected-version reference</th><th scope="col">Reference patch</th><th scope="col">Evidence-derived interpretation</th></tr></thead><tbody>'
    for row in rows:
        label = {
            "left_only": "Only in the left capture",
            "shared": "Recorded on both versions",
            "right_only": "Only in the right capture",
        }[row["change"]]
        match = row["reference_matches_left_retained_range"]
        if match is False:
            explanation = f"The left capture's retained NVD range excludes reference version {row['reference_version']}. Package backports and exploitability still require separate verification."
        elif match is True:
            explanation = f"Reference version {row['reference_version']} still matches the left capture's retained NVD range. A historical patch does not address every later CVE."
        else:
            explanation = "No comparable frozen-range check is available. Review endpoint coverage and the individual source records."
        body += f'<tr><th scope="row">{text(row["cve_id"])}<br><small>{text(row["protocol"])}/{row["port"]} · {text(row["product"])}</small></th><td>{_priority(row["left"])}</td><td>{_priority(row["right"])}</td><td><strong>{text(label)}</strong><br>{text(explanation)}</td></tr>'
    return body + "</tbody></table></div>"


def _comparison_section(result):
    body = '<section aria-label="Candidate inventory changes"><h2>What changed between the two versions?</h2>'
    if result["status"] == "unavailable":
        return (
            body + "<p>Two verified captures are required. No improvement is claimed.</p></section>"
        )
    counts = result["counts"]
    body += f"<p><strong>{counts['left_only']} only on the affected-version reference</strong> · <strong>{counts['shared']} on both</strong> · <strong>{counts['right_only']} only on the reference patch</strong></p>"
    body += "<p>The table compares saved candidate associations. It does not measure a completed fix on the same machine.</p>"
    for label, source in zip(
        ("Affected-version report", "Reference-patch report"), result["sources"]
    ):
        body += f'<a href="/captures/{text(source["capture_id"])}/report" target="_blank" rel="noopener">{label} ↗</a> · '
    retained = [
        row for row in result["rows"] if row["right"] and row["right"]["priority"] is not None
    ]
    if retained:
        highest = max(retained, key=lambda row: row["right"]["priority"])
        body += f"<p><strong>Still requires attention:</strong> {text(highest['cve_id'])} · recorded reference priority {_priority(highest['right'])}. Verify applicability and a maintained vendor release; the historical reference patch is not a complete security upgrade.</p>"
    if result["status"] == "limited":
        body += f'<p class="notice">Comparison has qualifications: {text(result["limits"][0])}. The frozen-range check below uses the retained left-hand evidence.</p>'
    changed = [row for row in result["rows"] if row["change"] != "shared"]
    body += (
        _comparison_table(changed)
        if changed
        else "<p>No difference in recorded candidate associations.</p>"
    )
    if counts["shared"]:
        body += f"<details><summary>{counts['shared']} candidates recorded on both versions · inspect retained risks</summary>"
        body += (
            _comparison_table([row for row in result["rows"] if row["change"] == "shared"])
            + "</details>"
        )
    body += "<details><summary>Comparison limits and source receipts</summary><ul>"
    body += "".join(f"<li>{text(limit)}</li>" for limit in result["limits"])
    body += "</ul>"
    for source in result["sources"]:
        body += f"<p><strong>{text(source['capture_id'])}</strong> · {text(source['target'])} · {text(source['captured_at'])}<br>AI: {text(source['ai_status'])} · {text(source['analysis_mode'])}<br>Snapshot: <code>{text(source['snapshot_hash'])}</code></p>"
    return (
        body
        + '</details><p><a href="/cve-lab/comparison.json" download="VulnAssess-CVE-comparison.json">Download comparison evidence · JSON</a></p></section>'
    )


def render(records):
    reference = "CVE-2023-36824"
    body = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Service CVE validation · VulnAssess</title><link rel="stylesheet" href="/static/environment.css"></head><body class="lab-comparison">'
        '<header><a href="/">VulnAssess</a><nav><a href="/network-labs">Office &amp; IoT labs</a><a href="/workflow">Workflow</a></nav></header><main>'
        "<h1>Service version comparison</h1><p>Compare two isolated Redis releases using saved service observations, CVE applicability ranges and recorded priorities.</p>"
    )
    body += (
        _comparison_section(comparison(records))
        + "<details><summary>Lab method and limitations</summary><p>Two real Redis releases, checked using read-only INFO server. Detection receives the observed version, not a list of expected CVEs.</p>"
        "<p>The reference test is CVE-2023-36824: upstream Redis identifies 7.0.12 as its fix. This historical reference patch is not a current secure release. Candidate matching does not prove exploitation or exclude vendor backports. The lab ACL disables COMMAND, scripting, key access and writes.</p>"
        '<p><a href="https://github.com/redis/redis/security/advisories/GHSA-4cfx-h9gq-xpx3" rel="noopener" target="_blank">Reference vendor advisory ↗</a></p></details>'
        + '<details><summary>Individual service captures and full reports</summary><div class="lab-grid">'
    )
    for ip, label in (
        ("127.0.0.4", "Affected-version reference"),
        ("127.0.0.5", "Reference patch comparison"),
    ):
        body += f"<article><h2>{text(label)}</h2><p><strong>Assessment target: {ip}</strong> · TCP/6379</p>"
        record = records.get(ip)
        if not record:
            body += "<p>No verified saved assessment. No CVE result is claimed.</p></article>"
            continue
        payload = record["payload"]
        services = [
            service
            for host in payload.get("hosts", [])
            if host["ip"] == ip
            for service in host["services"]
            if service["port"] == 6379 and service["protocol"] == "tcp"
        ]
        version = services[0].get("version") if len(services) == 1 else None
        candidates = [
            finding
            for finding in payload.get("findings", [])
            if finding.get("host_ip") == ip
            and len(services) == 1
            and candidate_facts(finding, Service.from_json(services[0]))
        ]
        cves = {cve for finding in candidates for cve in finding["cve_ids"]}
        scores = {}
        for finding in candidates:
            matches = [
                score
                for score in payload.get("scores", [])
                if score.get("finding_id") == finding["id"]
                and score.get("host_ip") == ip
                and score.get("cve_id") == finding["cve_ids"][0]
            ]
            scores[finding["id"]] = matches[0] if len(matches) == 1 else None
        body += f"<p><strong>Observed version:</strong> {text(version)}<br><strong>Scan:</strong> {text(record['result']['scan_status'])} · <strong>AI:</strong> {text(record['result']['ai_status'])}<br><strong>Collected:</strong> {text(record['captured_at'])}</p>"
        if record.get("analysis_source"):
            body += "<p>AI used retained scan evidence; this is not a new scan or intelligence refresh.</p>"
        body += f"<p><strong>{reference}:</strong> {'candidate association recorded' if reference in cves else 'no candidate association recorded in this capture'}</p>"
        body += f"<p>{len(candidates)} conditional CVE candidates · {len(payload.get('enrichments', []))} intelligence associations</p><ul>"
        for finding in sorted(
            candidates, key=lambda row: -((scores.get(row["id"]) or {}).get("risk") or 0)
        ):
            score = scores.get(finding["id"])
            body += f"<li><strong>{text(finding['cve_ids'][0])}</strong> · {text(score['risk'] if score else 'unscored')} / 100 · conditional priority</li>"
        identity = text(record["capture_id"])
        body += f'</ul><p><a href="/captures/{identity}/report" target="_blank" rel="noopener">Open full report ↗</a> · <a href="/captures/{identity}/report/download" download>Download report</a> · <a href="/captures/{identity}" target="_blank" rel="noopener">Raw evidence ↗</a></p></article>'
    body += "</div></details><p>Reading this page performs no scan, intelligence refresh or AI request. Raw publisher responses, rejected applicability branches and discovery limits are retained in each capture’s cve-discovery.json.</p></main></body></html>"
    return body
