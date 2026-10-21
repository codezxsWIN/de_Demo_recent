"""Escaped, read-only history pages. No script and no network-backed enrichment."""

import json
from html import escape
from typing import Any

from vulnassess.score_facts import missing_severity_basis


def page(title, content):
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<link rel="icon" href="data:,">'
        f"<title>{escape(title)} / VulnAssess</title>"
        '<link rel="stylesheet" href="/static/tokens.css">'
        '<link rel="stylesheet" href="/static/capture-review.css"></head><body>'
        '<a class="skip" href="#review">Skip to review</a><header><nav aria-label="Assessment navigation">'
        '<a href="/">Project home</a> '
        '<a href="/workflow">VulnAssess workflow</a> <a href="/captures">Saved assessments</a>'
        f'</nav></header><main id="review" tabindex="-1"><h1>{escape(title)}</h1>{content}</main></body></html>'
    )


def _details(title, value):
    return f"<details><summary>{escape(title)}</summary><pre>{escape(json.dumps(value, indent=2, ensure_ascii=False))}</pre></details>"


def _ai_label(status):
    # An interrupted request may have reached the provider without saving a result.
    return (
        "No completed analysis recorded"
        if status == "not_attempted"
        else str(status).replace("_", " ")
    )


def index(payload):
    rows = []
    for item in payload["captures"]:
        identity = escape(item["capture_id"], quote=True)
        status = (
            "Needs review — record unreadable"
            if item["status"] == "needs_review"
            else "Legacy evidence — no review checkpoint"
            if item["status"] == "legacy"
            else _ai_label(item.get("ai_status"))
        )
        if item.get("scan_status") == "partial":
            status = f"Partial scan · AI: {status}"
        rows.append(
            f'<li><h2><a href="/captures/{identity}">{escape(str(item.get("target") or item["capture_id"]))}</a></h2>'
            f"<p>{escape(status)} · {escape(str(item.get('captured_at') or 'Date unavailable'))}</p>"
            f'<p class="muted">{identity}</p></li>'
        )
    navigation = ""
    if payload["page"] > 1:
        navigation += f'<a href="/captures?page={payload["page"] - 1}">Previous page</a> '
    if payload["page"] * payload["page_size"] < payload["total"]:
        navigation += f'<a href="/captures?page={payload["page"] + 1}">Next page</a>'
    return page(
        "Saved assessments",
        "<p>Read-only local history. Opening a record does not scan, refresh intelligence or contact a model. Raw evidence hashes are checked when you open it.</p>"
        '<p class="muted">Records are ordered by capture ID, not collection time. Legacy evidence without a review checkpoint is available for inspection, not retroactively certified. Missing dates stay unknown.</p>'
        + (
            '<ul class="history">' + "".join(rows) + "</ul>"
            if rows
            else '<p role="status">No saved review checkpoints yet.</p>'
        )
        + f'<nav aria-label="History pages">{navigation}</nav>',
    )


def _legacy_review(record: dict[str, Any]) -> str:
    """Inspect hash-consistent older files without inventing a review receipt."""
    payload = record["payload"]
    captured = record["captured_at"]
    content = (
        '<p class="notice">Legacy evidence — no review checkpoint. Historical, read-only files; '
        "no new scan, intelligence retrieval, model call or approval restoration.</p>"
        "<h2>Review status is unknown</h2><ul>"
        + (
            f"<li>Collection time declared in manifest: {escape(captured)}</li>"
            if captured
            else "<li>Collection time unknown — not recorded; filesystem dates are not collection evidence.</li>"
        )
        + "<li>Collection status unknown — no review checkpoint.</li>"
        "<li>AI status unknown — no validated analysis receipt.</li>"
        "<li>Configuration receipt not recorded; current settings were not substituted.</li>"
        "<li>Intelligence receipt not recorded; retained feed facts are historical, not refreshed.</li>"
        "</ul><h2>Retained evidence</h2><dl>"
    )
    for label, key in (
        ("Hosts", "hosts"),
        ("Findings", "findings"),
        ("Stored priority values", "scores"),
    ):
        count = str(len(payload[key])) if key in payload else "Not recorded"
        content += f"<dt>{label}</dt><dd>{count}</dd>"
    content += "</dl><h2>Retained findings</h2><ul>"
    for finding in payload.get("findings", []):
        content += "<li>" + escape(str(finding.get("title") or finding["id"])) + "</li>"
    content += "</ul><h2>Retained priorities — not revalidated</h2>"
    content += "<p>These are stored values, not newly verified priorities or a complete assessment. Their original context, severity basis and policy may be incomplete.</p><ul>"
    findings = {item["id"]: item for item in payload.get("findings", [])}
    for score in payload.get("scores", []):
        finding = findings[score["finding_id"]]
        content += (
            "<li>"
            + escape(
                f"{score.get('band', 'Band not recorded')} · {score.get('risk', 'Value not recorded')} / 100 — {finding.get('title', score['finding_id'])}"
            )
            + "</li>"
        )
    content += "</ul>"
    for title, key in (
        ("Services as retained", "hosts"),
        ("Findings and provenance as retained", "findings"),
        ("Context as retained", "context"),
        ("Priority inputs as retained — not revalidated", "scores"),
        ("Vulnerability intelligence as retained", "enrichments"),
        ("Publisher metadata as retained", "feeds_meta"),
        ("Scanner coverage declarations as retained", "scanner_coverage"),
    ):
        content += (
            _details(title, payload[key])
            if key in payload
            else f"<p>{escape(title)}: not recorded.</p>"
        )
    content += "<h2>Local file consistency</h2><p>Checks against this manifest passed: local consistency only, not independent authenticity, collection time, target safety or validation of the stored conclusions.</p>"
    content += _details("Manifest file hashes", record["file_hashes"])
    content += f'<p class="hash">Capture ID: {escape(record["capture_id"])}</p>'
    return page(record["target"], content)


def review(record):
    result, payload = record["result"], record["payload"]
    summary = result.get("assessment_summary", {})
    ai_status = result.get("ai_status", "not_attempted")
    times = [
        (
            "Collection retained"
            if result.get("scan_status") == "partial"
            else "Collection completed",
            record["captured_at"] or "Capture time not recorded",
        ),
        ("Intelligence recorded with capture", record["intelligence_recorded_at"]),
        ("AI analysis attempted", record["analysis_attempted_at"] or "Not recorded"),
    ]
    content = '<p class="notice">Historical, read-only assessment. No new scan, intelligence fetch or AI call. Saved approvals are never restored.</p>'
    identity = escape(record["capture_id"], quote=True)
    content += (
        f'<p><a href="/captures/{identity}/report">Open readable assessment report</a> · '
        f'<a href="/captures/{identity}/report/download" download="VulnAssess-{identity}.html">'
        "Download self-contained report</a> · Print or save PDF from your browser.</p>"
    )
    content += (
        "<dl>"
        + "".join(
            f"<dt>{escape(label)}</dt><dd>{escape(str(value))}</dd>" for label, value in times
        )
        + "</dl>"
    )
    content += f"<h2>{'Recorded AI assessment' if ai_status == 'validated' else 'Evidence-only assessment'}</h2>"
    if result.get("scan_status") == "partial":
        content += '<p role="status">Partial scan — requested checks failed. Retained evidence remains available; coverage is incomplete.</p>'
    content += f"<p>AI status: {escape(_ai_label(ai_status))}</p><p>{escape(str(summary.get('conclusion', 'No conclusion recorded')))}</p>"
    content += f"<p>{len(payload.get('hosts', []))} hosts · {len(payload.get('findings', []))} findings · {len(payload.get('scores', []))} recorded priorities</p>"
    scored_ids = {item.get("finding_id") for item in payload.get("scores", [])}
    unscored = [item for item in payload.get("findings", []) if item.get("id") not in scored_ids]
    if unscored:
        content += (
            "<h2>Unscored findings — severity review required</h2>"
            "<p>No deterministic priority was recorded; these findings are not Low risk by default.</p><ul>"
            + "".join(
                f"<li>{escape(str(item.get('title') or item.get('id')))}</li>" for item in unscored
            )
            + "</ul>"
        )
    if summary.get("validated_ai_summary"):
        content += f"<p>{escape(str(summary['validated_ai_summary']))}</p>"
    context = summary.get("context", {})
    content += (
        "<h2>Context at collection</h2><p>"
        + escape(
            f"Role: {context.get('role', 'unknown')} · Exposure: {context.get('exposure', 'unknown')}"
        )
        + '</p><p class="muted">Recorded context guides priority; unknown controls are not assumed to be protective.</p>'
    )
    if payload.get("scores"):
        findings = {item["id"]: item for item in payload.get("findings", [])}
        content += "<h2>Recorded priorities</h2><ul>"
        for score in payload["scores"]:
            finding = findings.get(score.get("finding_id"), {})
            content += (
                "<li>"
                + escape(
                    f"{score.get('band')} · {score.get('risk')} / 100 — {finding.get('title', score.get('finding_id'))}"
                )
                + (
                    " — Needs severity review: this historical stored number has no severity basis; not established Low risk."
                    if missing_severity_basis(score)
                    else ""
                )
                + "</li>"
            )
        content += "</ul>"
    content += (
        "<h2>Coverage and unknowns</h2><ul>"
        + "".join(f"<li>{escape(str(gap))}</li>" for gap in summary.get("coverage_gaps", []))
        + "</ul>"
    )
    for title, value in (
        ("Scanner coverage", payload.get("scanner_coverage", {})),
        ("Context and supporting evidence", payload.get("context", [])),
        ("Findings and provenance", payload.get("findings", [])),
        ("Deterministic priorities", payload.get("scores", [])),
        (
            "Recorded intelligence and publisher dates",
            {"feeds": payload.get("feeds_meta", {}), "enrichments": payload.get("enrichments", [])},
        ),
        ("Services observed", payload.get("hosts", [])),
        ("AI actions, uncertainty and citations", result.get("analyst")),
        ("AI provider attempts", result.get("ai_attempts", [])),
    ):
        content += _details(title, value)
    if "self_defence" in payload:
        content += _details("Self-defence observations and precautions", payload["self_defence"])
    content += (
        "<h2>Integrity and provenance</h2><dl>"
        + "".join(
            f'<dt>{escape(key.replace("_", " "))}</dt><dd class="hash">{escape(str(record[key]))}</dd>'
            for key in (
                "capture_id",
                "configuration_hash",
                "evidence_hash",
                "intelligence_hash",
                "snapshot_hash",
            )
        )
        + "</dl>"
    )
    content += '<p class="muted">Hashes detect accidental changes, not an attacker who can replace both the records and their hashes. These are recorded observations, not a guarantee of current safety.</p>'
    return page(str(result.get("target", record["capture_id"])), content)
