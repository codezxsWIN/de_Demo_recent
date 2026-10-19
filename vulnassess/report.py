"""Offline HTML report. Inline CSS only: no external asset, no script, no network call."""

from html import escape
from typing import Any, Sequence

from vulnassess.schema import ContextProfile, Finding, Rationale, ScoreBreakdown
from vulnassess.score_facts import missing_severity_basis

BANDS = ("Critical", "High", "Medium", "Low")

CSS = """body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1a1a1a;max-width:1200px}
h1{color:#1F4E79;margin-bottom:4px}
h2{color:#1F4E79;border-bottom:2px solid #DCE6F1;padding-bottom:4px;margin-top:32px}
h3{color:#2E74B5;margin-bottom:4px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0 16px}
th{background:#1F4E79;color:#fff;text-align:left;padding:6px}
td{border-bottom:1px solid #ddd;padding:6px;vertical-align:top}
td.n{white-space:nowrap}
tr.Critical{background:#F8D7DA;font-weight:bold}
tr.High{background:#FBE5D6}
tr.Medium{background:#FFF3CD}
tr.Low{background:#E3F1E4}
.ev{font-family:Consolas,monospace;font-size:12px;color:#444;background:#f6f6f6;padding:2px 4px}
.hash{font-family:Consolas,monospace;font-size:11px;overflow-wrap:anywhere}
.muted{color:#666;font-size:12px}
.kpi{display:inline-block;margin:0 24px 8px 0}
.kpi b{font-size:22px;display:block}
footer{margin-top:40px;color:#666;font-size:12px;border-top:1px solid #ddd;padding-top:8px}
@media print{body{margin:12mm}h2{page-break-after:avoid}tr{page-break-inside:avoid}}"""


def _cell(value: Any) -> str:
    return "&mdash;" if value is None or value == "" else escape(str(value))


def _row(cells: Sequence[str], css_class: str = "") -> str:
    attribute = f" class='{escape(css_class)}'" if css_class else ""
    return f"<tr{attribute}>" + "".join(cells) + "</tr>"


def _table(headers: Sequence[str], rows: Sequence[str], css_class: str = "") -> str:
    attribute = f" class='{escape(css_class)}'" if css_class else ""
    head = "".join(f"<th>{escape(header)}</th>" for header in headers)
    return f"<table{attribute}>{_row([head])}{''.join(rows)}</table>"


def _summary(scores: Sequence[ScoreBreakdown], hosts: int) -> str:
    counts = {name: 0 for name in BANDS}
    for item in scores:
        counts[item.band] = counts.get(item.band, 0) + 1
    kpis = "".join(
        f"<div class='kpi'><b>{counts[name]}</b>{name}</div>" for name in BANDS if counts[name]
    )
    kpis += f"<div class='kpi'><b>{len(scores)}</b>findings ranked</div>"
    kpis += f"<div class='kpi'><b>{hosts}</b>hosts</div>"
    return "<h2>1. Summary</h2>" + kpis


def _ranked(
    scores: Sequence[ScoreBreakdown],
    findings: dict[str, Finding],
    profiles: dict[str, ContextProfile],
    rationales: dict[str, Rationale],
) -> str:
    rows = []
    details = []
    for position, item in enumerate(scores, start=1):
        finding = findings.get(item.finding_id)
        title = finding.title if finding else item.finding_id
        tool = finding.tool if finding else ""
        port = finding.port if finding else None
        label = f"{escape(title)}"
        if item.cve_id:
            label += f" &middot; {escape(item.cve_id)}"
        label += f"<br><span class='muted'>{_cell(tool)} &middot; port {_cell(port)}</span>"
        rationale = rationales.get(item.finding_id)
        why = _cell(rationale.text if rationale else item.reason)
        if missing_severity_basis(item):
            why = (
                "<strong>Needs severity review: historical stored priority has no severity basis; "
                "the stored number is not established Low risk.</strong><br>" + why
            )
        if rationale is not None and rationale.source == "llm":
            why += f"<br><span class='muted'>reworded by {escape(str(rationale.model))}</span>"
        rows.append(
            _row(
                [
                    f"<td class='n'>{position}</td>",
                    f"<td class='n'><b>{item.risk}</b></td>",
                    f"<td class='n'>{_cell(item.band)}</td>",
                    f"<td class='n'>{_cell(item.host_ip)}</td>",
                    f"<td>{label}</td>",
                    f"<td>{why}</td>",
                ],
                item.band,
            )
        )
        profile = profiles.get(item.host_ip)
        role = f"{profile.role.value} ({profile.role.confidence:.2f})" if profile else "unknown"
        exposure = profile.exposure.value.replace("_", "-") if profile else ""
        details.append(
            _row(
                [
                    f"<td>{position}</td>",
                    f"<td>{_cell(item.host_ip)}</td>",
                    f"<td>{_cell(role)}</td>",
                    f"<td>{_cell(exposure)}</td>",
                    f"<td>{_cell(item.base_score)}</td>",
                    f"<td>{_cell(item.env_score)}</td>",
                    f"<td>{_cell(_percent(item.epss_percentile))}</td>",
                    f"<td>{'yes' if item.kev else 'no'}</td>",
                    f"<td>{_cell(item.fix)}</td>",
                ]
            )
        )
    body = "<h2>2. Ranked findings</h2><p class='muted'>Ordered by context-aware risk. The same "
    body += "CVE can sit at very different ranks on different hosts; the Why column says what "
    body += "moved it.</p>"
    body += _table(["#", "Risk", "Band", "Host", "Finding", "Why"], rows, "ranked")
    body += "<h3>Score details and recommended fixes</h3>"
    body += _table(
        [
            "#",
            "Host",
            "Role (conf.)",
            "Exposure",
            "CVSS base",
            "CVSS env.",
            "EPSS %ile",
            "KEV",
            "Recommended fix",
        ],
        details,
    )
    return body + _control_applicability(scores, findings)


def _unscored(findings: Sequence[Finding], scores: Sequence[ScoreBreakdown]) -> str:
    scored = {item.finding_id for item in scores}
    missing = [item for item in findings if item.id not in scored]
    if not missing:
        return ""
    return (
        "<h2>Unscored findings — severity review required</h2>"
        "<p>No deterministic priority was recorded for these findings. They are not Low risk "
        "by default and remain part of this assessment.</p><ul>"
        + "".join(
            f"<li>{escape(item.title)} · {_cell(item.host_ip)} · {_cell(item.id)}"
            f"<br>{_cell(item.tool)} · {_cell(item.provenance.raw_path)} · record {_cell(item.provenance.record_index)}"
            f"<br><span class='ev'>{escape(item.evidence)}</span></li>"
            for item in missing
        )
        + "</ul>"
    )


def _control_applicability(scores: Sequence[ScoreBreakdown], findings: dict[str, Finding]) -> str:
    """Render persisted scoring decisions separately from immutable host observations."""
    rows: list[str] = []
    policies: set[str] = set()
    for item in scores:
        decisions = item.inputs.get("control_applicability")
        if not isinstance(decisions, dict):
            continue  # Historical scores are not silently reinterpreted.
        policies.add(str(item.inputs.get("context_policy", "unknown")))
        finding = findings.get(item.finding_id)
        endpoint = f"{item.host_ip}:{finding.port}" if finding else item.host_ip
        for key, decision in sorted(decisions.items()):
            if not isinstance(decision, dict):
                continue
            rows.append(
                _row(
                    [
                        f"<td>{_cell(item.finding_id)}<br>{_cell(endpoint)}</td>",
                        f"<td>{_cell(key)}</td>",
                        f"<td>{_cell(decision.get('status'))}</td>",
                        f"<td>{_cell(decision.get('reason_code'))}</td>",
                        f"<td><span class='ev'>{_cell(decision.get('evidence'))}</span></td>",
                        f"<td>{_cell(decision.get('limitation'))}</td>",
                    ]
                )
            )
    if not rows:
        return ""
    return (
        "<h3>Control applicability by finding</h3>"
        "<p class='muted'>Host observations remain recorded below. Only eligible, "
        "finding-bound control signals can enter the configured Environmental mapping; "
        "a signal is not proof of mitigation. Policy: "
        + _cell(", ".join(sorted(policies)))
        + ".</p>"
        + _table(
            ["Finding / endpoint", "Control", "Decision", "Reason code", "Evidence", "Limitation"],
            rows,
        )
    )


def _percent(value: float | None) -> str | None:
    return None if value is None else str(int(round(value * 100)))


def _context(profiles: Sequence[ContextProfile]) -> str:
    body = "<h2>3. Host context and evidence</h2>"
    for profile in profiles:
        exposure = profile.exposure.value.replace("_", "-")
        body += (
            f"<h3>{escape(profile.host_ip)} &mdash; {escape(str(profile.role.value))} &middot; "
            f"{escape(exposure)} &middot; segment {_cell(profile.segment)}</h3>"
        )
        rows = []
        entries = [("role", profile.role), ("exposure", profile.exposure)]
        entries += [(f"control: {key}", value) for key, value in sorted(profile.controls.items())]
        entries += [(f"manual: {key}", value) for key, value in sorted(profile.manual.items())]
        for name, feature in entries:
            rows.append(
                _row(
                    [
                        f"<td>{escape(name)}</td>",
                        f"<td>{_cell(feature.value)}</td>",
                        f"<td>{feature.confidence:.2f}</td>",
                        f"<td>{escape(feature.source)}</td>",
                        f"<td><span class='ev'>{escape(feature.evidence)}</span></td>",
                    ]
                )
            )
        body += _table(["Feature", "Value", "Confidence", "Source", "Evidence (verbatim)"], rows)
    return body


def _methodology(
    weights: dict, feeds: dict[str, dict[str, Any]], rationales: dict[str, Rationale]
) -> str:
    threat = weights["threat"]
    bands = weights["bands"]
    reworded = sorted(
        {item.model for item in rationales.values() if item.source == "llm" and item.model}
    )
    model_note = (
        "No language model was used: every reason is a deterministic sentence built from the "
        "facts shown above."
        if not reworded
        else (
            f"A local model ({escape(', '.join(str(name) for name in reworded))}) reworded "
            f"{sum(1 for item in rationales.values() if item.source == 'llm')} of "
            f"{len(rationales)} sentences. It never sees or produces a score: it is given the "
            "band and the context words only, any number it writes that is not in those facts "
            "is rejected, and a rejected sentence falls back to the deterministic one."
        )
    )
    text = (
        "Risk = CVSS 3.1 <b>Environmental</b> score (Modified metrics and C/I/A Requirements "
        "auto-filled from the inferred context) &times; 10, multiplied by a threat factor "
        f"{threat['base_multiplier']} + {threat['epss_weight']} &times; EPSS percentile when EPSS "
        "data exists. With no EPSS row the threat component is <i>unscored</i> and the "
        "environmental score alone ranks the finding. A CISA KEV listing forces the threat factor "
        f"to {threat['kev_multiplier']}, adds {threat['kev_boost']}, and &mdash; only when the host "
        f"is internet-facing &mdash; applies a floor of {threat['kev_floor_internet_facing']}. "
        "Findings without a usable CVSS 3.1 vector fall back to the tool's own severity table. "
        "Observed EPSS and KEV facts are retained; the configured KEV boost and exposure floor "
        "still apply, but EPSS does not multiply a native-severity fallback. " + model_note
    )
    body = f"<h2>4. Methodology</h2><p>{text}</p>"
    body += _table(
        ["Band", "Risk threshold"],
        [
            _row([f"<td>{escape(name)}</td>", f"<td>&ge; {bands[name]}</td>"])
            for name in ("Critical", "High", "Medium")
        ]
        + [_row(["<td>Low</td>", "<td>below Medium</td>"])],
    )
    body += _table(
        ["Feed", "Snapshot date", "Records", "SHA-256"],
        [
            _row(
                [
                    f"<td>{escape(name)}</td>",
                    f"<td>{_cell(info.get('file_date'))}</td>",
                    f"<td>{_cell(info.get('rows'))}</td>",
                    f"<td class='ev'>{escape(str(info.get('sha256', ''))[:16])}&hellip;</td>",
                ]
            )
            for name, info in sorted(feeds.items())
        ],
    )
    return body


def _provenance(scores: Sequence[ScoreBreakdown], findings: dict[str, Finding]) -> str:
    rows = []
    for item in scores:
        finding = findings.get(item.finding_id)
        if finding is None:
            continue
        rows.append(
            _row(
                [
                    f"<td>{escape(finding.title)}</td>",
                    f"<td>{escape(finding.tool)}</td>",
                    f"<td class='ev'>{escape(finding.provenance.raw_path)}</td>",
                    f"<td>{finding.provenance.record_index}</td>",
                ]
            )
        )
    return "<h2>5. Provenance</h2>" + _table(["Finding", "Tool", "Raw file", "Record"], rows)


def _bounded(value: Any, limit: int = 2048) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def _audit(audit: dict[str, Any]) -> str:
    body = "<h2>6. Research and audit evidence</h2>"
    body += (
        "<p class='muted'>Each row carries one permitted evidence label. A successful hash "
        "check does not upgrade synthetic, missing, or otherwise unverified input evidence.</p>"
    )
    evidence_rows = [
        _row(
            [
                f"<td>{_cell(item.get('component'))}</td>",
                f"<td class='n'><b>{_cell(item.get('evidence_status'))}</b></td>",
                f"<td class='hash'>{_cell(item.get('artifact_hash'))}</td>",
                f"<td>{escape(_bounded(item.get('summary', '')))}</td>",
                f"<td class='hash'>{escape(_bounded(item.get('path', '')))}</td>",
            ]
        )
        for item in audit.get("rows", [])
    ]
    body += _table(
        ["Component", "Evidence", "Content hash", "Result", "Artifact"],
        evidence_rows,
    )
    limitations = audit.get("limitations", [])
    if limitations:
        body += (
            "<h3>Limitations</h3><ul>"
            + "".join(f"<li>{escape(_bounded(item))}</li>" for item in limitations)
            + "</ul>"
        )

    intelligence = audit.get("intelligence", {})
    trace_rows = [
        _row([f"<td>{escape(str(key))}</td>", f"<td>{escape(str(value))}</td>"])
        for key, value in sorted(intelligence.get("trace_counts", {}).items())
    ]
    body += "<h3>Intelligence matching decisions</h3>"
    body += _table(["Decision and method", "Count"], trace_rows)
    unmatched_rows = [
        _row(
            [
                f"<td class='hash'>{escape(str(item.get('finding_id', '')))}</td>",
                f"<td>{escape(_bounded('; '.join(str(value) for value in item.get('reasons', []))))}</td>",
            ]
        )
        for item in intelligence.get("unmatched", [])
    ]
    if unmatched_rows:
        body += _table(["Unmatched finding", "Recorded reasons"], unmatched_rows)

    unification = audit.get("unification", {})
    group_rows = [
        _row(
            [
                f"<td class='hash'>{escape(str(group.get('id', '')))}</td>",
                f"<td class='hash'>{escape(', '.join(str(value) for value in group.get('source_finding_ids', [])))}</td>",
                f"<td>{_cell(group.get('method'))}</td>",
                f"<td>{_cell(group.get('confidence'))}</td>",
                f"<td>{escape(_bounded(group.get('justification', '')))}</td>",
            ]
        )
        for group in unification.get("groups", [])
    ]
    body += "<h3>Raw-to-group mapping (preview only)</h3>"
    body += _table(
        ["Group ID", "Source finding IDs", "Method", "Confidence", "Justification"],
        group_rows,
    )
    candidate_rows = [
        _row(
            [
                f"<td class='hash'>{escape(str(item.get('left_finding_id', '')))}</td>",
                f"<td class='hash'>{escape(str(item.get('right_finding_id', '')))}</td>",
                f"<td>{_cell(item.get('method'))}</td>",
                f"<td>{_cell(item.get('confidence'))}</td>",
                f"<td>{escape(_bounded(item.get('justification', '')))}</td>",
            ]
        )
        for item in unification.get("candidates", [])
    ]
    if candidate_rows:
        body += "<h3>Correlation candidates requiring review</h3>"
        body += _table(
            ["Left finding", "Right finding", "Method", "Confidence", "Why not merged"],
            candidate_rows,
        )

    model_rows = [
        _row(
            [
                f"<td>{_cell(item.get('host_ip'))}</td>",
                f"<td>{_cell(item.get('rule'))}</td>",
                f"<td>{_cell(item.get('model'))}</td>",
                f"<td>{_cell(item.get('confidence'))}</td>",
                f"<td>{_cell(item.get('margin'))}</td>",
                f"<td>{'yes' if item.get('abstained') else 'no'}</td>",
                f"<td>{_cell(item.get('feature_coverage'))}</td>",
                f"<td>{_cell(', '.join(item.get('out_of_vocabulary', [])))}</td>",
                f"<td>{_cell(item.get('model_hash'))}</td>",
                f"<td>{escape(_bounded(item.get('evidence', '')))}</td>",
            ]
        )
        for item in audit.get("model_cases", [])
    ]
    if model_rows:
        body += "<h3>Shadow-model predictions (not scoring inputs)</h3>"
        body += _table(
            [
                "Host",
                "Rule",
                "Model",
                "Confidence",
                "Margin",
                "Abstained",
                "Feature coverage",
                "Out-of-vocabulary features",
                "Model hash",
                "Evidence",
            ],
            model_rows,
        )

    context_artifact = audit.get("artifacts", {}).get("context", {})
    disagreement_rows = [
        _row(
            [
                f"<td>{_cell(item.get('host_ip'))}</td>",
                f"<td>{_cell(item.get('truth'))}</td>",
                f"<td>{_cell(item.get('rule'))}</td>",
                f"<td>{_cell(item.get('model'))}</td>",
                f"<td>{_cell(item.get('model_confidence'))}</td>",
                f"<td>{escape(_bounded(item.get('rule_evidence', '')))}</td>",
            ]
        )
        for item in context_artifact.get("rule_model_disagreements", [])
    ]
    if disagreement_rows:
        body += "<h3>Context-evaluation disagreements</h3>"
        body += _table(
            ["Host", "Truth", "Rule", "Model", "Model confidence", "Rule evidence"],
            disagreement_rows,
        )

    rescan_artifact = audit.get("artifacts", {}).get("rescan", {})
    rescan_rows = [
        _row(
            [
                f"<td class='hash'>{escape(str(item.get('finding_id', '')))}</td>",
                f"<td>{_cell(item.get('host_ip'))}</td>",
                f"<td>{_cell(item.get('outcome'))}</td>",
                f"<td>{escape(_bounded(item.get('evidence', '')))}</td>",
                f"<td>{'yes' if item.get('evidence_loss') else 'no'}</td>",
            ]
        )
        for item in rescan_artifact.get("outcomes", [])
    ]
    if rescan_rows:
        body += "<h3>Re-scan outcomes requiring human adjudication</h3>"
        body += _table(
            ["Finding", "Host", "Outcome", "Evidence", "Evidence loss"],
            rescan_rows,
        )
    return body


def render(
    run: dict[str, Any],
    scores: Sequence[ScoreBreakdown],
    findings: Sequence[Finding],
    profiles: Sequence[ContextProfile],
    feeds: dict[str, dict[str, Any]],
    weights: dict,
    config_hash: str,
    rationales: dict[str, Rationale] | None = None,
    audit: dict[str, Any] | None = None,
    history: dict[str, Any] | None = None,
) -> str:
    by_id = {finding.id: finding for finding in findings}
    by_host = {profile.host_ip: profile for profile in profiles}
    reworded = rationales or {}
    digest = scores[0].weights_hash if scores else ""
    header = (
        "<h1>AI-Based Network Vulnerability Assessment &mdash; report</h1>"
        f"<div class='muted'>Run {escape(str(run.get('run_id', '')))} &middot; started "
        f"{escape(str(run.get('started_at', '')))} &middot; ranking by inferred context"
        + (
            f" &middot; evidence {escape(str(audit.get('assessment_evidence_status')))}"
            if audit is not None
            else ""
        )
        + "</div>"
    )
    footer = (
        f"<footer>run_id {escape(str(run.get('run_id', '')))} &middot; config hash "
        f"{escape(config_hash)} &middot; weights hash {escape(digest)} &middot; started "
        f"{escape(str(run.get('started_at', '')))}</footer>"
    )
    history_note = ""
    if history is not None:
        history_note = (
            "<h2>Assessment history</h2><p>Recorded intelligence revision: "
            + _cell(history.get("intelligence_revision"))
            + "; hash: "
            + _cell(history.get("intelligence_hash"))
            + "</p>"
            + "".join(f"<p>{escape(str(item))}</p>" for item in history.get("limitations", []))
        )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>Vulnerability report {escape(str(run.get('run_id', '')))}</title>"
        f"<style>{CSS}</style></head><body>"
        + header
        + history_note
        + _summary(scores, len(profiles))
        + _unscored(findings, scores)
        + _ranked(scores, by_id, by_host, reworded)
        + _context(profiles)
        + _methodology(weights, feeds, reworded)
        + _provenance(scores, by_id)
        + (_audit(audit) if audit is not None else "")
        + footer
        + "</body></html>"
    )
