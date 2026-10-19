"""Escaped, server-rendered evidence typography over existing stored records."""

import json
from html import escape
from typing import Any

from vulnassess.ui.drawings import building, door

EVIDENCE_KEYS = frozenset(
    {
        "evidence",
        "banner",
        "raw_path",
        "base_vector",
        "env_vector",
        "cvss31_vector",
        "cvss40_vector",
        "weights_hash",
        "sha256",
        "config_hash",
    }
)


def evidence(text: str, source: str, block: bool = True) -> str:
    tag = "pre" if block else "span"
    return (
        '<div class="quotation">'
        f'<span class="source-label">{escape(source)}</span>'
        f'<{tag} class="evidence">{escape(text)}</{tag}>'
        "</div>"
    )


def evidence_items(value: Any, source: str = "Stored run") -> list[tuple[str, str]]:
    items = []
    if isinstance(value, dict):
        for key, child in value.items():
            label = f"{source} / {key}"
            if key in EVIDENCE_KEYS and isinstance(child, str) and child:
                items.append((child, label))
            else:
                items.extend(evidence_items(child, label))
    elif isinstance(value, list):
        for child in value:
            identity = "record"
            if isinstance(child, dict):
                identity = str(
                    child.get("id")
                    or child.get("host_ip")
                    or child.get("ip")
                    or child.get("finding_id")
                    or child.get("feed")
                    or "record"
                )
            items.extend(evidence_items(child, f"{source} / {identity}"))
    return items


def _claim(feature: dict[str, Any], label: str, source: str) -> str:
    value = str(feature["value"]).replace("_", " ")
    return (
        '<div class="claim">'
        f'<dt>{escape(label)} <span class="source-kind">{escape(str(feature["source"]))}</span></dt>'
        f'<dd class="inferred">{escape(value)}</dd>'
        f"<dd>{evidence(feature['evidence'], source)}</dd>"
        "</div>"
    )


def _host_rows(payload: dict[str, Any]) -> str:
    profiles = {profile["host_ip"]: profile for profile in payload["context"]}
    scores = {score["finding_id"]: score for score in payload["scores"]}
    rows = []
    for host in payload["hosts"]:
        address = host["ip"]
        profile = profiles.get(address)
        silhouette = "" if profile is None else building(str(profile["role"]["value"]))
        doors = "".join(
            door(scores.get(finding["id"], {}).get("band"), finding["id"])
            for finding in payload["findings"]
            if finding["host_ip"] == address
        )
        claims = (
            '<p class="unavailable">No context profile recorded.</p>'
            if profile is None
            else '<dl class="claims">'
            + _claim(profile["role"], "Role", "Context / role evidence")
            + _claim(profile["exposure"], "Exposure", "Context / exposure evidence")
            + "</dl>"
        )
        rows.append(
            '<article class="host-record">'
            f'<div class="host-identity"><div class="host-mark">{silhouette}'
            f"{evidence(address, 'Scanner / host address', block=False)}</div>"
            f'<div class="host-doors" aria-label="Stored finding bands">{doors}</div></div>'
            f"{claims}</article>"
        )
    return "".join(rows) or '<p class="unavailable">No hosts recorded.</p>'


def run_strip(payload: dict[str, Any]) -> str:
    run = payload["run"]
    feeds = "".join(
        "<tr>"
        f'<th scope="row">{escape(feed["feed"].upper())}</th>'
        f"<td>{evidence(feed['file_date'] or 'Not recorded', 'Feed snapshot / date', False)}</td>"
        '<td class="unavailable">Not stored</td></tr>'
        for feed in payload["feeds_meta"]
    )
    scanners = "".join(
        "<li>"
        + evidence(tool, "Finding provenance / scanner", False)
        + '<span class="unavailable">Version not recorded</span></li>'
        for tool in sorted({finding["tool"] for finding in payload["findings"]})
    )
    hashes = "".join(
        evidence(value, "Stored score / weights hash", False)
        for value in payload["config_hashes"]["score_weights"]
    )
    return (
        '<section id="run-strip" class="run-strip" aria-label="Run provenance">'
        '<details class="run-details"><summary><span>Run provenance</span>'
        '<span class="source-label">Run ID</span>'
        f'<span class="evidence">{escape(run["run_id"])}</span>'
        '<span class="source-label">Config hash</span>'
        f'<span class="evidence">{escape(run["config_hash"])}</span></summary>'
        '<div class="run-provenance">'
        + evidence(run["run_id"], "Run / identifier", False)
        + evidence(run["started_at"], "Run / started-at", False)
        + evidence(run["config_hash"], "Run / config hash", False)
        + hashes
        + '<p class="unavailable">Per-file imported-at timestamps are not stored.</p>'
        '<table class="record-table"><caption>Current store feed snapshots; not frozen per run</caption>'
        "<thead><tr><th>Feed</th><th>Snapshot date</th><th>Age in days</th></tr></thead>"
        f"<tbody>{feeds}</tbody></table>"
        f'<ul class="scanner-list">{scanners}</ul>'
        "</div></details></section>"
    )


def pipeline_map(payload: dict[str, Any]) -> str:
    stages = (
        ("import", "Import", payload["run"]["summary"].get("imports", [])),
        ("intel", "Intelligence", payload["feeds_meta"]),
        ("enrich", "Enrich", payload["enrichments"]),
        ("context", "Context", payload["context"]),
        ("rank", "Rank", payload["scores"]),
        ("explain", "Explain", payload["rationales"]),
        ("report", "Report", None),
    )
    links = []
    ledgers = []
    for key, title, records in stages:
        status = "Records present" if records else "No stored output"
        links.append(
            f'<li><a href="#stage-{key}" data-stage-link="{key}">'
            f"<strong>{title}</strong><span>{status}</span></a></li>"
        )
        stored = (
            '<p class="unavailable">No output record persisted for this stage.</p>'
            if not records
            else evidence(
                json.dumps(records, indent=2, ensure_ascii=False), f"Stored {title.lower()} records"
            )
        )
        counters = ""
        if key == "import":
            for record in records or []:
                counters += '<div class="import-counts">'
                counters += evidence(record["target_ip"], "Import summary / target", False)
                counters += (
                    '<span><span class="source-label">Import summary / hosts</span>'
                    '<span class="evidence" data-stored-count="hosts">'
                    f"{escape(str(record['hosts']))}</span></span>"
                )
                for tool, count in sorted(record["findings"].items()):
                    counters += (
                        f'<span><span class="source-label">Import summary / {escape(tool)} findings</span>'
                        '<span class="evidence" '
                        f'data-stored-count="findings.{escape(tool)}">{escape(str(count))}</span></span>'
                    )
                counters += "</div>"
        ledgers.append(
            f'<details id="stage-{key}" class="stage-ledger"><summary>{title} records</summary>'
            f"{counters}{stored}</details>"
        )
    return (
        '<section id="pipeline" aria-labelledby="pipeline-heading">'
        '<div class="section-heading"><h2 id="pipeline-heading">Pipeline record</h2>'
        '<a href="#findings">Open ranked findings</a></div>'
        f'<ol class="pipeline-map">{"".join(links)}</ol>'
        '<p class="unavailable pipeline-note">Stage totals and completion events are not stored. '
        "Import counters below are the recorded per-target values, not totals.</p>"
        f'<div class="stage-ledgers">{"".join(ledgers)}</div></section>'
    )


def render_entry(
    template: str,
    payload: dict[str, Any] | None,
    runs: list[dict[str, Any]],
    configuration: dict[str, Any] | None = None,
) -> str:
    from vulnassess.ui.presentation import render_workbench

    return render_workbench(template, payload, runs, configuration or {})
