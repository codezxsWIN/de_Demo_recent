"""Self-contained visual replay of the local vulnerability-assessment pipeline."""

import json
from html import escape
from typing import Any

from vulnassess.role_model import RoleModel
from vulnassess.scoring import best_enrichment
from vulnassess.store import Store
from vulnassess.visual_template import HTML_TEMPLATE

STAGES = (
    ("scope", "Scope fence", "Targets are checked before any scanner artifact is opened."),
    ("ingest", "Scanner ingest", "Nmap, ZAP and Nikto records become canonical findings."),
    ("intel", "Offline intel", "Local NVD, EPSS and KEV snapshots enrich matching CVEs."),
    ("model", "Role model", "The learned classifier activates scan-derived features."),
    ("context", "Context profile", "Role, exposure and controls retain confidence and evidence."),
    (
        "environment",
        "CVSS environment",
        "Context modifies the Environmental vector deterministically.",
    ),
    (
        "threat",
        "Threat overlay",
        "EPSS and KEV change urgency without changing technical severity.",
    ),
    ("rank", "Prioritised queue", "The same CVE separates into two operational priorities."),
)


def _round(value: float | None, digits: int = 3) -> float | None:
    return None if value is None else round(float(value), digits)


def build_payload(
    store: Store,
    run_id: str,
    model: RoleModel,
    model_report: dict[str, Any],
    weights: dict[str, Any],
) -> dict[str, Any]:
    """Build browser data from the same store and artifact used by the CLI."""
    hosts = store.hosts(run_id)
    findings = {finding.id: finding for finding in store.findings(run_id)}
    profiles = {profile.host_ip: profile for profile in store.profiles(run_id)}
    scores = store.scores(run_id)
    captured_enrichments = store.enrichments_for_run(run_id)
    enrichments = {
        finding_id: [item.to_json() for item in captured_enrichments.get(finding_id, [])]
        for finding_id in findings
    }
    baseline_order = sorted(
        scores,
        key=lambda item: (
            -(item.base_score if item.base_score is not None else item.risk / 10.0),
            item.finding_id,
        ),
    )
    baseline_positions = {
        item.finding_id: position for position, item in enumerate(baseline_order, start=1)
    }
    score_by_host: dict[str, list[Any]] = {}
    for score in scores:
        score_by_host.setdefault(score.host_ip, []).append(score)

    host_rows = []
    for host in hosts:
        profile = profiles.get(host.ip)
        prediction = model.predict(host)
        top_score = score_by_host.get(host.ip, [None])[0]
        host_rows.append(
            {
                "ip": host.ip,
                "hostname": host.hostname,
                "os": host.os_guess,
                "services": [service.to_json() for service in host.services],
                "rule_role": None if profile is None else profile.role.to_json(),
                "exposure": None if profile is None else profile.exposure.to_json(),
                "segment": None if profile is None else profile.segment,
                "controls": (
                    {}
                    if profile is None
                    else {key: feature.to_json() for key, feature in profile.controls.items()}
                ),
                "manual": (
                    {}
                    if profile is None
                    else {key: feature.to_json() for key, feature in profile.manual.items()}
                ),
                "prediction": prediction.to_json(),
                "top_risk": None if top_score is None else top_score.risk,
                "top_band": None if top_score is None else top_score.band,
                "finding_count": len(score_by_host.get(host.ip, [])),
            }
        )

    ranked = []
    for position, score in enumerate(scores, start=1):
        finding = findings[score.finding_id]
        enrichment = best_enrichment(captured_enrichments.get(finding.id, []))
        profile = profiles.get(score.host_ip)
        ranked.append(
            {
                "position": position,
                "finding_id": finding.id,
                "host_ip": finding.host_ip,
                "tool": finding.tool,
                "tool_native_id": finding.tool_native_id,
                "port": finding.port,
                "protocol": finding.protocol,
                "url": finding.url,
                "title": finding.title,
                "description": finding.description,
                "evidence": finding.evidence,
                "cve_ids": list(finding.cve_ids),
                "cwe_ids": list(finding.cwe_ids),
                "native_severity": finding.native_severity,
                "native_confidence": finding.native_confidence,
                "provenance": finding.provenance.to_json(),
                "cve": score.cve_id,
                "risk": score.risk,
                "band": score.band,
                "baseline_position": baseline_positions[score.finding_id],
                "rank_delta": baseline_positions[score.finding_id] - position,
                "base_vector": score.base_vector,
                "base_score": score.base_score,
                "env_vector": score.env_vector,
                "env_score": score.env_score,
                "env_modifications": score.env_modifications,
                "epss_percentile": score.epss_percentile,
                "threat_multiplier": score.threat_multiplier,
                "kev": score.kev,
                "native_fallback": score.native_fallback,
                "inputs": score.inputs,
                "weights_hash": score.weights_hash,
                "reason": score.reason,
                "fix": score.fix,
                "role": None if profile is None else profile.role.value,
                "exposure": None if profile is None else profile.exposure.value,
                "environment": (
                    None
                    if profile is None or "environment" not in profile.manual
                    else profile.manual["environment"].value
                ),
                "patch_reference": (
                    None
                    if enrichment is None or not enrichment.patch_references
                    else enrichment.patch_references[0]
                ),
                "enrichment": None if enrichment is None else enrichment.to_json(),
                "enrichment_candidates": enrichments[finding.id],
            }
        )

    comparison = [
        item
        for item in ranked
        if item["cve"] == "CVE-1999-9001" and item["host_ip"] in ("172.28.0.10", "172.28.0.12")
    ]
    comparison.sort(key=lambda item: -item["risk"])

    tool_counts: dict[str, int] = {}
    for finding in findings.values():
        tool_counts[finding.tool] = tool_counts.get(finding.tool, 0) + 1

    feeds = {
        name: {
            "file_date": metadata.get("file_date"),
            "rows": metadata.get("rows"),
            "sha256": metadata.get("sha256"),
        }
        for name, metadata in store.feeds_meta(run_id=run_id).items()
    }
    return {
        "status": "NOT RUN",
        "data_kind": "synthetic",
        "run_id": run_id,
        "stages": [
            {"id": stage_id, "name": name, "description": description}
            for stage_id, name, description in STAGES
        ],
        "model": {
            "hash": model.model_hash,
            "algorithm": model.training["algorithm"],
            "classes": list(model.classes),
            "features": len(model.features),
            "temperature": model.temperature,
            "confidence_threshold": model.confidence_threshold,
            "margin_threshold": model.margin_threshold,
            "training_examples": model.training["examples"],
            "validation_examples": model_report["model"]["validation_examples"],
            "metrics": {
                key: model_report["validation"][key]
                for key in (
                    "accuracy",
                    "coverage",
                    "macro_f1",
                    "log_loss",
                    "expected_calibration_error",
                )
            },
        },
        "scope": {
            "allowed": [host.ip for host in hosts],
            "canary": "172.28.0.250",
            "canary_blocked": True,
        },
        "feeds": feeds,
        "tool_counts": tool_counts,
        "pipeline_counts": {
            "hosts": len(hosts),
            "canonical_findings": len(findings),
            "enriched_findings": sum(bool(items) for items in enrichments.values()),
            "enrichment_records": sum(len(items) for items in enrichments.values()),
            "context_profiles": len(profiles),
            "scored_findings": len(scores),
            "unique_cves": len(
                {item["cve_id"] for items in enrichments.values() for item in items}
            ),
        },
        "findings": [findings[key].to_json() for key in sorted(findings)],
        "hosts": host_rows,
        "ranked": ranked,
        "comparison": comparison,
        "weights": {
            "kev_boost": weights["threat"]["kev_boost"],
            "kev_floor": weights["threat"]["kev_floor_internet_facing"],
            "bands": weights["bands"],
        },
    }


def _safe_json(payload: dict[str, Any]) -> str:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def _render_legacy(payload: dict[str, Any]) -> str:
    """Render a standalone simulation with no external resources."""
    data = _safe_json(payload)
    title = escape(str(payload.get("run_id", "simulation")))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnAssess Pipeline Replay - {title}</title>
<style>
:root{{
  --paper:#f4f1ea;--paper-2:#ebe7de;--ink:#252a27;--muted:#666b65;--line:#c8c5bc;
  --sage:#50705e;--sage-2:#dce6de;--blue:#44758a;--blue-2:#dbe8ed;--amber:#b06b24;
  --red:#a43f35;--red-2:#f2d9d4;--green:#4e7352;--green-2:#dce8dc;--white:#fffdf8;
  --shadow:0 10px 30px rgba(51,48,39,.10);--radius:6px;
}}
*{{box-sizing:border-box}}
html,body{{max-width:100%;overflow-x:hidden}}
html{{background:var(--paper);color:var(--ink);font-family:Bahnschrift,"Segoe UI",sans-serif;letter-spacing:0}}
body{{margin:0;min-width:320px;background:
  linear-gradient(rgba(80,112,94,.045) 1px,transparent 1px),
  linear-gradient(90deg,rgba(80,112,94,.045) 1px,transparent 1px),var(--paper);
  background-size:32px 32px}}
button,input{{font:inherit;letter-spacing:0}}
button{{cursor:pointer}}
.topbar{{height:74px;padding:0 26px;border-bottom:1px solid var(--line);background:rgba(244,241,234,.96);
  display:flex;align-items:center;justify-content:space-between;gap:20px;position:sticky;top:0;z-index:20}}
.brand{{display:flex;align-items:center;gap:12px;min-width:240px}}
.brand-mark{{width:38px;height:38px;border:1px solid var(--ink);display:grid;place-items:center;background:var(--white)}}
.brand-mark svg{{width:25px;height:25px}}
.brand strong{{font-family:Georgia,serif;font-size:20px;font-weight:700}}
.brand small{{display:block;color:var(--muted);font-size:11px;margin-top:2px}}
.run-state{{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:center}}
.badge{{border:1px solid var(--line);padding:5px 8px;border-radius:4px;font-size:11px;background:var(--white)}}
.badge.live{{color:var(--green);border-color:#9ab39e;background:var(--green-2)}}
.badge.synthetic{{color:var(--amber);border-color:#d8b17f;background:#f7e7d2}}
.controls{{display:flex;align-items:center;gap:8px;justify-content:flex-end;min-width:300px}}
.icon-button{{width:36px;height:36px;border:1px solid var(--line);border-radius:4px;background:var(--white);display:grid;place-items:center}}
.icon-button:hover,.icon-button:focus-visible{{border-color:var(--sage);box-shadow:0 0 0 3px rgba(80,112,94,.12)}}
.icon-button svg{{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2}}
.speed{{display:flex;border:1px solid var(--line);border-radius:4px;overflow:hidden;background:var(--white)}}
.speed button{{border:0;border-right:1px solid var(--line);background:transparent;padding:8px 9px;font-size:11px}}
.speed button:last-child{{border-right:0}}
.speed button.active{{background:var(--ink);color:var(--white)}}
.stage-band{{border-bottom:1px solid var(--line);background:var(--paper-2);overflow-x:auto}}
.stages{{display:grid;grid-template-columns:repeat(8,minmax(128px,1fr));min-width:1024px;max-width:1600px;margin:auto}}
.stage{{height:70px;border:0;border-right:1px solid var(--line);background:transparent;padding:10px 12px;text-align:left;color:var(--muted)}}
.stage .number{{font-family:Georgia,serif;font-size:12px;margin-right:6px}}
.stage .name{{display:block;color:inherit;font-size:12px;font-weight:700;margin-top:5px}}
.stage.done{{background:rgba(80,112,94,.07);color:var(--sage)}}
.stage.active{{background:var(--white);color:var(--ink);box-shadow:inset 0 -3px 0 var(--sage)}}
.progress-row{{display:flex;align-items:center;gap:12px;padding:7px 26px;border-bottom:1px solid var(--line);background:var(--white)}}
.progress-row input{{width:100%;accent-color:var(--sage)}}
.stage-readout{{min-width:250px;text-align:right;font-size:12px;color:var(--muted)}}
.stage-readout strong{{color:var(--ink)}}
.shell{{max-width:1540px;margin:0 auto;padding:18px 22px 48px}}
.section-head{{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;margin-bottom:12px}}
.section-head h2{{font-family:Georgia,serif;font-size:21px;margin:0}}
.section-head p{{margin:4px 0 0;color:var(--muted);font-size:12px;max-width:680px}}
.micro{{font-size:10px;color:var(--muted);text-transform:uppercase}}
.workspace{{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(280px,.55fr);gap:16px}}
.panel{{border:1px solid var(--line);border-radius:var(--radius);background:rgba(255,253,248,.91);box-shadow:var(--shadow);padding:16px;min-width:0}}
.topology-panel{{min-height:470px}}
.topology{{height:388px;position:relative;overflow:hidden;border-top:1px solid var(--line);background:
  linear-gradient(90deg,rgba(68,117,138,.035),transparent 40%,rgba(80,112,94,.055))}}
.topology svg.wires{{position:absolute;inset:0;width:100%;height:100%;z-index:0}}
.wire{{fill:none;stroke:var(--line);stroke-width:2;stroke-dasharray:7 7;transition:stroke .25s,opacity .25s}}
.wire.active{{stroke:var(--sage);stroke-dasharray:none}}
.packet{{fill:var(--amber);opacity:0;filter:drop-shadow(0 0 5px rgba(176,107,36,.55))}}
.packet.active{{opacity:1}}
.node{{position:absolute;z-index:2;border:1px solid var(--line);border-radius:6px;background:var(--white);box-shadow:0 5px 16px rgba(41,46,42,.08);padding:9px 10px;min-width:124px;transition:transform .25s,border-color .25s,box-shadow .25s}}
button.node{{text-align:left;color:var(--ink)}}
.node.active{{border-color:var(--sage);box-shadow:0 0 0 3px rgba(80,112,94,.12),0 8px 20px rgba(41,46,42,.12);transform:translateY(-2px)}}
.node .node-title{{font-size:12px;font-weight:700;display:block}}
.node .node-meta{{font-size:10px;color:var(--muted);display:block;margin-top:3px}}
.node .node-icon{{width:25px;height:25px;float:left;margin-right:8px;color:var(--blue)}}
.source-nmap{{left:2%;top:9%}}.source-zap{{left:2%;top:38%}}.source-nikto{{left:2%;top:67%}}
.engine{{left:38%;top:35%;min-width:150px;border-color:#9ab39e;background:var(--sage-2)}}
.host-a{{right:2%;top:6%}}.host-b{{right:2%;top:37%}}.host-c{{right:2%;top:68%}}
.feed-row{{position:absolute;left:28%;right:27%;bottom:8px;display:flex;gap:5px;justify-content:center;z-index:3}}
.feed{{font-size:9px;border:1px solid var(--line);border-radius:3px;background:var(--white);padding:5px 7px}}
.event-panel{{height:470px;display:flex;flex-direction:column}}
.event-stream{{overflow:auto;min-height:0;border-top:1px solid var(--line)}}
.event{{display:grid;grid-template-columns:34px 1fr;gap:10px;padding:12px 0;border-bottom:1px solid #dedbd3;opacity:.32;transition:opacity .3s,transform .3s;transform:translateY(3px)}}
.event.visible{{opacity:1;transform:none}}
.event-index{{width:26px;height:26px;border:1px solid var(--line);display:grid;place-items:center;border-radius:50%;font-family:Georgia,serif;font-size:11px}}
.event.visible .event-index{{background:var(--sage);border-color:var(--sage);color:white}}
.event strong{{font-size:12px}}.event p{{font-size:11px;color:var(--muted);margin:4px 0 0;line-height:1.45}}
.event code{{font:10px Consolas,monospace;color:var(--blue)}}
.analysis-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}}
.host-switcher{{display:flex;border-bottom:1px solid var(--line);margin:0 -16px 14px;padding:0 16px;overflow-x:auto}}
.host-tab{{border:0;border-bottom:3px solid transparent;background:transparent;padding:9px 12px;font-size:11px;color:var(--muted);white-space:nowrap}}
.host-tab.active{{border-color:var(--sage);color:var(--ink);font-weight:700}}
.model-summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:15px}}
.stat{{border-left:2px solid var(--sage);padding:4px 8px}}
.stat b{{font-family:Georgia,serif;font-size:18px;display:block}}
.stat span{{font-size:9px;color:var(--muted)}}
.prob-list{{display:grid;gap:7px}}
.prob-row{{display:grid;grid-template-columns:126px 1fr 50px;align-items:center;gap:8px;font-size:11px}}
.prob-label{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.track{{height:8px;background:var(--paper-2);border:1px solid #d6d2c9;overflow:hidden;border-radius:2px}}
.fill{{height:100%;width:0;background:var(--blue);transition:width .7s cubic-bezier(.2,.8,.2,1)}}
.prob-row.winner .fill{{background:var(--sage)}}
.prob-value{{text-align:right;font-variant-numeric:tabular-nums;color:var(--muted)}}
.evidence-box{{margin-top:14px;border-left:3px solid var(--amber);background:#f8ecdc;padding:9px 11px;font:11px Consolas,monospace;line-height:1.45}}
.abstain{{color:var(--amber);font-weight:700}}
.score-flow{{display:grid;grid-template-columns:repeat(5,1fr);gap:7px;align-items:end;height:156px;padding-top:12px}}
.score-step{{display:flex;flex-direction:column;justify-content:flex-end;align-items:center;height:140px;min-width:0}}
.score-bar{{width:100%;max-width:72px;height:0;background:var(--blue-2);border:1px solid var(--blue);transition:height .7s cubic-bezier(.2,.8,.2,1);position:relative}}
.score-step.final .score-bar{{background:var(--red-2);border-color:var(--red)}}
.score-bar b{{position:absolute;top:-23px;left:50%;transform:translateX(-50%);font-family:Georgia,serif;font-size:16px}}
.score-step small{{margin-top:6px;text-align:center;font-size:9px;color:var(--muted);min-height:23px}}
.mod-list{{display:flex;gap:5px;flex-wrap:wrap;margin-top:12px}}
.mod{{font:10px Consolas,monospace;padding:5px 6px;border:1px solid var(--line);background:var(--paper-2);border-radius:3px}}
.formula{{font:11px Consolas,monospace;background:var(--ink);color:#f8f5ee;padding:9px;border-radius:4px;margin-top:12px;overflow:auto}}
.comparison{{margin-top:16px;padding:0;overflow:hidden}}
.comparison-head{{padding:16px 18px;background:var(--ink);color:var(--white);display:flex;justify-content:space-between;gap:14px;align-items:center}}
.comparison-head h2{{font-family:Georgia,serif;font-size:22px;margin:0}}
.comparison-head p{{font-size:11px;margin:0;color:#d7d5cc}}
.compare-grid{{display:grid;grid-template-columns:1fr 1fr}}
.machine{{padding:18px;border-right:1px solid var(--line)}}.machine:last-child{{border-right:0}}
.machine-top{{display:flex;justify-content:space-between;gap:12px;align-items:start}}
.machine h3{{font-size:14px;margin:0}}.machine .role{{font-family:Georgia,serif;font-size:18px;margin-top:4px}}
.band{{padding:5px 8px;border-radius:3px;font-size:10px;font-weight:700}}
.band.Critical{{background:var(--red-2);color:var(--red)}}.band.High{{background:#f5dfc6;color:#95591e}}
.risk-meter{{height:18px;border:1px solid var(--line);background:var(--paper-2);margin:16px 0 7px;overflow:hidden}}
.risk-meter span{{display:block;height:100%;width:0;transition:width .9s cubic-bezier(.2,.8,.2,1);background:var(--amber)}}
.machine.Critical .risk-meter span{{background:var(--red)}}
.risk-line{{display:flex;justify-content:space-between;align-items:baseline}}
.risk-line b{{font-family:Georgia,serif;font-size:27px}}
.machine dl{{display:grid;grid-template-columns:1fr auto;gap:7px 12px;font-size:11px;margin:14px 0 0}}
.machine dt{{color:var(--muted)}}.machine dd{{margin:0;font-weight:700}}
.queue-panel{{margin-top:16px}}
.queue{{width:100%;border-collapse:collapse;table-layout:fixed}}
.queue th{{font-size:9px;color:var(--muted);text-align:left;border-bottom:1px solid var(--line);padding:7px}}
.queue td{{font-size:11px;border-bottom:1px solid #dedbd3;padding:8px 7px;vertical-align:middle;overflow:hidden;text-overflow:ellipsis}}
.queue tr{{opacity:.25;transition:opacity .3s,background .3s}}
.queue tr.visible{{opacity:1}}
.queue tr.focus{{background:#f7e7d2}}
.queue .rank{{font-family:Georgia,serif;font-size:16px;width:42px}}
.queue .risk{{font-family:Georgia,serif;font-size:15px;width:70px}}
.queue .host{{width:115px}}.queue .status{{width:78px}}.queue .tool{{width:58px}}
.footer-note{{display:flex;justify-content:space-between;gap:20px;margin-top:18px;padding:12px 2px;color:var(--muted);font-size:10px;border-top:1px solid var(--line)}}
[data-stage="0"] .engine,[data-stage="0"] .host-node,[data-stage="0"] .feed{{opacity:.35}}
@keyframes pulse{{0%,100%{{transform:scale(1)}}50%{{transform:scale(1.06)}}}}
[data-playing="true"] .engine.active{{animation:pulse 1.3s ease-in-out infinite}}
@media (max-width:1050px){{
  .topbar{{height:auto;min-height:74px;flex-wrap:wrap;padding:12px 18px}}.brand,.controls{{min-width:0}}
  .run-state{{order:3;width:100%;justify-content:flex-start}}.workspace{{grid-template-columns:1fr}}
  .event-panel{{height:300px}}.analysis-grid{{grid-template-columns:1fr}}
}}
@media (max-width:700px){{
  .topbar{{align-items:flex-start}}.brand small{{display:none}}.controls{{flex-wrap:wrap}}
  .speed{{order:3}}.shell{{padding:12px 10px 32px}}.progress-row{{padding:7px 12px}}
  .stage-readout{{min-width:120px}}.topology-panel{{min-height:520px}}.topology{{height:438px}}
  .node{{min-width:105px;padding:7px}}.node .node-icon{{display:none}}
  .source-nmap{{left:1%;top:5%}}.source-zap{{left:1%;top:24%}}.source-nikto{{left:1%;top:43%}}
  .engine{{left:34%;top:24%;width:90px;min-width:90px;padding:7px}}.host-a{{right:1%;top:4%}}.host-b{{right:1%;top:27%}}.host-c{{right:1%;top:50%}}
  .feed-row{{left:5%;right:5%;bottom:8px;flex-wrap:wrap}}.model-summary{{grid-template-columns:1fr 1fr}}
  .prob-row{{grid-template-columns:105px 1fr 42px}}.compare-grid{{grid-template-columns:1fr}}
  .machine{{border-right:0;border-bottom:1px solid var(--line)}}.queue .tool{{display:none}}
  .queue td .micro{{display:none}}.queue td{{font-size:10px;padding-top:10px;padding-bottom:10px}}
}}
@media (prefers-reduced-motion:reduce){{*{{animation:none!important;transition:none!important}}}}
</style>
</head>
<body data-stage="0" data-playing="false">
<header class="topbar">
  <div class="brand">
    <div class="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 32 32"><path d="M16 3 27 7v8c0 7-4.6 11.3-11 14-6.4-2.7-11-7-11-14V7l11-4Z" fill="none" stroke="currentColor" stroke-width="2"/><path d="M10 16h4l2-5 3 10 2-5h3" fill="none" stroke="currentColor" stroke-width="2"/></svg>
    </div>
    <div><strong>VulnAssess</strong><small>Context-aware pipeline replay</small></div>
  </div>
  <div class="run-state">
    <span class="badge synthetic">SYNTHETIC DATA &middot; NOT RUN</span>
    <span class="badge live" id="runBadge">RUN {title}</span>
    <span class="badge" id="modelBadge">MODEL</span>
  </div>
  <div class="controls">
    <button class="icon-button" id="restart" title="Restart replay" aria-label="Restart replay"><svg viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/></svg></button>
    <button class="icon-button" id="play" title="Play replay" aria-label="Play replay"><svg id="playIcon" viewBox="0 0 24 24"><path d="m8 5 11 7-11 7Z"/></svg></button>
    <div class="speed" aria-label="Replay speed"><button data-speed="1600">0.5x</button><button class="active" data-speed="900">1x</button><button data-speed="460">2x</button></div>
  </div>
</header>
<nav class="stage-band" aria-label="Pipeline stages"><div class="stages" id="stages"></div></nav>
<div class="progress-row">
  <input id="scrubber" type="range" min="0" max="7" value="0" step="1" aria-label="Pipeline stage">
  <div class="stage-readout"><strong id="stageName">Scope fence</strong><br><span id="stageCount">1 of 8</span></div>
</div>
<main class="shell">
  <div class="workspace">
    <section class="panel topology-panel">
      <div class="section-head"><div><span class="micro">Live system graph</span><h2>Evidence moving through the pipeline</h2><p id="stageDescription"></p></div><span class="badge" id="activityBadge">READY</span></div>
      <div class="topology" id="topology">
        <svg class="wires" viewBox="0 0 1000 430" preserveAspectRatio="none" aria-hidden="true">
          <path id="scanWire1" class="wire scan-wire" d="M145 70 C280 70 310 185 430 185"/>
          <path id="scanWire2" class="wire scan-wire" d="M145 185 C280 185 310 185 430 185"/>
          <path id="scanWire3" class="wire scan-wire" d="M145 300 C280 300 310 185 430 185"/>
          <path id="hostWire1" class="wire host-wire" d="M550 185 C680 185 690 62 825 62"/>
          <path id="hostWire2" class="wire host-wire" d="M550 185 C680 185 700 185 825 185"/>
          <path id="hostWire3" class="wire host-wire" d="M550 185 C680 185 690 310 825 310"/>
          <path id="feedWire" class="wire feed-wire" d="M470 390 C470 330 480 260 480 220"/>
          <circle class="packet scan-packet" r="5"><animateMotion dur="1.7s" repeatCount="indefinite" path="M145 70 C280 70 310 185 430 185"/></circle>
          <circle class="packet scan-packet" r="5"><animateMotion begin=".5s" dur="1.9s" repeatCount="indefinite" path="M145 185 C280 185 310 185 430 185"/></circle>
          <circle class="packet feed-packet" r="5"><animateMotion dur="1.5s" repeatCount="indefinite" path="M470 390 C470 330 480 260 480 220"/></circle>
          <circle class="packet host-packet" r="5"><animateMotion dur="1.8s" repeatCount="indefinite" path="M550 185 C680 185 690 310 825 310"/></circle>
        </svg>
        <div class="node source-nmap source-node"><svg class="node-icon" viewBox="0 0 24 24"><path d="M4 7h16M7 4v6m10-6v6M5 14h4v4H5zm10 0h4v4h-4zM9 16h6" fill="none" stroke="currentColor" stroke-width="1.7"/></svg><span class="node-title">Nmap XML</span><span class="node-meta" id="nmapCount">service evidence</span></div>
        <div class="node source-zap source-node"><svg class="node-icon" viewBox="0 0 24 24"><path d="M12 3 4 7v5c0 5 3 8 8 10 5-2 8-5 8-10V7l-8-4Z" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="m9 12 2 2 4-5" fill="none" stroke="currentColor" stroke-width="1.7"/></svg><span class="node-title">ZAP JSON</span><span class="node-meta" id="zapCount">web findings</span></div>
        <div class="node source-nikto source-node"><svg class="node-icon" viewBox="0 0 24 24"><path d="M5 4h14v16H5zM8 8h8m-8 4h8m-8 4h5" fill="none" stroke="currentColor" stroke-width="1.7"/></svg><span class="node-title">Nikto JSON</span><span class="node-meta" id="niktoCount">third reader</span></div>
        <div class="node engine"><svg class="node-icon" viewBox="0 0 24 24"><path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1" fill="none" stroke="currentColor" stroke-width="1.7"/><circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="1.7"/></svg><span class="node-title">Unified engine</span><span class="node-meta">canonical evidence</span></div>
        <div id="hostNodes"></div>
        <div class="feed-row"><span class="feed">NVD 2 rows</span><span class="feed">EPSS 2 rows</span><span class="feed">KEV 1 row</span></div>
      </div>
    </section>
    <aside class="panel event-panel">
      <div class="section-head"><div><span class="micro">Event stream</span><h2>What just happened</h2></div></div>
      <div class="event-stream" id="events"></div>
    </aside>
  </div>

  <div class="analysis-grid">
    <section class="panel model-panel">
      <div class="section-head"><div><span class="micro">Learned role model</span><h2>Probability and evidence</h2><p>Multinomial logistic regression. Predictions stay shadow-only.</p></div><span class="badge" id="predictionBadge">WAITING</span></div>
      <div class="host-switcher" id="hostTabs"></div>
      <div class="model-summary">
        <div class="stat"><b id="modelClasses">9</b><span>role classes</span></div>
        <div class="stat"><b id="modelFeatures">134</b><span>features</span></div>
        <div class="stat"><b id="modelAccuracy">1.000</b><span>synthetic validation</span></div>
        <div class="stat"><b id="modelCoverage">1.000</b><span>synthetic coverage</span></div>
      </div>
      <div class="prob-list" id="probabilities"></div>
      <div class="evidence-box" id="modelEvidence">Model evidence appears at the role-model stage.</div>
    </section>

    <section class="panel score-panel">
      <div class="section-head"><div><span class="micro">Deterministic risk model</span><h2>Score construction</h2><p id="scoreTitle">Select a host to inspect its top-ranked finding.</p></div><span class="badge" id="scoreBand">WAITING</span></div>
      <div class="score-flow" id="scoreFlow"></div>
      <div class="mod-list" id="modifications"></div>
      <div class="formula" id="formula">risk = environmental x 10 x threat + KEV boost</div>
    </section>
  </div>

  <section class="panel comparison">
    <div class="comparison-head"><div><span class="micro">Research claim in motion</span><h2>Same CVE. Same base. Different operational risk.</h2></div><p>Context is the only host-specific input in this comparison.</p></div>
    <div class="compare-grid" id="comparison"></div>
  </section>

  <section class="panel queue-panel">
    <div class="section-head"><div><span class="micro">Final output</span><h2>Remediation queue</h2><p>The queue reveals only after every upstream input is visible.</p></div><span class="badge" id="queueState">LOCKED</span></div>
    <table class="queue"><thead><tr><th class="rank">#</th><th class="risk">Risk</th><th class="status">Band</th><th class="host">Host</th><th class="tool">Tool</th><th>Finding and deterministic reason</th></tr></thead><tbody id="queue"></tbody></table>
  </section>

  <div class="footer-note"><span>Local-only replay. No external assets, scripts, feeds or model calls.</span><span id="footerHash"></span></div>
</main>
<script>const DATA={data};
const state={{stage:0,playing:false,speed:900,selected:DATA.hosts[0]?.ip,timer:null}};
const icons={{
 play:'<path d="m8 5 11 7-11 7Z"/>',
 pause:'<path d="M8 5v14M16 5v14"/>'
}};
const eventText=[
 ['Authorisation fence closed',`Allowed ${{DATA.scope.allowed.length}} explicit hosts. Canary ${{DATA.scope.canary}} stays blocked.`,'ScopeError before file access'],
 ['Scanner records normalised',`${{DATA.tool_counts.nmap||0}} Nmap, ${{DATA.tool_counts.zap||0}} ZAP, ${{DATA.tool_counts.nikto||0}} Nikto findings entered one schema.`,'provenance retained'],
 ['Offline snapshots joined',`${{Object.keys(DATA.feeds).length}} feed snapshots matched CVEs without a network call.`,'NVD + EPSS + KEV'],
 ['Role probabilities calculated',`${{DATA.model.features}} binary scan features entered a ${{DATA.model.classes.length}}-class linear model.`,'shadow inference only'],
 ['Context profile assembled','Role, exposure and observed controls now carry confidence and verbatim evidence.','no silent assumptions'],
 ['Environmental vector changed','Internal reachability and role requirements modify CVSS metrics before threat is applied.','pure deterministic scoring'],
 ['Exploitation signal overlaid','EPSS sets likelihood; KEV confirms exploitation and adds the configured boost.','same CVE = same threat facts'],
 ['Queue committed','Six findings are ordered by operational risk. The same 9.8 CVE now separates by 21 points.','100.0 vs 79.0']
];
function esc(value){{return String(value??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]))}}
function hostClass(index){{return ['host-a','host-b','host-c'][index]||'host-c'}}
function renderStatic(){{
 document.getElementById('modelBadge').textContent=`MODEL ${{DATA.model.hash}}`;
 document.getElementById('footerHash').textContent=`model ${{DATA.model.hash}} | run ${{DATA.run_id}}`;
 document.getElementById('modelClasses').textContent=DATA.model.classes.length;
 document.getElementById('modelFeatures').textContent=DATA.model.features;
 document.getElementById('modelAccuracy').textContent=Number(DATA.model.metrics.accuracy).toFixed(3);
 document.getElementById('modelCoverage').textContent=Number(DATA.model.metrics.coverage).toFixed(3);
 document.getElementById('nmapCount').textContent=`${{DATA.tool_counts.nmap||0}} canonical findings`;
 document.getElementById('zapCount').textContent=`${{DATA.tool_counts.zap||0}} canonical findings`;
 document.getElementById('niktoCount').textContent=`${{DATA.tool_counts.nikto||0}} canonical findings`;
 document.getElementById('stages').innerHTML=DATA.stages.map((s,i)=>`<button class="stage" data-stage-button="${{i}}"><span class="number">0${{i+1}}</span><span class="name">${{esc(s.name)}}</span></button>`).join('');
 document.getElementById('events').innerHTML=eventText.map((e,i)=>`<div class="event" data-event="${{i}}"><div class="event-index">${{i+1}}</div><div><strong>${{esc(e[0])}}</strong><p>${{esc(e[1])}}</p><code>${{esc(e[2])}}</code></div></div>`).join('');
 document.getElementById('hostNodes').innerHTML=DATA.hosts.map((h,i)=>`<button class="node host-node ${{hostClass(i)}}" data-host="${{esc(h.ip)}}"><span class="node-title">${{esc(h.ip)}}</span><span class="node-meta">${{esc(h.prediction.label)}} | ${{h.finding_count}} findings</span></button>`).join('');
 document.getElementById('hostTabs').innerHTML=DATA.hosts.map(h=>`<button class="host-tab" data-host="${{esc(h.ip)}}">${{esc(h.ip)}}</button>`).join('');
 document.getElementById('comparison').innerHTML=DATA.comparison.map(item=>`<article class="machine ${{esc(item.band)}}"><div class="machine-top"><div><h3>${{esc(item.host_ip)}}</h3><div class="role">${{esc(String(item.role).replaceAll('_',' '))}}</div></div><span class="band ${{esc(item.band)}}">${{esc(item.band)}}</span></div><div class="risk-meter"><span data-risk="${{item.risk}}"></span></div><div class="risk-line"><span>Context-aware risk</span><b>${{Number(item.risk).toFixed(1)}}</b></div><dl><dt>CVSS base</dt><dd>${{item.base_score}}</dd><dt>Exposure</dt><dd>${{esc(String(item.exposure).replaceAll('_',' '))}}</dd><dt>Environment</dt><dd>${{esc(item.environment||'production')}}</dd><dt>CVSS environmental</dt><dd>${{item.env_score}}</dd><dt>EPSS percentile</dt><dd>${{Math.round(item.epss_percentile*100)}}</dd><dt>CISA KEV</dt><dd>${{item.kev?'yes':'no'}}</dd></dl></article>`).join('');
 document.getElementById('queue').innerHTML=DATA.ranked.map(item=>`<tr data-queue-row="${{item.position}}" data-host="${{esc(item.host_ip)}}"><td class="rank">${{item.position}}</td><td class="risk">${{Number(item.risk).toFixed(1)}}</td><td class="status"><span class="band ${{esc(item.band)}}">${{esc(item.band)}}</span></td><td class="host">${{esc(item.host_ip)}}</td><td class="tool">${{esc(item.tool)}}</td><td><b>${{esc(item.title)}}</b><br><span class="micro">${{esc(item.reason)}}</span></td></tr>`).join('');
 bind(); selectHost(state.selected);
}}
function bind(){{
 document.querySelectorAll('[data-stage-button]').forEach(b=>b.addEventListener('click',()=>setStage(Number(b.dataset.stageButton),false)));
 document.querySelectorAll('[data-host]').forEach(b=>b.addEventListener('click',()=>selectHost(b.dataset.host)));
 document.getElementById('scrubber').addEventListener('input',e=>setStage(Number(e.target.value),false));
 document.getElementById('play').addEventListener('click',()=>state.playing?pause():play());
 document.getElementById('restart').addEventListener('click',()=>{{pause();setStage(0,false);play()}});
 document.querySelectorAll('[data-speed]').forEach(b=>b.addEventListener('click',()=>{{state.speed=Number(b.dataset.speed);document.querySelectorAll('[data-speed]').forEach(x=>x.classList.toggle('active',x===b));if(state.playing){{pause();play()}}}}));
}}
function setStage(index,fromTimer){{
 state.stage=Math.max(0,Math.min(DATA.stages.length-1,index));document.body.dataset.stage=state.stage;
 document.getElementById('scrubber').value=state.stage;
 document.getElementById('stageName').textContent=DATA.stages[state.stage].name;
 document.getElementById('stageCount').textContent=`${{state.stage+1}} of ${{DATA.stages.length}}`;
 document.getElementById('stageDescription').textContent=DATA.stages[state.stage].description;
 document.getElementById('activityBadge').textContent=state.stage===7?'COMPLETE':'PROCESSING';
 document.querySelectorAll('.stage').forEach((b,i)=>{{b.classList.toggle('active',i===state.stage);b.classList.toggle('done',i<state.stage)}});
 document.querySelectorAll('.event').forEach((e,i)=>e.classList.toggle('visible',i<=state.stage));
 document.querySelectorAll('.scan-wire').forEach(e=>e.classList.toggle('active',state.stage>=1));
 document.querySelectorAll('.host-wire').forEach(e=>e.classList.toggle('active',state.stage>=3));
 document.querySelectorAll('.feed-wire').forEach(e=>e.classList.toggle('active',state.stage>=2));
 document.querySelectorAll('.scan-packet').forEach(e=>e.classList.toggle('active',state.playing&&state.stage===1));
 document.querySelectorAll('.feed-packet').forEach(e=>e.classList.toggle('active',state.playing&&state.stage===2));
 document.querySelectorAll('.host-packet').forEach(e=>e.classList.toggle('active',state.playing&&state.stage>=3&&state.stage<7));
 document.querySelector('.engine').classList.toggle('active',state.stage>=1&&state.stage<7);
 document.querySelectorAll('.host-node').forEach(e=>e.classList.toggle('active',state.stage>=3&&e.dataset.host===state.selected));
 document.querySelectorAll('.prob-row .fill').forEach(e=>e.style.width=state.stage>=3?e.dataset.width+'%':'0%');
 document.querySelectorAll('.score-bar').forEach(e=>e.style.height=state.stage>=5?e.dataset.height+'%':'0%');
 document.querySelectorAll('[data-risk]').forEach(e=>e.style.width=state.stage>=7?e.dataset.risk+'%':'0%');
 document.querySelectorAll('[data-queue-row]').forEach(e=>e.classList.toggle('visible',state.stage>=7));
 document.getElementById('queueState').textContent=state.stage>=7?'RANKED':'LOCKED';
 document.getElementById('predictionBadge').textContent=state.stage>=3?'SHADOW ACTIVE':'WAITING';
 document.getElementById('scoreBand').textContent=state.stage>=5?(currentScore()?.band||'NO CVE'):'WAITING';
 document.getElementById('modelEvidence').style.opacity=state.stage>=3?'1':'.25';
 if(!fromTimer&&state.playing){{pause()}}
}}
function play(){{
 if(state.stage===DATA.stages.length-1)state.stage=-1;state.playing=true;document.body.dataset.playing='true';
 document.getElementById('playIcon').innerHTML=icons.pause;document.getElementById('play').title='Pause replay';
 const tick=()=>{{if(!state.playing)return;if(state.stage>=DATA.stages.length-1){{pause();return}}setStage(state.stage+1,true);state.timer=setTimeout(tick,state.speed)}};tick();
}}
function pause(){{state.playing=false;document.body.dataset.playing='false';clearTimeout(state.timer);document.getElementById('playIcon').innerHTML=icons.play;document.getElementById('play').title='Play replay';setStage(state.stage,true)}}
function currentHost(){{return DATA.hosts.find(h=>h.ip===state.selected)||DATA.hosts[0]}}
function currentScore(){{return DATA.ranked.find(r=>r.host_ip===state.selected)}}
function selectHost(ip){{
 state.selected=ip;document.querySelectorAll('[data-host]').forEach(e=>e.classList.toggle('active',e.dataset.host===ip));
 const h=currentHost(),p=h.prediction,ordered=Object.entries(p.probabilities).sort((a,b)=>b[1]-a[1]);
 document.getElementById('probabilities').innerHTML=ordered.map(([label,value],i)=>`<div class="prob-row ${{i===0?'winner':''}}"><span class="prob-label">${{esc(label.replaceAll('_',' '))}}</span><div class="track"><div class="fill" data-width="${{value*100}}"></div></div><span class="prob-value">${{(value*100).toFixed(1)}}%</span></div>`).join('');
 document.getElementById('modelEvidence').innerHTML=`<b>${{p.abstained?'<span class="abstain">ABSTAINED -> unknown</span>':esc(p.label.replaceAll('_',' '))}}</b><br>${{esc(p.evidence)}}`;
 renderScore();setStage(state.stage,true);
}}
function renderScore(){{
 const s=currentScore();if(!s){{document.getElementById('scoreTitle').textContent='No finding for this host.';document.getElementById('scoreFlow').innerHTML='';return}}
 document.getElementById('scoreTitle').textContent=s.title;
 const base=s.base_score??(s.risk/10),env=s.env_score??base,threat=s.threat_multiplier??1,boost=s.kev?DATA.weights.kev_boost:0;
 const steps=[['Base',base*10],['Environment',env*10],['Threat',Math.min(env*10*threat,100)],['KEV +'+boost,Math.min(env*10*threat+boost,100)],['Final',s.risk]];
 document.getElementById('scoreFlow').innerHTML=steps.map((step,i)=>`<div class="score-step ${{i===4?'final':''}}"><div class="score-bar" data-height="${{Math.max(5,step[1])}}"><b>${{Number(step[1]).toFixed(1)}}</b></div><small>${{esc(step[0])}}</small></div>`).join('');
 const mods=Object.entries(s.env_modifications||{{}});document.getElementById('modifications').innerHTML=mods.length?mods.map(([k,v])=>`<span class="mod">${{esc(k)}}:${{esc(v)}}</span>`).join(''):'<span class="mod">native fallback</span>';
 document.getElementById('formula').textContent=s.base_score===null?`${{s.native_fallback}} -> ${{s.risk}}`:`${{s.env_score}} x 10 x ${{s.threat_multiplier??'unscored'}} + ${{boost}} = ${{s.risk}}`;
}}
renderStatic();setStage(0,true);setTimeout(play,650);
</script>
</body>
</html>"""


def render(payload: dict[str, Any]) -> str:
    """Render the stage-driven assessment workbench with embedded local data."""
    title = escape(str(payload.get("run_id", "simulation")))
    head, tail = HTML_TEMPLATE.split("%%PAYLOAD%%", 1)
    return head.replace("%%TITLE%%", title) + _safe_json(payload) + tail.replace("%%TITLE%%", title)
