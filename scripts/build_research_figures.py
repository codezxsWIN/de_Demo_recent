"""Export descriptive paper figures from verified, existing assessment receipts.

No scanning, model calls, intelligence refreshes, or invented benchmark results.
Requires matplotlib in the environment used to run this script.
"""

import csv
import hashlib
import json
import sys
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.backends.backend_pdf import PdfPages  # noqa: E402
from matplotlib.colors import ListedColormap  # noqa: E402
from matplotlib.ticker import MaxNLocator  # noqa: E402

from vulnassess.capture_history import load  # noqa: E402
from vulnassess.evaluate import positions, ranking_blocks  # noqa: E402

OUT = ROOT / "artifacts" / "research-figures-2026-10-29"
RAW = ROOT / "data" / "live" / "raw"
TARGETS = {
    "http://127.0.0.1:8787/": "HarborDesk",
    "127.0.0.2": "Office",
    "127.0.0.3": "IoT",
}
BLUE, PURPLE, ORANGE = "#2865A8", "#7653A8", "#C47B24"
plt.rcParams.update({
    "font.family": "DejaVu Serif", "font.size": 10, "axes.titlesize": 12,
    "axes.labelsize": 10, "axes.spines.top": False, "axes.spines.right": False,
    "pdf.fonttype": 42, "ps.fonttype": 42, "svg.fonttype": "none",
    "savefig.facecolor": "white", "figure.facecolor": "white",
})


def export_csv(name, rows):
    if not rows:
        raise ValueError(f"No observations for {name}")
    with (OUT / name).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def choose_captures():
    selected = {}
    for path in RAW.glob("assessment-*/review-final.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        target = record.get("result", {}).get("target")
        if target not in TARGETS:
            continue
        # Include the latest final record regardless of AI success; do not select
        # only successful examples to inflate the coverage plot.
        stamp = datetime.fromisoformat(record["captured_at"]).timestamp() if record.get("captured_at") else float("-inf")
        if target not in selected or stamp > selected[target][0]:
            selected[target] = (stamp, path.parent.name)
    if set(selected) != set(TARGETS):
        raise ValueError("A final capture is required for every displayed environment")
    return {TARGETS[target]: load(RAW, selected[target][1]) for target in TARGETS}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    captures = choose_captures()
    snapshots = []
    for name, record in captures.items():
        payload, result = record["payload"], record["result"]
        counts = Counter(item.get("tool") for item in payload["findings"])
        analyst = result.get("analyst") or {}
        coverage = analyst.get("batch_coverage") or analyst.get("finding_coverage") or {}
        included = coverage.get("findings_included", len(coverage.get("included_ids", [])))
        snapshots.append({
            "environment": name, "capture_id": record["capture_id"],
            "captured_at": record.get("captured_at"), "snapshot_hash": record["snapshot_hash"],
            "services": len(result.get("services", [])), "findings": len(payload["findings"]),
            "protocol_policy_findings": counts["service-network"],
            "product_version_cve_candidates": counts["nvd-cpe"],
            "other_scanner_findings": len(payload["findings"]) - counts["service-network"] - counts["nvd-cpe"],
            "uniquely_scored_findings": len({s["finding_id"] for s in payload["scores"]}),
            "validated_ai_findings": included if result.get("ai_status") == "validated" else None,
            "ai_status": result.get("ai_status", "unknown"),
        })
    export_csv("environment_observations.csv", snapshots)
    figures, captions = [], []

    fig, ax = plt.subplots(figsize=(7.2, 3.8))
    y, left = np.arange(len(snapshots)), np.zeros(len(snapshots))
    for key, label, color, hatch in [
        ("protocol_policy_findings", "Protocol policy observations", BLUE, ""),
        ("product_version_cve_candidates", "Product/version CVE candidates", PURPLE, "//"),
        ("other_scanner_findings", "Other scanner observations", ORANGE, ".."),
    ]:
        vals = np.array([r[key] for r in snapshots])
        ax.barh(y, vals, left=left, color=color, hatch=hatch, label=label, height=.54,
                edgecolor="white", linewidth=.6)
        for i, value in enumerate(vals):
            if value:
                ax.text(left[i] + value / 2, i, str(value), ha="center", va="center", color="white", weight="bold")
        left += vals
    for i, total in enumerate(left):
        ax.text(total + .4, i, str(int(total)), va="center")
    ax.set(yticks=y, yticklabels=[r["environment"] for r in snapshots], xlabel="Retained finding records",
           title="Finding composition across three local environments", xlim=(0, max(left) * 1.12))
    ax.invert_yaxis()
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(loc="upper left", bbox_to_anchor=(0, -.24), frameon=False, fontsize=8, ncol=1)
    fig.subplots_adjust(left=.18, right=.96, top=.84, bottom=.36)
    figures.append(("01_finding_composition", fig))
    captions.append("Figure 1. Finding composition in the latest finalized local assessment of each environment, selected without filtering by AI outcome. Product/version CVE associations are candidates, not confirmed exploitability. Other scanner findings are not necessarily network vulnerabilities; HarborDesk contains web-application checks. Counts describe these captures and do not measure comparative detection accuracy.")

    office = captures["Office"]["payload"]
    candidates = {f["id"]: f for f in office["findings"] if f.get("tool") == "nvd-cpe"}
    ranking_rows = []
    for score in office["scores"]:
        if score["finding_id"] not in candidates or score.get("base_score") is None:
            continue
        enrichment = next((e for e in office["enrichments"] if (e["finding_id"], e["cve_id"]) == (score["finding_id"], score["cve_id"])), {})
        if enrichment.get("cvss31_base") is None:
            continue
        ranking_rows.append({"finding_id": score["finding_id"], "cve_id": score["cve_id"],
                             "cvss_base": enrichment["cvss31_base"], "system_priority": score["risk"],
                             "system_cvss_version": score.get("cvss_version_used")})
    if len({r["finding_id"] for r in ranking_rows}) != len(ranking_rows):
        raise ValueError("Ranking comparison requires one score per candidate finding")
    base_ranks = positions(ranking_blocks({r["finding_id"]: r["cvss_base"] for r in ranking_rows}))
    sys_ranks = positions(ranking_blocks({r["finding_id"]: r["system_priority"] for r in ranking_rows}))
    for row in ranking_rows:
        row.update(cvss_rank=base_ranks[row["finding_id"]], system_rank=sys_ranks[row["finding_id"]])
    ranking_rows.sort(key=lambda r: (r["cvss_rank"], r["cve_id"]))
    export_csv("priority_order_comparison.csv", ranking_rows)
    fig, ax = plt.subplots(figsize=(7.2, 5.4))
    # Spread labels within score ties only for display; plotted points retain the
    # average tied ranks. The CSV retains the exact numeric ranks.
    n = len(ranking_rows)
    for i, row in enumerate(ranking_rows, 1):
        color = BLUE if row["system_rank"] < row["cvss_rank"] else ORANGE if row["system_rank"] > row["cvss_rank"] else "#999999"
        ax.plot([0, 1], [row["cvss_rank"], row["system_rank"]], color=color, alpha=.75, lw=1.1, marker="o", ms=4)
        ax.annotate(row["cve_id"], (0, row["cvss_rank"]), xytext=(-8, (row["cvss_rank"]-i)*13),
                    textcoords="offset points", ha="right", va="center", fontsize=8)
        ax.annotate(f"{row['system_priority']:.1f}", (1, row["system_rank"]), xytext=(9, 0),
                    textcoords="offset points", va="center", fontsize=8)
    ax.set(xticks=[0, 1], xticklabels=["CVSS v3.1-only ordering", "VulnAssess ordering"],
           ylabel="Rank (average rank for ties)", title=f"Priority ordering of {n} Office CVE candidates",
           ylim=(n+1, 0), xlim=(-.04, 1.15))
    ax.set_yticks([])
    ax.set_ylabel("")
    ax.spines["left"].set_visible(False)
    ax.text(.5, -.14, "Same candidate cohort; ties averaged. Right labels: recorded priority (0–100).", transform=ax.transAxes,
            ha="center", fontsize=8)
    fig.subplots_adjust(left=.29, right=.92, top=.9, bottom=.18)
    figures.append(("02_priority_rank_changes", fig))
    captions.append("Figure 2. CVSS-only and VulnAssess priority rankings for the same Office product/version candidate cohort. Ties retain average ranks; the CSV contains the exact scores. Blue denotes a move toward the top, orange a move downward, and grey no rank change. Displayed right-hand values are the system's existing priorities. Exposure, role, environment and threat inputs are not isolated here; this is not an ablation or an expert-agreement experiment. Changed ordering does not establish improved accuracy.")

    receipts = []
    for path in (ROOT / "data/service-networks").glob("remediation-verification-*.json"):
        data = json.loads(path.read_text())
        if data.get("status") == "passed" and set(data.get("stages", {})) >= {"before", "after", "restored"}:
            receipts.append((data.get("verified_at", ""), path, data))
    _, receipt_path, receipt = max(receipts, key=lambda x: x[0])
    remediation = []
    for environment in ("office", "iot"):
        for phase in ("before", "after", "restored"):
            row = receipt["stages"][phase][environment]
            remediation.append({"environment": environment, "phase": phase, "service": row["service"],
                                "port": row["port"], "anonymous_accepted": row["proof"]["anonymous_accepted"],
                                "observed_at": row["observed_at"], "source_receipt": receipt_path.name})
    export_csv("remediation_protocol_checks.csv", remediation)
    matrix = np.array([[int(r["anonymous_accepted"]) for r in remediation[i:i+3]] for i in (0, 3)])
    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    ax.imshow(matrix, cmap=ListedColormap(["#DAE7F3", "#F8D9BC"]), vmin=0, vmax=1, aspect="auto")
    for (i, j), value in np.ndenumerate(matrix):
        ax.text(j, i, "Anonymous accepted" if value else "Anonymous rejected", ha="center", va="center", fontsize=10)
    ax.set(xticks=[0, 1, 2], xticklabels=["Before control change", "After control change", "Lab reset"],
           yticks=[0, 1], yticklabels=["Office FTP\nTCP/2121", "IoT MQTT\nTCP/1883"],
           title="Observed effect of authentication configuration")
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    fig.subplots_adjust(left=.2, right=.98, top=.78, bottom=.24)
    figures.append(("03_remediation_verification", fig))
    captions.append("Figure 3. Recorded before/change/reset protocol checks on the same lab endpoint addresses. FTP anonymous login and MQTT anonymous connect/message exchange were accepted before the configuration change, rejected afterward, and accepted again following lab reset. This receipt covers two authentication checks; it does not demonstrate patching of CVEs or elimination of every weakness. Containers were recreated during the configuration cycle; this is a controlled endpoint comparison, not an unchanged-process experiment.")

    labels = json.loads((ROOT / "labs/service_networks/expected-policy-findings.json").read_text())["targets"]
    checks = []
    for target, name in [("127.0.0.2", "Office"), ("127.0.0.3", "IoT")]:
        observed = {f["tool_native_id"] for f in captures[name]["payload"]["findings"] if f["tool"] == "service-network"}
        expected = set(labels[target])
        for identity in sorted(expected):
            checks.append({"environment": name, "expected_condition": identity, "recorded": identity in observed,
                           "capture_id": captures[name]["capture_id"]})
    export_csv("scripted_policy_check_coverage.csv", checks)
    fig, ax = plt.subplots(figsize=(7.2, 3.2))
    for i, name in enumerate(("Office", "IoT")):
        group = [r for r in checks if r["environment"] == name]
        matched, total = sum(r["recorded"] for r in group), len(group)
        ax.barh(i, total, color="#E7E9ED", height=.5)
        ax.barh(i, matched, color=BLUE, height=.5)
        ax.text(total+.1, i, f"{matched}/{total} scripted conditions recorded", va="center", fontsize=9)
    ax.set(yticks=[0, 1], yticklabels=["Office", "IoT"], xlim=(0, 8.8),
           xlabel="Named expected policy conditions", title="Recovery of predefined lab policy conditions")
    ax.invert_yaxis()
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    fig.subplots_adjust(left=.14, right=.98, top=.82, bottom=.24)
    figures.append(("04_scripted_policy_coverage", fig))
    captions.append("Figure 4. Coverage of owner-authored expected policy-condition IDs in the retained Office and IoT captures. These labels were compared after scanning; they are an evaluation checklist, not independent expert ground truth. This small positive-only set does not establish real-world recall, specificity, false-positive rate or overall detection accuracy.")

    fig, ax = plt.subplots(figsize=(7.2, 3.8))
    x, width = np.arange(len(snapshots)), .25
    for offset, key, label, color, hatch in [
        (-1, "findings", "Recorded findings", "#AEB5BF", ""),
        (0, "uniquely_scored_findings", "Findings with stored priority", BLUE, "//"),
        (1, "validated_ai_findings", "Findings in validated AI review", PURPLE, ".."),
    ]:
        values = [r[key] if r[key] is not None else 0 for r in snapshots]
        bars = ax.bar(x+offset*width, values, width, label=label, color=color, hatch=hatch, edgecolor="white")
        for bar, row in zip(bars, snapshots):
            value = row[key]
            ax.annotate(str(value) if value is not None else "Unavailable", (bar.get_x()+width/2, bar.get_height()),
                        xytext=(0, 4), textcoords="offset points", ha="center", fontsize=8)
    ax.set(xticks=x, xticklabels=[r["environment"] for r in snapshots], ylabel="Finding count",
           title="Recorded scoring and AI-review coverage by capture")
    ax.set_ylim(0, max(r["findings"] for r in snapshots)*1.18)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(loc="upper left", bbox_to_anchor=(0, -.2), frameon=False, fontsize=8)
    fig.subplots_adjust(left=.12, right=.98, top=.86, bottom=.35)
    figures.append(("05_scoring_ai_coverage", fig))
    captions.append("Figure 5. Recorded findings, uniquely scored findings and findings included in a validated AI review for each selected capture. AI validation means the implemented citation, structure, selected semantic and deterministic-score checks passed; it is not a measure of model factual accuracy. The latest finalized capture per environment is used regardless of AI outcome. Captures are separate case studies, not repeated independent trials or an availability benchmark.")

    with PdfPages(OUT / "VulnAssess_research_figures.pdf") as pdf:
        for stem, fig in figures:
            for ext in ("pdf", "svg", "png"):
                fig.savefig(OUT / f"{stem}.{ext}", dpi=600, bbox_inches="tight")
            pdf.savefig(fig, bbox_inches="tight")
    # A compact preview for sharing; individual exports retain publication resolution.
    preview, axes = plt.subplots(3, 2, figsize=(12, 12))
    for ax, (stem, _) in zip(axes.flat, figures):
        ax.imshow(plt.imread(OUT / f"{stem}.png"))
        ax.axis("off")
    axes.flat[-1].axis("off")
    axes.flat[-1].text(.05, .8, "VulnAssess: measured lab evidence\n\nFive descriptive figures\nPNG (600 dpi), SVG and PDF\nSource CSVs and provenance included\n\nControlled local case studies\nCVE matches are applicability candidates\nStudy limits appear in the captions", fontsize=13, va="top")
    preview.tight_layout()
    preview.savefig(OUT / "preview.png", dpi=160)
    (OUT / "captions_and_limits.txt").write_text("\n\n".join(captions)+"\n\nSelected captures:\n"+json.dumps(snapshots, indent=2), encoding="utf-8")
    prompt = """Prepare the empirical evaluation section and figures for VulnAssess, an AI-assisted network vulnerability assessment tool. Use ONLY the attached CSVs and verified source manifest as measured results. Preserve all capture IDs, sample sizes, data types and limitations.

Current evidence: three local assessment case studies; positive-only Office/IoT policy-condition checklists; a two-endpoint authentication configuration cycle; within-cohort CVSS versus system priority order; and implementation-level AI review coverage. CVE version matches are candidates, not confirmed vulnerable installations. HarborDesk includes application checks and must not be described as pure network detection. A passed citation validator is not independent factual validation.

Write precise figure captions and explain what each result establishes. Label the rank plot as an ordering comparison, not superiority. Do not present count bars as precision or recall. Do not infer zero false positives from positive-only labels. Do not infer general availability from a selected capture or convert unit-test pass counts into detection accuracy. Do not manufacture missing measurements, baselines, confidence intervals, timing data, ROC curves, model training results or expert ratings.

For stronger future experiments, specify: independent labelled positive and negative endpoint cases; clear CVE applicability ground truth; two or more blinded expert rankings; CVSS-only, CVSS+EPSS and full-context baselines on the same cohort; component ablations; NDCG@k, Kendall tau-b, precision/recall and false-positive rates only where reference labels justify them; and adversarial AI cases measuring unsupported-claim acceptance and citation coverage. Report denominators and missing cases. Treat host/run as the independent unit where appropriate, preserve ties, and distinguish development data from held-out evaluation. Add confidence intervals only when repeat observations and a justified sampling design support them.

Deliver a short Results section, one caption per supplied figure, a limitations paragraph, and a future-experiment table with columns: claim, required data, baseline, metric, and acceptance criterion. Separate observed results from proposed experiments. Never describe this evidence as enterprise readiness or comprehensive network security assurance.
"""
    (OUT / "research_analysis_prompt.txt").write_text(prompt, encoding="utf-8")
    manifest = {"selection": "latest final captured_at per named target, irrespective of AI outcome",
                "captures": snapshots, "remediation_receipt": str(receipt_path.relative_to(ROOT)),
                "remediation_receipt_file_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                "limits": ["descriptive local case studies", "no independent expert rankings", "no held-out detection benchmark", "CVE candidates are not confirmed exploitability"],
                "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in OUT.iterdir() if p.is_file() and p.name != "source_manifest.json"}}
    (OUT / "source_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    archive = OUT.parent / "VulnAssess_research_figures.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in OUT.iterdir():
            if path.is_file():
                bundle.write(path, path.name)
        bundle.write(Path(__file__), "build_research_figures.py")
    print(json.dumps({"output": str(OUT), "archive": str(archive), "captures": snapshots,
                      "scripted_conditions_recorded": sum(r["recorded"] for r in checks),
                      "scripted_conditions_expected": len(checks), "figure_count": len(figures)}, indent=2))


if __name__ == "__main__":
    main()
