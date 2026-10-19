"""Run the RQ1-RQ4 research harness using explicitly synthetic inputs.

This demonstrates the evaluation machinery. It cannot establish any hypothesis;
genuine captures, independent context truth, and expert rankings remain required.
"""

import json
from pathlib import Path

from run_model_simulation import main as run_role_model
from run_visual_simulation import build as build_simulation
from vulnassess import evaluate, experiments
from vulnassess.assessment_snapshot import build_snapshot, save_snapshot
from vulnassess.context_eval import evaluate_context, load_context_truth
from vulnassess.role_model import load_model
from vulnassess.settings import Settings
from vulnassess.store import Store
from vulnassess.unify import unify_run

ROOT = Path(__file__).resolve().parent
SYNTHETIC = ROOT / "tests" / "synthetic"
DATABASE = ROOT / "data" / "visual-simulation.db"
MODEL = ROOT / "models" / "synthetic-role-model.json"
OUTPUT = ROOT / "reports" / "research-simulation.json"
SNAPSHOT = ROOT / "reports" / "research-assessment-snapshot.json"
RUN_ID = "visual-sim"


def build() -> dict:
    if run_role_model() != 0:
        raise RuntimeError("role-model simulation failed before research evaluation")
    build_simulation()
    settings = Settings(ROOT / "config")
    model = load_model(MODEL)
    context_truth = load_context_truth(SYNTHETIC / "synthetic_context_truth.yaml")
    ranking_truth = evaluate.load_truth(SYNTHETIC / "synthetic_groundtruth.yaml")

    with Store(DATABASE) as store:
        hosts = store.hosts(RUN_ID)
        model_predictions = {host.ip: model.predict(host) for host in hosts}
        context_result = evaluate_context(store.profiles(RUN_ID), context_truth, model_predictions)
        ablation_result = experiments.run_ablations(settings, store, RUN_ID, truth=ranking_truth)
        stability_result = experiments.stability_check(settings, store, RUN_ID, 5)
        unification_result = unify_run(store, RUN_ID).to_json()
        snapshot = build_snapshot(settings, store, RUN_ID, model_hash=model.model_hash)
        save_snapshot(snapshot, SNAPSHOT)

    report = {
        "evidence_status": "TESTED WITH SYNTHETIC",
        "hypothesis_interpretation": "INELIGIBLE",
        "reason": (
            "Synthetic context labels and rankings exercise arithmetic only; they are not "
            "independent practitioner judgments."
        ),
        "missing_human_inputs": [
            "tests/fixtures/nmap/*.xml",
            "tests/fixtures/zap/*.json",
            "tests/fixtures/nikto/*.json",
            "reviewed NVD/EPSS/KEV snapshots",
            "independent host context truth",
            "2-3 expert tied rankings with per-expert critical sets",
        ],
        "model_hash": model.model_hash,
        "context_evaluation": context_result,
        "ranking_evaluation": ablation_result.get("expert_evaluation"),
        "ablations": {
            "experiment_hash": ablation_result["experiment_hash"],
            "feed_snapshot_hash": ablation_result["feed_snapshot_hash"],
            "config_drift": ablation_result["config_drift"],
            "inactive_scenarios": ablation_result["inactive_scenarios"],
            "comparisons": ablation_result["comparisons"],
        },
        "stability": stability_result,
        "unification": unification_result,
        "assessment_snapshot": {
            "path": str(SNAPSHOT),
            "hash": snapshot["snapshot_hash"],
        },
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    report = build()
    context = report["context_evaluation"]
    ranking = report["ranking_evaluation"]
    ablations = report["ablations"]
    stability = report["stability"]

    print("VULNASSESS RESEARCH SIMULATION")
    print("  evidence: TESTED WITH SYNTHETIC - hypotheses are INELIGIBLE")
    print(
        "  RQ1 rules: "
        f"role accuracy={context['rule_role']['accuracy']:.3f} "
        f"coverage={context['rule_role']['coverage']:.3f}; "
        f"exposure accuracy={context['exposure']['accuracy']:.3f}"
    )
    print(
        "  RQ1 shadow model: "
        f"role accuracy={context['model_role']['accuracy']:.3f} "
        f"coverage={context['model_role']['coverage']:.3f}; "
        f"disagreements={len(context['rule_model_disagreements'])}"
    )
    print(
        "  RQ2 synthetic tau-b: "
        f"full={ranking['methods']['full']['tau_b_mean']} "
        f"cvss_only={ranking['methods']['cvss_only']['tau_b_mean']} "
        f"cvss_epss={ranking['methods']['cvss_epss']['tau_b_mean']}"
    )
    print(
        "  RQ3 synthetic queue reduction: "
        f"{ranking['h3']['mean_reduction_percent']}% "
        f"(eligible={ranking['h3']['eligible']})"
    )
    print(
        "  RQ4: "
        f"{len(ablations['comparisons'])} ablations; "
        f"inactive={ablations['inactive_scenarios']}; "
        f"deterministic={stability['deterministic']} across {stability['repeats']} repeats"
    )
    print(
        "  correlation: "
        f"{report['unification']['raw_count']} raw -> "
        f"{report['unification']['unified_count']} groups; "
        f"{len(report['unification']['candidates'])} review candidate(s)"
    )
    print(f"  assessment snapshot: {SNAPSHOT} ({report['assessment_snapshot']['hash']})")
    print(f"  output: {OUTPUT}")
    print("  next human evidence: " + ", ".join(report["missing_human_inputs"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
