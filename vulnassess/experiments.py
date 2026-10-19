"""In-memory ranking ablations and stability diagnostics for RQ4.

Experiments never update the store. Their hashes bind results to the current
run, configuration, and feed metadata so drift is distinct from nondeterminism.
"""

import json
from dataclasses import replace
from hashlib import sha256
from typing import Any, Mapping, Sequence

from vulnassess import evaluate, scoring
from vulnassess.errors import ConfigError
from vulnassess.schema import ContextProfile, Enrichment, Feature, ScoreBreakdown

SCENARIOS = (
    "full",
    "no_role",
    "no_exposure",
    "no_controls",
    "no_manual",
    "no_epss",
    "no_kev",
    "context_only",
    "threat_only",
    "cvss_only",
    "cvss_epss",
)


def _canonical(payload: Any) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _digest(payload: Any) -> str:
    return sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _false_control() -> Feature:
    return Feature(False, 0.0, "rule", "none observed")


def _neutral_profile(profile: ContextProfile) -> ContextProfile:
    return ContextProfile(
        host_ip=profile.host_ip,
        role=Feature("unknown", 1.0, "rule", "none observed"),
        exposure=Feature("internal", 0.0, "rule", "none observed"),
        segment=profile.segment,
        controls={key: _false_control() for key in profile.controls},
        manual={},
    )


def _profile_for(profile: ContextProfile, scenario: str) -> ContextProfile:
    if scenario in ("threat_only", "cvss_only", "cvss_epss"):
        return _neutral_profile(profile)
    return ContextProfile(
        host_ip=profile.host_ip,
        role=(
            Feature("unknown", 1.0, "rule", "none observed")
            if scenario == "no_role"
            else profile.role
        ),
        exposure=(
            Feature("internal", 0.0, "rule", "none observed")
            if scenario == "no_exposure"
            else profile.exposure
        ),
        segment=profile.segment,
        controls=(
            {key: _false_control() for key in profile.controls}
            if scenario == "no_controls"
            else dict(profile.controls)
        ),
        manual={} if scenario == "no_manual" else dict(profile.manual),
    )


def _enrichment_for(enrichment: Enrichment | None, scenario: str) -> Enrichment | None:
    if enrichment is None:
        return None
    changes: dict[str, Any] = {}
    if scenario in ("no_epss", "context_only", "cvss_only"):
        changes.update(epss=None, epss_percentile=None)
    if scenario in ("no_kev", "context_only", "cvss_only", "cvss_epss"):
        changes.update(kev=False, kev_date_added=None)
    return replace(enrichment, **changes) if changes else enrichment


def score_scenario(settings, store, run_id: str, scenario: str) -> list[ScoreBreakdown]:
    """Recompute one scenario without writing a score row."""
    if scenario not in SCENARIOS:
        raise ConfigError(f"unknown ablation scenario {scenario!r}; expected one of {SCENARIOS}")
    profiles = {profile.host_ip: profile for profile in store.profiles(run_id)}
    if not profiles:
        raise ConfigError(f"MISSING: context profiles for run {run_id!r}")
    services = {host.ip: host.services for host in store.hosts(run_id)}
    results: list[ScoreBreakdown] = []
    enrichments = store.enrichments_for_run(run_id)
    for finding in store.findings(run_id):
        profile = profiles.get(finding.host_ip)
        if profile is None:
            raise ConfigError(
                f"MISSING: context profile for host {finding.host_ip!r} in run {run_id!r}"
            )
        enrichment = scoring.best_enrichment(enrichments.get(finding.id, []))
        results.append(
            scoring.score(
                finding,
                _enrichment_for(enrichment, scenario),
                _profile_for(profile, scenario),
                services.get(finding.host_ip, ()),
                settings.weights,
            )
        )
    return sorted(results, key=lambda item: (-item.risk, item.finding_id))


def _positions(scores: Sequence[ScoreBreakdown]) -> dict[str, float]:
    return evaluate.positions(
        evaluate.ranking_blocks({item.finding_id: item.risk for item in scores})
    )


def _comparison(
    full: Sequence[ScoreBreakdown], candidate: Sequence[ScoreBreakdown]
) -> dict[str, Any]:
    full_by_id = {item.finding_id: item for item in full}
    candidate_by_id = {item.finding_id: item for item in candidate}
    full_positions = _positions(full)
    candidate_positions = _positions(candidate)
    ids = sorted(set(full_by_id) | set(candidate_by_id))
    changed = []
    for finding_id in ids:
        before = full_by_id.get(finding_id)
        after = candidate_by_id.get(finding_id)
        if before is None or after is None:
            changed.append(
                {
                    "finding_id": finding_id,
                    "risk_before": None if before is None else before.risk,
                    "risk_after": None if after is None else after.risk,
                    "band_before": None if before is None else before.band,
                    "band_after": None if after is None else after.band,
                    "position_before": full_positions.get(finding_id),
                    "position_after": candidate_positions.get(finding_id),
                }
            )
            continue
        if (
            before.risk != after.risk
            or before.band != after.band
            or full_positions[finding_id] != candidate_positions[finding_id]
        ):
            changed.append(
                {
                    "finding_id": finding_id,
                    "host_ip": before.host_ip,
                    "risk_before": before.risk,
                    "risk_after": after.risk,
                    "risk_delta": round(after.risk - before.risk, 6),
                    "band_before": before.band,
                    "band_after": after.band,
                    "position_before": full_positions[finding_id],
                    "position_after": candidate_positions[finding_id],
                    "position_delta": candidate_positions[finding_id] - full_positions[finding_id],
                }
            )
    common = sorted(set(full_positions) & set(candidate_positions))
    tau = evaluate.kendall_tau_b(
        {key: float(full_positions[key]) for key in common},
        {key: float(candidate_positions[key]) for key in common},
    )
    return {
        "changed_findings": len(changed),
        "band_changes": sum(item.get("band_before") != item.get("band_after") for item in changed),
        "position_changes": sum(
            item.get("position_before") != item.get("position_after") for item in changed
        ),
        "kendall_tau_b_vs_full": tau,
        "inactive": not changed,
        "changes": changed,
    }


def run_ablations(
    settings,
    store,
    run_id: str,
    scenarios: Sequence[str] = SCENARIOS,
    truth: dict[str, Any] | None = None,
    cohort_ids: Sequence[str] | None = None,
    research_binding: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run the predeclared scenarios against one immutable store snapshot."""
    requested = tuple(dict.fromkeys(("full", *scenarios)))
    results = {
        scenario: score_scenario(settings, store, run_id, scenario) for scenario in requested
    }
    full = results["full"]
    all_methods = {
        scenario: [item.finding_id for item in scores] for scenario, scores in results.items()
    }
    methods = all_methods
    ranking_blocks = {
        scenario: evaluate.ranking_blocks({item.finding_id: item.risk for item in scores})
        for scenario, scores in results.items()
    }
    if cohort_ids is not None:
        selected = tuple(str(finding_id) for finding_id in cohort_ids)
        if len(selected) != len(set(selected)):
            raise ConfigError("ablation cohort contains duplicate finding IDs")
        missing = sorted(set(selected) - set(all_methods["full"]))
        if missing:
            raise ConfigError(
                f"ablation cohort finding {missing[0]!r} is not present in run {run_id!r}"
            )
        selected_set = set(selected)
        methods = {
            scenario: [finding_id for finding_id in order if finding_id in selected_set]
            for scenario, order in all_methods.items()
        }
        ranking_blocks = {
            scenario: evaluate.restrict_ranking(order, selected_set)
            for scenario, order in ranking_blocks.items()
        }
    serialized = {
        scenario: [item.to_json() for item in scores] for scenario, scores in results.items()
    }
    comparisons = {
        scenario: _comparison(full, scores)
        for scenario, scores in results.items()
        if scenario != "full"
    }
    feed_meta = {
        key: {
            "sha256": value.get("sha256"),
            "file_date": value.get("file_date"),
            "rows": value.get("rows"),
        }
        for key, value in store.feeds_meta(run_id=run_id).items()
    }
    run = store.run_info(run_id)
    if run is None:
        raise ConfigError(f"MISSING: run {run_id!r}")
    payload: dict[str, Any] = {
        "run_id": run_id,
        "config_hash_current": settings.config_hash(),
        "config_hash_at_run_start": run.get("config_hash"),
        "config_drift": settings.config_hash() != run.get("config_hash"),
        "feed_snapshot": feed_meta,
        "feed_snapshot_hash": _digest(feed_meta),
        "scenarios": serialized,
        "comparisons": comparisons,
        "orders": methods,
        "ranking_blocks": ranking_blocks,
        "inactive_scenarios": sorted(
            scenario for scenario, item in comparisons.items() if item["inactive"]
        ),
    }
    if cohort_ids is not None:
        payload["evaluation_cohort_ids"] = sorted(set(str(item) for item in cohort_ids))
    if truth is not None:
        payload["expert_evaluation"] = evaluate.evaluate(ranking_blocks, truth)
        payload["evidence_status"] = payload["expert_evaluation"]["evidence_status"]
        payload["data_kind"] = payload["expert_evaluation"]["data_kind"]
    else:
        payload["evidence_status"] = "NOT RUN"
        payload["data_kind"] = "assessment_diagnostic"
    if research_binding is not None:
        payload["research_binding"] = dict(sorted(research_binding.items()))
    payload["experiment_hash"] = _digest(payload)
    return payload


def stability_check(settings, store, run_id: str, repeats: int = 3) -> dict[str, Any]:
    """Repeat the full in-memory calculation and distinguish drift from instability."""
    if repeats < 2:
        raise ConfigError("stability check requires at least two repeats")
    hashes = []
    for _ in range(repeats):
        scores = score_scenario(settings, store, run_id, "full")
        hashes.append(_digest([item.to_json() for item in scores]))
    run = store.run_info(run_id)
    if run is None:
        raise ConfigError(f"MISSING: run {run_id!r}")
    current_config = settings.config_hash()
    return {
        "run_id": run_id,
        "repeats": repeats,
        "score_hashes": hashes,
        "unique_score_hashes": len(set(hashes)),
        "deterministic": len(set(hashes)) == 1,
        "config_hash_current": current_config,
        "config_hash_at_run_start": run.get("config_hash"),
        "config_drift": current_config != run.get("config_hash"),
        "feed_snapshot_hash": _digest(
            {
                key: {
                    "sha256": value.get("sha256"),
                    "file_date": value.get("file_date"),
                    "rows": value.get("rows"),
                }
                for key, value in store.feeds_meta(run_id=run_id).items()
            }
        ),
    }
