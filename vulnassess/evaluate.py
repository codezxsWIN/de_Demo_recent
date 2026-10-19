"""Agreement metrics between our ranking and expert rankings. Stdlib arithmetic only.

A ranking is a list of finding ids, best first. An entry may itself be a list of ids
sharing one rank.
"""

from collections import Counter
from collections.abc import Mapping
from itertools import groupby
from math import log2, sqrt
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

from vulnassess.errors import ConfigError


def _flatten(order: Sequence[Any]) -> list[str]:
    flat: list[str] = []
    for entry in order:
        if isinstance(entry, (list, tuple)):
            flat.extend(str(item) for item in entry)
        else:
            flat.append(str(entry))
    return flat


def positions(order: Sequence[Any]) -> dict[str, float]:
    """Map each id to its 1-based position; tied ids share the average of their slots."""
    result: dict[str, float] = {}
    cursor = 1
    for entry in order:
        group = [str(item) for item in entry] if isinstance(entry, (list, tuple)) else [str(entry)]
        average = (cursor + cursor + len(group) - 1) / 2.0
        for item in group:
            result[item] = average
        cursor += len(group)
    return result


def ranking_blocks(values: Mapping[str, float]) -> list[str | list[str]]:
    """Preserve equal numeric priorities as whole blocks, with stable display IDs."""
    ordered = sorted(values, key=lambda identity: (-values[identity], identity))
    result: list[str | list[str]] = []
    for _, identities in groupby(ordered, key=lambda identity: values[identity]):
        group = list(identities)
        result.append(group[0] if len(group) == 1 else group)
    return result


def restrict_ranking(order: Sequence[Any], selected: set[str]) -> list[str | list[str]]:
    """Filter to a cohort without converting score ties into invented preferences."""
    result: list[str | list[str]] = []
    for entry in order:
        group = entry if isinstance(entry, (list, tuple)) else [entry]
        included = [identity for identity in group if identity in selected]
        if included:
            result.append(included[0] if len(included) == 1 else included)
    return result


def kendall_tau_b(first: dict[str, float], second: dict[str, float]) -> float | None:
    common = sorted(set(first) & set(second))
    concordant = discordant = tied_first = tied_second = 0
    for index, left in enumerate(common):
        for right in common[index + 1 :]:
            a = first[left] - first[right]
            b = second[left] - second[right]
            if a == 0 and b == 0:
                continue
            if a == 0:
                tied_first += 1
            elif b == 0:
                tied_second += 1
            elif (a > 0) == (b > 0):
                concordant += 1
            else:
                discordant += 1
    denominator = sqrt(
        (concordant + discordant + tied_first) * (concordant + discordant + tied_second)
    )
    if denominator == 0:
        return None
    return round((concordant - discordant) / denominator, 4)


def kendall_w(rankings: Sequence[Sequence[Any]]) -> float | None:
    """Concordance across m >= 2 raters. None when a single annotator supplied the truth."""
    raters = len(rankings)
    if raters < 2:
        return None
    all_positions = [positions(order) for order in rankings]
    items = sorted(set(all_positions[0]).intersection(*[set(p) for p in all_positions[1:]]))
    count = len(items)
    if count < 2:
        return None
    sums = [sum(p[item] for p in all_positions) for item in items]
    mean = sum(sums) / count
    deviation = sum((value - mean) ** 2 for value in sums)
    tie_correction = 0
    for rater_positions in all_positions:
        groups = Counter(rater_positions[item] for item in items)
        tie_correction += sum(size**3 - size for size in groups.values() if size > 1)
    denominator = raters**2 * (count**3 - count) - raters * tie_correction
    if denominator == 0:
        return None
    return round(min(max(12 * deviation / denominator, 0.0), 1.0), 4)


def ndcg_at_k(ours: Sequence[Any], expert: Sequence[Any], k: int = 10) -> float:
    expert_positions = positions(expert)
    count = len(expert_positions)
    if count == 0:
        return 0.0

    def relevance(item: str) -> float:
        position = expert_positions.get(item)
        return 0.0 if position is None else max(count - position, 0.0)

    ideal = sorted(expert_positions, key=lambda item: expert_positions[item])[:k]
    # Expected gain across every ordering inside a score-tied block, including
    # ties crossing the cutoff. Finding IDs must not change measured usefulness.
    gain, cursor = 0.0, 0
    for entry in ours:
        group = entry if isinstance(entry, (list, tuple)) else [entry]
        if not group:
            continue
        average_gain = sum(relevance(item) for item in group) / len(group)
        gain += average_gain * sum(
            1 / log2(index + 2) for index in range(cursor, min(cursor + len(group), k))
        )
        cursor += len(group)
        if cursor >= k:
            break
    best = sum(relevance(item) / log2(index + 2) for index, item in enumerate(ideal))
    if best == 0:
        return 0.0
    return round(gain / best, 4)


def critical_queue_at_full_recall(order: Sequence[Any], critical: Iterable[str]) -> int | None:
    """How far an analyst must read before every expert-critical finding has been seen."""
    wanted = {str(item) for item in critical}
    if not wanted:
        return 0
    seen: set[str] = set()
    queue_size = 0
    for entry in order:
        group = [str(item) for item in entry] if isinstance(entry, (list, tuple)) else [str(entry)]
        queue_size += len(group)
        seen.update(wanted.intersection(group))
        if seen == wanted:
            return queue_size
    return None


def _validate_ranking(
    order: Any, label: str, *, allow_empty: bool = False, allow_ties: bool = True
) -> set[str]:
    """Validate finding identities before metrics can coerce or overwrite them."""
    if not isinstance(order, (list, tuple)) or (not order and not allow_empty):
        qualifier = "a list" if allow_empty else "a non-empty list"
        raise ConfigError(f"{label} must be {qualifier} of finding IDs")
    identities: set[str] = set()
    for entry in order:
        if isinstance(entry, (list, tuple)):
            if not allow_ties or not entry:
                raise ConfigError(f"{label} contains an invalid finding ID or empty tied rank")
            items = entry
        else:
            items = (entry,)
        for item in items:
            if not isinstance(item, str) or not item.strip():
                raise ConfigError(f"{label} finding IDs must be non-empty strings")
            if item in identities:
                raise ConfigError(f"{label} contains finding {item!r} twice")
            identities.add(item)
    return identities


def _validate_truth(payload: Any, label: str = "truth") -> dict[str, Any]:
    """Apply the same truth contract to file input and direct evaluation calls."""
    if not isinstance(payload, dict):
        raise ConfigError(f"{label}: expected a mapping at the top level")
    if "experts" not in payload:
        raise ConfigError(f"{label}: key 'experts' is required")
    experts = payload["experts"]
    if not isinstance(experts, list) or not experts:
        raise ConfigError(f"{label}: key 'experts' must be a non-empty list")
    if "expert_critical" in payload:
        _validate_ranking(
            payload["expert_critical"],
            f"{label}: expert_critical",
            allow_empty=True,
            allow_ties=False,
        )
    names: set[str] = set()
    for expert in experts:
        if not isinstance(expert, dict) or "name" not in expert or "ranking" not in expert:
            raise ConfigError(f"{label}: every expert needs 'name' and 'ranking'")
        name = expert["name"]
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"{label}: expert name must be non-empty text")
        if name.strip() in names:
            raise ConfigError(f"{label}: duplicate expert name {name!r}")
        names.add(name.strip())
        ranked = _validate_ranking(expert["ranking"], f"{label}: expert {name!r} ranking")
        if "critical" not in expert and "expert_critical" not in payload:
            raise ConfigError(
                f"{label}: provide top-level 'expert_critical' or 'critical' for every expert"
            )
        critical = _validate_ranking(
            expert.get("critical", payload.get("expert_critical")),
            f"{label}: expert {name!r} critical set",
            allow_empty=True,
            allow_ties=False,
        )
        outside = sorted(critical - ranked)
        if outside:
            raise ConfigError(
                f"{label}: expert {name!r} critical finding {outside[0]!r} is not in its ranking"
            )
        if payload.get("evidence_status") == "VERIFIED":
            if any(
                not isinstance(expert.get(field), str) or not expert[field].strip()
                for field in ("reviewer", "provenance")
            ):
                raise ConfigError(
                    f"{label}: VERIFIED expert {name!r} requires reviewer and provenance"
                )
    return payload


def load_truth(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"MISSING: truth file {path}")
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ConfigError(f"{path}: unreadable YAML ({type(error).__name__})") from error
    return _validate_truth(payload, str(path))


def evaluate(methods: Mapping[str, Sequence[Any]], truth: dict[str, Any]) -> dict[str, Any]:
    _validate_truth(truth)
    if not isinstance(methods, Mapping):
        raise ConfigError("evaluation methods must be a mapping of names to rankings")
    method_ids = {
        name: _validate_ranking(order, f"method {name!r} ranking", allow_empty=True)
        for name, order in methods.items()
    }
    experts = truth["experts"]
    expert_ids = [set(_flatten(expert["ranking"])) for expert in experts]
    same_population = all(identities == expert_ids[0] for identities in expert_ids)
    complete_methods = {
        name: same_population and identities == expert_ids[0]
        for name, identities in method_ids.items()
    }
    default_critical = truth.get("expert_critical", [])
    critical_by_expert = {
        expert["name"]: expert.get("critical", default_critical) for expert in experts
    }
    synthetic = "synthetic" in str(truth.get("_comment", "")).lower() or any(
        str(record.get(field, "")).strip().lower() == "synthetic"
        for record in (truth, *experts)
        for field in ("data_kind", "label_source")
    )
    verified = (
        not synthetic
        and truth.get("evidence_status") == "VERIFIED"
        and all(expert.get("reviewer") and expert.get("provenance") for expert in experts)
    )
    result: dict[str, Any] = {
        "experts": [expert["name"] for expert in experts],
        "evidence_status": ("NOT RUN" if synthetic else ("VERIFIED" if verified else "NOT RUN")),
        "data_kind": "synthetic" if synthetic else "human",
        "critical_sets": critical_by_expert,
    }

    concordance = kendall_w([expert["ranking"] for expert in experts])
    result["kendall_w"] = concordance
    if concordance is None:
        result["limitation"] = (
            "single-annotator study: inter-rater agreement not available"
            if len(experts) == 1
            else "inter-rater agreement not available: rankings are degenerate or incomparable"
        )

    result["methods"] = {}
    for name, order in methods.items():
        our_positions = positions(order)
        taus = {
            expert["name"]: kendall_tau_b(our_positions, positions(expert["ranking"]))
            for expert in experts
        }
        ndcgs = {expert["name"]: ndcg_at_k(order, expert["ranking"], 10) for expert in experts}
        queues = {
            expert["name"]: critical_queue_at_full_recall(order, critical_by_expert[expert["name"]])
            for expert in experts
        }
        defined_taus = [value for value in taus.values() if value is not None]
        defined_queues = [value for value in queues.values() if value is not None]
        result["methods"][name] = {
            "tau_b": taus,
            "tau_b_mean": (
                round(sum(defined_taus) / len(defined_taus), 4) if defined_taus else None
            ),
            "ndcg_at_10": ndcgs,
            "ndcg_at_10_mean": round(sum(ndcgs.values()) / len(ndcgs), 4),
            "critical_queue_by_expert": queues,
            "critical_queue": (
                round(sum(defined_queues) / len(defined_queues), 4) if defined_queues else None
            ),
            "critical_queue_defined_experts": len(defined_queues),
        }

    primary = "ours" if "ours" in methods else ("full" if "full" in methods else None)
    h2: dict[str, Any] = {
        "eligible": (
            verified
            and primary is not None
            and all(
                complete_methods.get(name, False)
                and all(value is not None for value in result["methods"][name]["tau_b"].values())
                for name in (primary, "cvss_only", "cvss_epss")
            )
        ),
        "primary_method": primary,
        "targets": {"vs_cvss_only": 0.20, "vs_cvss_epss": 0.10},
        "deltas": {},
        "passes": {},
    }
    if primary is not None:
        primary_tau = result["methods"][primary]["tau_b_mean"]
        for baseline, target in (("cvss_only", 0.20), ("cvss_epss", 0.10)):
            baseline_tau = result["methods"].get(baseline, {}).get("tau_b_mean")
            delta = (
                None
                if primary_tau is None or baseline_tau is None
                else round(primary_tau - baseline_tau, 4)
            )
            h2["deltas"][baseline] = delta
            h2["passes"][baseline] = (
                delta >= target if h2["eligible"] and delta is not None else None
            )
    result["h2"] = h2

    h3_reductions: dict[str, float | None] = {}
    if primary is not None and "cvss_only" in result["methods"]:
        primary_queues = result["methods"][primary]["critical_queue_by_expert"]
        baseline_queues = result["methods"]["cvss_only"]["critical_queue_by_expert"]
        for expert in result["experts"]:
            ours = primary_queues[expert]
            baseline = baseline_queues[expert]
            h3_reductions[expert] = (
                None
                if ours is None or baseline in (None, 0)
                else round(100 * (baseline - ours) / baseline, 4)
            )
    defined_reductions = [value for value in h3_reductions.values() if value is not None]
    h3_mean = (
        round(sum(defined_reductions) / len(defined_reductions), 4) if defined_reductions else None
    )
    h3_eligible = (
        verified
        and primary is not None
        and complete_methods.get(primary, False)
        and complete_methods.get("cvss_only", False)
        and len(defined_reductions) == len(experts)
    )
    result["h3"] = {
        "eligible": h3_eligible,
        "target_percent": 40.0,
        "reductions_percent": h3_reductions,
        "mean_reduction_percent": h3_mean,
        "defined_experts": len(defined_reductions),
        "pass": (h3_mean >= 40.0 if h3_eligible and h3_mean is not None else None),
    }
    return result


def markdown_table(result: dict[str, Any]) -> str:
    lines = []
    if result.get("kendall_w") is not None:
        lines.append(f"Kendall's W across {len(result['experts'])} experts: {result['kendall_w']}")
    else:
        lines.append(result.get("limitation", ""))
    lines.append("")
    lines.append("| Method | mean tau-b | mean NDCG@10 | critical queue |")
    lines.append("| --- | --- | --- | --- |")
    for name, scores in result.get("methods", {}).items():
        queue = "n/a" if scores["critical_queue"] is None else scores["critical_queue"]
        tau = "undefined" if scores["tau_b_mean"] is None else scores["tau_b_mean"]
        lines.append(f"| {name} | {tau} | {scores['ndcg_at_10_mean']} | {queue} |")
    return "\n".join(lines)
