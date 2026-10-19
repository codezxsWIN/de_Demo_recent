"""Compare two runs. A finding id is a fingerprint, so the same issue keeps its identity."""

from typing import Any

from vulnassess.errors import ConfigError


def diff_runs(store, before: str, after: str) -> dict[str, Any]:
    """What appeared, what went away, and what moved band between two runs."""
    for run_id in (before, after):
        if store.run_info(run_id) is None:
            raise ConfigError(f"MISSING: run {run_id!r} in the store")

    old = {finding.id: finding for finding in store.findings(before)}
    new = {finding.id: finding for finding in store.findings(after)}
    old_scores = {item.finding_id: item for item in store.scores(before)}
    new_scores = {item.finding_id: item for item in store.scores(after)}

    def describe(finding_id: str, finding) -> dict[str, Any]:
        score = new_scores.get(finding_id) or old_scores.get(finding_id)
        return {
            "finding_id": finding_id,
            "host_ip": finding.host_ip,
            "tool": finding.tool,
            "title": finding.title,
            "risk": None if score is None else score.risk,
            "band": None if score is None else score.band,
        }

    appeared = [describe(key, new[key]) for key in sorted(set(new) - set(old))]
    absent = [describe(key, old[key]) for key in sorted(set(old) - set(new))]

    moved = []
    persisting = []
    for key in sorted(set(old) & set(new)):
        entry = describe(key, new[key])
        first, second = old_scores.get(key), new_scores.get(key)
        if first is not None and second is not None and first.risk != second.risk:
            moved.append(
                {
                    **entry,
                    "risk_before": first.risk,
                    "risk_after": second.risk,
                    "band_before": first.band,
                    "band_after": second.band,
                }
            )
        else:
            persisting.append(entry)

    return {
        "before": before,
        "after": after,
        "new": appeared,
        "absent": absent,
        "resolved": absent,
        "changed": moved,
        "persisting": persisting,
        "counts": {
            "new": len(appeared),
            "absent": len(absent),
            "resolved": len(absent),
            "changed": len(moved),
            "persisting": len(persisting),
        },
        "interpretation": (
            "absent means not observed in the later run; it is not proof of remediation"
        ),
    }


def markdown_table(result: dict[str, Any]) -> str:
    counts = result["counts"]
    lines = [
        f"{result['before']} -> {result['after']}: "
        f"{counts['new']} new, {counts.get('absent', counts['resolved'])} absent, "
        f"{counts['changed']} changed, {counts['persisting']} unchanged",
        "Absent means not observed; use comparability-aware re-scan analysis before claiming a fix.",
    ]
    for label in ("new", "absent", "changed"):
        if not result[label]:
            continue
        lines.append("")
        lines.append(label.upper())
        for entry in result[label]:
            if label == "changed":
                lines.append(
                    f"  {entry['host_ip']:<15} {entry['risk_before']} -> {entry['risk_after']} "
                    f"({entry['band_before']} -> {entry['band_after']})  {entry['title']}"
                )
            else:
                risk = "-" if entry["risk"] is None else entry["risk"]
                lines.append(f"  {entry['host_ip']:<15} {risk:>6}  {entry['title']}")
    return "\n".join(lines)
