"""Pure candidate-inventory comparison of two verified saved assessments.

Callers load both inputs through capture_history.load. No scanner, provider,
cache, network access or expected-CVE answer key is used here.
"""

from vulnassess.cve_discovery import candidate_facts, identity, matching_criteria
from vulnassess.schema import Service


def _inventory(record):
    payload = record["payload"]
    target = record["result"]["resolved_ip"]
    services = [
        Service.from_json(service)
        for host in payload.get("hosts", [])
        if host.get("ip") == target
        for service in host.get("services", [])
    ]
    endpoints, rows, issues = {}, {}, []
    for service in services:
        cpe = identity(service)
        if cpe:
            key = (service.protocol, service.port, ":".join(cpe.split(":")[2:5]))
            if (
                sum(
                    (item.port, item.protocol) == (service.port, service.protocol)
                    for item in services
                )
                != 1
            ):
                issues.append("Ambiguous duplicate service identity in a capture")
                endpoints[key] = None
            else:
                endpoints[key] = service
    for finding in payload.get("findings", []):
        if finding.get("tool") != "nvd-cpe":
            continue
        observed = [
            item
            for item in services
            if (item.port, item.protocol) == (finding.get("port"), finding.get("protocol"))
        ]
        proof = candidate_facts(finding, observed[0]) if len(observed) == 1 else None
        if finding.get("host_ip") != target or proof is None:
            issues.append("A candidate could not be bound to the recorded service identity")
            continue
        service = observed[0]
        cpe = identity(service)
        if cpe is None:
            issues.append("No supported product identity for this candidate")
            continue
        key = (
            service.protocol,
            service.port,
            ":".join(cpe.split(":")[2:5]),
            proof["cve"],
        )
        if key in rows:
            issues.append("Duplicate candidate association in a capture")
            rows[key].update(
                ambiguous=True,
                finding_id=None,
                priority=None,
                band=None,
                enriched=False,
                match_method=None,
                matched_criteria=[],
                nvd_record_sha256=None,
                finding_ids=sorted(set(rows[key]["finding_ids"] + [finding["id"]])),
            )
            continue
        scores = [
            item
            for item in payload.get("scores", [])
            if item.get("finding_id") == finding["id"]
            and item.get("cve_id") == proof["cve"]
            and item.get("host_ip") == target
        ]
        enrichments = [
            item
            for item in payload.get("enrichments", [])
            if item.get("finding_id") == finding["id"] and item.get("cve_id") == proof["cve"]
        ]
        score = scores[0] if len(scores) == 1 else None
        enrichment = enrichments[0] if len(enrichments) == 1 else None
        rows[key] = {
            "finding_id": finding["id"],
            "finding_ids": [finding["id"]],
            "ambiguous": False,
            "version": service.version,
            "priority": score.get("risk") if score else None,
            "band": score.get("band") if score else None,
            "enriched": enrichment is not None,
            "match_method": enrichment.get("match_method") if enrichment else None,
            "matched_criteria": proof["matched_criteria"],
            "nvd_record_sha256": proof["nvd_record_sha256"],
        }
    coverage = payload.get("scanner_coverage", {}).get("cve-discovery", "")
    if record["result"].get("scan_status") != "complete" or not coverage.startswith("complete:"):
        issues.append("Scan or product-discovery coverage is incomplete or not established")
    if not endpoints:
        issues.append("No unambiguous versioned service identity was recorded")
    source = {
        "capture_id": record["capture_id"],
        "snapshot_hash": record["snapshot_hash"],
        "target": target,
        "captured_at": record.get("captured_at"),
        "ai_status": record["result"].get("ai_status", "not_attempted"),
        "analysis_mode": "retained-evidence reanalysis"
        if record.get("analysis_source")
        else "analysis attached to this capture",
        "feeds": {
            name: {key: meta.get(key) for key in ("path", "file_date", "loaded_at")}
            for name, meta in payload.get("feeds_meta", {}).items()
        },
    }
    return rows, endpoints, issues, source


def compare(left, right):
    """Describe associations on separate endpoints; never claim remediation."""
    if left is None or right is None:
        return {
            "status": "unavailable",
            "limits": ["Two verified captures are required"],
            "rows": [],
            "sources": [],
            "counts": {"left_only": 0, "shared": 0, "right_only": 0},
        }
    before, left_endpoints, issues, left_source = _inventory(left)
    after, right_endpoints, right_issues, right_source = _inventory(right)
    issues += right_issues
    if left["capture_id"] == right["capture_id"] or left_source["target"] == right_source["target"]:
        issues.append(
            "This view requires two separate reference endpoints; it is not a same-endpoint remediation experiment"
        )
    if set(left_endpoints) != set(right_endpoints):
        issues.append("The captures do not cover the same protocol, port and product identities")
    if left_source["feeds"] != right_source["feeds"]:
        issues.append(
            "Intelligence snapshot dates, retrieval times or sources differ; inventory differences cannot be attributed solely to the version change"
        )
    if left.get("configuration_hash") != right.get("configuration_hash"):
        issues.append(
            "Assessment configuration differs; priorities are not a controlled before/after measurement"
        )
    counts = {"left_only": 0, "shared": 0, "right_only": 0}
    rows = []
    for key in sorted(set(before) | set(after)):
        change = (
            "shared"
            if key in before and key in after
            else "left_only"
            if key in before
            else "right_only"
        )
        counts[change] += 1
        right_service = right_endpoints.get(key[:3])
        range_check = None
        if (
            key in before
            and right_service is not None
            and not before[key]["ambiguous"]
            and not after.get(key, {}).get("ambiguous")
        ):
            range_check = bool(
                matching_criteria(
                    [{"operator": "OR", "cpeMatch": before[key]["matched_criteria"]}], right_service
                )
            )
        rows.append(
            {
                "protocol": key[0],
                "port": key[1],
                "product": key[2],
                "cve_id": key[3],
                "change": change,
                "left": before.get(key),
                "right": after.get(key),
                "reference_version": right_service.version if right_service else None,
                "reference_matches_left_retained_range": range_check,
            }
        )
    rows.sort(
        key=lambda row: (
            row["change"] == "shared",
            -max(
                (side.get("priority") or 0 for side in (row["left"], row["right"]) if side),
                default=0,
            ),
            row["cve_id"],
        )
    )
    return {
        "status": "limited" if issues else "comparable",
        "counts": counts,
        "rows": rows,
        "sources": [left_source, right_source],
        "limits": list(dict.fromkeys(issues))
        + [
            "Separate-endpoint candidate comparison, not proof of a completed remediation or exploitability.",
            "Priorities are copied from their captures; no score is recomputed or cross-capture risk reduction asserted.",
            "A candidate absent from a capture is not proof that the service is free of that vulnerability or of other vulnerabilities.",
        ],
    }
