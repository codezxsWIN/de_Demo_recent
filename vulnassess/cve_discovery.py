"""Discover conditional CVE candidates from observed, versioned service CPEs.

Product/version matching is not confirmation of package identity, patch state or
exploitability. Complex environment-dependent NVD configurations stay unresolved.
"""

import json
import re
import time
from datetime import UTC, datetime
from urllib.parse import urlencode

from packaging.version import InvalidVersion, Version

from vulnassess import intel, intel_online
from vulnassess.errors import IntelUnavailable
from vulnassess.schema import EVIDENCE_MAX, Finding, Provenance

MAX_PRODUCTS = 4
MAX_RESULTS = 100
MAX_FINDINGS = 32
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")
NOTICE = "Product/version candidate only. Distribution, package revision, vendor backports, required configuration and exploitability remain unverified."


def coverage(receipt):
    if receipt.get("offline_snapshot"):
        return "not run: offline publisher snapshot selected; no public product queries or automatic candidate inventory claimed"
    queries = receipt.get("queries", [])
    skipped = receipt.get("services_skipped", [])
    partial = bool(
        receipt.get("error")
        or receipt.get("finding_budget_reached")
        or skipped
        or any(query["status"] != "complete" for query in queries)
    )
    return f"{'partial' if partial else 'complete'}: {len(queries)} observed product/version queries; skipped services: {len(skipped)}; candidate applicability only, not exploit confirmation; see cve-discovery.json for decisions and omitted identities"


def identity(service):
    if not isinstance(service.cpe, str):
        return None
    if service.cpe.startswith("cpe:2.3:"):
        if len(service.cpe.split(":")) != 13:
            return None
    elif service.cpe.startswith("cpe:/"):
        fields = service.cpe[5:].split(":")
        if len(fields) > 7 or any(field not in {"", "*", "-"} for field in fields[4:]):
            return None
    else:
        return None
    parsed = intel._to_cpe23(service.cpe)
    if not parsed or parsed[0] != "a" or not service.version:
        return None
    part, vendor, product, pinned = parsed
    if any(not re.fullmatch(r"[a-z0-9_-]{1,80}", value) for value in (vendor, product)):
        return None
    try:
        Version(service.version)
    except InvalidVersion:
        return None
    if not re.fullmatch(r"[0-9][a-zA-Z0-9._-]{0,63}", service.version):
        return None
    if pinned not in {"*", "", service.version}:
        return None
    if service.cpe.startswith("cpe:2.3:") and any(
        field not in {"*", "-"} for field in service.cpe.split(":")[6:]
    ):
        return None
    return f"cpe:2.3:{part}:{vendor}:{product}:{service.version}:*:*:*:*:*:*:*"


def matching_criteria(configurations, service):
    """Accept an independent OR product branch, never flatten AND/negated nodes."""
    if not identity(service) or not isinstance(configurations, list):
        return []

    def visit(node, depth=0):
        if (
            not isinstance(node, dict)
            or depth > 8
            or node.get("negate", False) is not False
            or node.get("operator", "OR") != "OR"
        ):
            return []
        if not isinstance(node.get("cpeMatch", []), list) or not isinstance(
            node.get("nodes", []), list
        ):
            return []
        matches = []
        for match in node.get("cpeMatch", []):
            if not isinstance(match, dict) or match.get("vulnerable") is not True:
                continue
            criteria = match.get("criteria", "")
            fields = criteria.split(":") if isinstance(criteria, str) else []
            if (
                len(fields) != 13
                or fields[:2] != ["cpe", "2.3"]
                or any(field not in {"*", "-"} for field in fields[6:])
                or not intel._same_product(service.cpe, criteria)
                or fields[5] == "-"
            ):
                continue
            # Require comparable bounds rather than the legacy numeric-prefix fallback.
            try:
                for key, value in match.items():
                    if key.startswith("version") and value:
                        Version(str(value))
                if fields[5] != "*" and fields[5] != service.version:
                    continue
                ranged = {**match, "criteria": ":".join(fields[:5] + ["*"] + fields[6:])}
                matched, _, _ = intel._in_range(service.version, ranged)
            except (InvalidVersion, TypeError, ValueError):
                continue
            if matched:
                matches.append(match)
        for child in node.get("nodes", []):
            matches.extend(visit(child, depth + 1))
        return matches

    return [match for configuration in configurations for match in visit(configuration)]


def candidate_facts(finding, service=None):
    """Validate this finding's exact identity before treating it as a candidate."""
    if isinstance(finding, Finding):
        finding = finding.to_json()
    if finding.get("tool") != "nvd-cpe":
        return None
    try:

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate candidate evidence key")
                result[key] = value
            return result

        proof = json.loads(finding["evidence"], object_pairs_hook=unique)
        if (
            proof["status"] != "product-version candidate"
            or finding["cve_ids"] != [proof["cve"]]
            or not CVE.fullmatch(proof["cve"])
            or finding["tool_native_id"] != "cpe-version:" + proof["cve"]
            or (finding["host_ip"], finding["port"], finding["protocol"])
            != (proof["target_ip"], proof["port"], proof["transport"])
            or not re.fullmatch(r"[a-f0-9]{64}", proof["nvd_record_sha256"])
        ):
            return None
        from vulnassess.schema import Service

        observed = Service.from_json(proof["service"])
        if (observed.port, observed.protocol) != (proof["port"], proof["transport"]):
            return None
        if service is not None and (
            service.port,
            service.protocol,
            service.cpe,
            service.version,
        ) != (observed.port, observed.protocol, observed.cpe, observed.version):
            return None
        if not identity(observed) or not matching_criteria(
            [{"operator": "OR", "cpeMatch": proof["matched_criteria"]}], observed
        ):
            return None
        expected_url = (
            intel_online.NVD_URL
            + "?"
            + urlencode(
                {
                    "cpeName": identity(observed),
                    "isVulnerable": "",
                    "resultsPerPage": MAX_RESULTS,
                    "startIndex": 0,
                }
            )
        )
        if (
            proof.get("source_url") != expected_url
            or finding.get("provenance", {}).get("tool") != "nvd-cpe"
        ):
            return None
        return proof
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return None


def discover(host, directory, store, *, fetch=None, sleep=time.sleep, progress=None):
    """Bound public product-only queries, retain every decision and explicit omissions."""
    fetch = fetch or intel_online.fetch_json
    now = datetime.now(UTC)
    receipt = {
        "target_ip": host.ip,
        "observed_at": now.isoformat(),
        "queries": [],
        "services_skipped": [],
        "notice": NOTICE,
    }
    metadata = store.feeds_meta() if store is not None else {}
    if (
        all(feed in metadata for feed in ("nvd", "epss", "kev"))
        and metadata["nvd"]["path"] != intel_online.NVD_URL
        and not intel.is_fixture_source(metadata["nvd"]["path"])
    ):
        # Preserve the existing deliberately loaded offline publisher snapshot.
        # Reading a local catalog must not silently become a public product lookup.
        receipt.update(
            offline_snapshot=True,
            findings_created=0,
            finding_budget_reached=False,
            notice=NOTICE
            + " Online product discovery was not attempted: an offline publisher snapshot is selected. Existing snapshot matching remains separate.",
        )
        with (directory / "cve-discovery.json").open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, indent=2)
        return [], receipt
    findings, queries, available = [], {}, []
    for service in host.services:
        cpe = identity(service)
        if cpe is None:
            receipt["services_skipped"].append(
                {
                    "port": service.port,
                    "transport": service.protocol,
                    "reason": "No unambiguous versioned application CPE; no CVE guessed from port or name",
                }
            )
            continue
        if cpe not in queries:
            if len(queries) >= MAX_PRODUCTS:
                receipt["services_skipped"].append(
                    {
                        "port": service.port,
                        "reason": "Product query budget reached; discovery coverage is partial",
                    }
                )
                continue
            if queries:
                sleep(7)
            url = (
                intel_online.NVD_URL
                + "?"
                + urlencode(
                    {
                        "cpeName": cpe,
                        "isVulnerable": "",
                        "resultsPerPage": MAX_RESULTS,
                        "startIndex": 0,
                    }
                )
            )
            query = {"cpe": cpe, "source_url": url, "status": "error", "decisions": []}
            receipt["queries"].append(query)
            queries[cpe] = query
            try:
                if progress:
                    progress(
                        "nvd",
                        "running",
                        f"Discovering candidate CVEs for observed product/version {cpe}; no target address sent",
                    )
                payload = fetch(url, 2 * 1024 * 1024)
                entries, total = payload.get("vulnerabilities"), payload.get("totalResults")
                if (
                    not isinstance(entries, list)
                    or len(entries) > MAX_RESULTS
                    or type(total) is not int
                    or total < len(entries)
                    or type(payload.get("startIndex")) is not int
                    or payload["startIndex"] != 0
                    or (total and not entries)
                ):
                    raise IntelUnavailable("NVD product query returned invalid coverage")
                records, seen = [], set()
                for entry in entries:
                    record = intel._compact_cve(entry)
                    if not CVE.fullmatch(record["id"]) or record["id"] in seen:
                        raise IntelUnavailable(
                            "NVD product query returned invalid or duplicate IDs"
                        )
                    seen.add(record["id"])
                    record["_configurations"] = entry.get("cve", entry).get("configurations", [])
                    record["_fetched_at"] = now.isoformat()
                    records.append(record)
                query.update(
                    status="complete" if total == len(entries) else "partial",
                    total_results=total,
                    returned=len(entries),
                    response_sha256=intel_online._digest(payload),
                    records=records,
                )
                available.extend(records)
            except (
                IntelUnavailable,
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                RecursionError,
            ) as error:
                query["error"] = (
                    f"Product lookup failed ({type(error).__name__}); no matches inferred"
                )
        query = queries[cpe]
        for record in query.get("records", []):
            criteria = matching_criteria(record["_configurations"], service)
            query["decisions"].append(
                {
                    "cve": record["id"],
                    "port": service.port,
                    "matched": bool(criteria),
                    "reason": "Observed product/version matches an independent NVD OR branch"
                    if criteria
                    else "No supported product/version-only applicability branch; version or environment requirements not satisfied",
                }
            )
            if not criteria or len(findings) >= MAX_FINDINGS:
                continue
            proof = {
                "status": "product-version candidate",
                "target_ip": host.ip,
                "port": service.port,
                "transport": service.protocol,
                "service": {
                    "port": service.port,
                    "protocol": service.protocol,
                    "name": (service.name or "")[:60],
                    "product": (service.product or "")[:80],
                    "version": service.version,
                    "cpe": service.cpe,
                    "tls": service.tls,
                },
                "cve": record["id"],
                "matched_criteria": criteria[:1],
                "nvd_record_sha256": intel.publisher_record_digest(record),
                "source_url": query["source_url"],
                "notice": NOTICE,
            }
            evidence = json.dumps(proof, ensure_ascii=False, separators=(",", ":"))
            if len(evidence) > EVIDENCE_MAX:
                # Optional display labels must never truncate endpoint-binding JSON.
                proof["service"].pop("name", None)
                proof["service"].pop("product", None)
                proof.pop("notice", None)
                evidence = json.dumps(proof, ensure_ascii=False, separators=(",", ":"))
            if len(evidence) > EVIDENCE_MAX:
                query["decisions"][-1].update(
                    matched=False,
                    reason="Candidate evidence exceeds the serialized evidence budget; no truncated finding created",
                )
                continue
            findings.append(
                Finding.make(
                    host_ip=host.ip,
                    port=service.port,
                    protocol=service.protocol,
                    tool="nvd-cpe",
                    tool_native_id="cpe-version:" + record["id"],
                    title=record["id"] + " · product/version applicability candidate",
                    description=NOTICE,
                    evidence=evidence,
                    cve_ids=[record["id"]],
                    reference_urls=record.get("patch_references", []),
                    native_confidence="medium",
                    provenance=Provenance(
                        "nvd-cpe",
                        str((directory / "cve-discovery.json").resolve()),
                        len(findings),
                        "live",
                    ),
                )
            )
    if available and store is not None:
        store.put_cves(available)
        with store.connection:
            intel_online._save_meta(
                store.connection,
                "nvd",
                intel_online.NVD_URL,
                available,
                now.date().isoformat(),
                now,
            )
    receipt["findings_created"] = len(findings)
    receipt["finding_budget_reached"] = len(findings) >= MAX_FINDINGS
    with (directory / "cve-discovery.json").open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
    return findings, receipt
