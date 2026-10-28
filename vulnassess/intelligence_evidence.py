"""Freeze the exact publisher records read for one assessment, without fetching."""

import json
import re
from datetime import UTC, datetime
from hashlib import sha256

from vulnassess.errors import IntelUnavailable

MAX_RECORDS = 128
MAX_BYTES = 2 * 1024 * 1024


def digest(value):
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def freeze(store, findings, enrichments, feeds):
    """Bind each referenced CVE to its scan finding and retained source values.

    This freezes reference data, not a new applicability or exploitation verdict.
    Matching decisions and priorities remain the canonical pipeline's outputs.
    """
    ids = sorted({identity for finding in findings for identity in finding.cve_ids})
    ids = sorted(set(ids) | {item.cve_id for item in enrichments})
    if len(ids) > MAX_RECORDS:
        raise IntelUnavailable("Assessment intelligence evidence exceeds its CVE budget")
    rows = []
    for identity in ids:
        facts = {
            "nvd": store.cve(identity),
            "epss": store.epss(identity),
            "kev": store.kev(identity),
        }
        rows.append(
            {
                "cve": identity,
                "finding_ids": sorted(
                    {finding.id for finding in findings if identity in finding.cve_ids}
                    | {item.finding_id for item in enrichments if item.cve_id == identity}
                ),
                "matched_finding_ids": sorted(
                    {item.finding_id for item in enrichments if item.cve_id == identity}
                ),
                "records": facts,
                "record_sha256": {
                    name: digest(value) if value is not None else None
                    for name, value in facts.items()
                },
                "kev_listed": facts["kev"] is not None if "kev" in feeds else None,
                "nvd_fetched_at": (facts["nvd"] or {}).get("_fetched_at"),
            }
        )
    body = {
        "schema_version": 1,
        "state": "recorded",
        "recorded_at": datetime.now(UTC).isoformat(),
        "sources": feeds,
        "records": rows,
        "notice": "Publisher reference records used by this assessment. CVE association does not confirm installed package applicability or exploitability. These records do not change when the shared intelligence cache refreshes.",
    }
    if len(json.dumps(body, ensure_ascii=True).encode()) > MAX_BYTES:
        raise IntelUnavailable("Assessment intelligence evidence exceeds its byte budget")
    return {**body, "sha256": digest(body)}


def verify(snapshot, *, findings=None, enrichments=None, feeds=None):
    if not isinstance(snapshot, dict) or snapshot.get("state") != "recorded":
        raise IntelUnavailable("No recorded assessment intelligence evidence")
    body = {key: value for key, value in snapshot.items() if key != "sha256"}
    if snapshot.get("sha256") != digest(body):
        raise IntelUnavailable("Assessment intelligence evidence hash mismatch")
    rows = snapshot.get("records")
    if snapshot.get("schema_version") != 1 or not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise IntelUnavailable("Invalid assessment intelligence evidence schema")
    if not isinstance(snapshot.get("sources"), dict):
        raise IntelUnavailable("Assessment intelligence sources are invalid")
    identities = set()
    if feeds is not None and snapshot.get("sources") != feeds:
        raise IntelUnavailable("Assessment publisher sources differ from retained feeds")
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("cve"), str)
            or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", row["cve"])
            or row["cve"] in identities
        ):
            raise IntelUnavailable("Invalid or duplicate assessment intelligence identifier")
        identities.add(row["cve"])
        if not isinstance(row.get("records"), dict) or set(row["records"]) != {
            "nvd",
            "epss",
            "kev",
        }:
            raise IntelUnavailable("Assessment intelligence record sources are invalid")
        if not isinstance(row.get("record_sha256"), dict):
            raise IntelUnavailable("Assessment publisher record hashes are invalid")
        for field in ("finding_ids", "matched_finding_ids"):
            if (
                not isinstance(row.get(field), list)
                or any(not isinstance(item, str) for item in row[field])
                or len(set(row[field])) != len(row[field])
            ):
                raise IntelUnavailable("Assessment intelligence finding references are invalid")
        if findings is not None and enrichments is not None:
            linked = {item["id"] for item in findings if row["cve"] in item.get("cve_ids", [])}
            matched = {item["finding_id"] for item in enrichments if item["cve_id"] == row["cve"]}
            if (
                set(row["finding_ids"]) != linked | matched
                or set(row["matched_finding_ids"]) != matched
            ):
                raise IntelUnavailable("Assessment intelligence is not bound to its findings")
        for source, value in row["records"].items():
            if value is not None and not isinstance(value, dict):
                raise IntelUnavailable("Assessment publisher record is not an object")
            expected = digest(value) if value is not None else None
            if row["record_sha256"].get(source) != expected:
                raise IntelUnavailable("Assessment publisher record hash mismatch")
            if value is not None:
                identity = (
                    value.get("id")
                    if source == "nvd"
                    else value.get("cve")
                    if source == "epss"
                    else value.get("cveID")
                )
                if identity != row["cve"]:
                    raise IntelUnavailable("Assessment publisher record has a different CVE")
        if enrichments is not None:
            nvd, epss = row["records"]["nvd"] or {}, row["records"]["epss"] or {}
            expected = {
                **{
                    key: nvd.get(key)
                    for key in ("cvss31_base", "cvss31_vector", "cvss40_base", "cvss40_vector")
                },
                "epss": epss.get("epss"),
                "epss_percentile": epss.get("percentile"),
                "kev": row["records"]["kev"] is not None,
            }
            for item in enrichments:
                if item["cve_id"] == row["cve"] and any(
                    item.get(key) != value for key, value in expected.items()
                ):
                    raise IntelUnavailable(
                        "Assessment enrichment contradicts its retained publisher records"
                    )
    if findings is not None and enrichments is not None:
        expected_ids = {
            identity for finding in findings for identity in finding.get("cve_ids", [])
        } | {item["cve_id"] for item in enrichments}
        if identities != expected_ids:
            raise IntelUnavailable("Assessment intelligence evidence has incomplete CVE coverage")
