"""Bounded NVD CPE Match applicability evidence, separate from CVE detection."""

import json
import re
from datetime import UTC, datetime
from hashlib import sha256
from urllib.parse import urlencode
from uuid import UUID

from vulnassess import intel_online
from vulnassess.errors import IntelUnavailable

URL = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
PAGE_LIMIT = 50


def lookup(cve_id, *, fetch=intel_online.fetch_json):
    if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve_id):
        raise IntelUnavailable("CPE Match lookup requires one CVE identifier")
    url = URL + "?" + urlencode({"cveId": cve_id, "resultsPerPage": PAGE_LIMIT, "startIndex": 0})
    payload = fetch(url, 2 * 1024 * 1024)
    if not isinstance(payload, dict):
        raise IntelUnavailable("NVD CPE Match response must be an object")
    rows, total = payload.get("matchStrings"), payload.get("totalResults")
    if (
        not isinstance(rows, list)
        or len(rows) > PAGE_LIMIT
        or type(total) is not int
        or total < len(rows)
        or type(payload.get("startIndex")) is not int
        or payload["startIndex"] != 0
        or (total > 0 and not rows)
    ):
        raise IntelUnavailable("NVD CPE Match response has invalid coverage")
    records, seen = [], set()
    for row in rows:
        item = row.get("matchString") if isinstance(row, dict) else None
        if not isinstance(item, dict):
            raise IntelUnavailable("NVD CPE Match response has an invalid record")
        identity, criteria = item.get("matchCriteriaId"), item.get("criteria")
        try:
            normalized_id = str(UUID(identity))
        except (ValueError, TypeError, AttributeError) as error:
            raise IntelUnavailable("NVD CPE Match identifier is invalid") from error
        if (
            normalized_id in seen
            or not isinstance(criteria, str)
            or not criteria.startswith("cpe:2.3:")
            or len(criteria) > 1024
            or item.get("status") not in {"Active", "Inactive"}
        ):
            raise IntelUnavailable("NVD CPE Match criteria or status is invalid")
        seen.add(normalized_id)
        records.append(item)
    return {
        "cve": cve_id,
        "source_url": url,
        "fetched_at": datetime.now(UTC).isoformat(),
        "publisher_timestamp": payload.get("timestamp"),
        "records": records,
        "returned": len(records),
        "total_results": total,
        "coverage": "complete" if len(records) == total else "partial",
        "response_sha256": sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=True).encode()
        ).hexdigest(),
        "notice": "Applicability criteria only. Active does not mean the target is vulnerable. CVE configuration logic, OS/package revisions, patch state and observed product identity still require verification. No finding or score is created.",
    }


def save(store, cve_id, evidence):
    if store.path.name != "intel-cache.db":
        raise IntelUnavailable("CPE Match writes are restricted to the isolated intelligence cache")
    if store.cve(cve_id) is None or evidence.get("cve") != cve_id:
        raise IntelUnavailable("CPE Match evidence requires its corresponding cached NVD CVE")
    with store.connection:
        store.connection.execute(
            "CREATE TABLE IF NOT EXISTS cpe_match_evidence (cve TEXT PRIMARY KEY, json TEXT NOT NULL)"
        )
        store.connection.execute(
            "INSERT INTO cpe_match_evidence(cve,json) VALUES (?,?) ON CONFLICT(cve) DO UPDATE SET json=excluded.json",
            (cve_id, json.dumps(evidence, ensure_ascii=True)),
        )


def cached(store, cve_id):
    exists = store.connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cpe_match_evidence'"
    ).fetchone()
    if not exists:
        return None
    row = store.connection.execute(
        "SELECT json FROM cpe_match_evidence WHERE cve=?", (cve_id,)
    ).fetchone()
    return json.loads(row["json"]) if row else None
