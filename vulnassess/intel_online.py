"""Small, explicit-CVE lookups; never a target scan or full NVD mirror."""

import json
import math
import re
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

from vulnassess.errors import IntelUnavailable
from vulnassess.intel import _compact_cve

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
MAX_CVES = 5
FRESH_FOR = timedelta(hours=24)
FetchJson = Callable[[str, int], dict[str, Any]]
Progress = Callable[[str, str, str], None]


class RequestedCache:
    """Read-only matcher view of the IDs checked by one successful targeted sync."""

    def __init__(self, store: Any, cve_ids: Iterable[str]) -> None:
        self._store = store
        self._ids = frozenset(item.strip().upper() for item in cve_ids)

    def cve(self, cve_id: str) -> dict[str, Any] | None:
        identity = cve_id.strip().upper()
        return self._store.cve(identity) if identity in self._ids else None

    def epss(self, cve_id: str) -> dict[str, Any] | None:
        identity = cve_id.strip().upper()
        return self._store.epss(identity) if identity in self._ids else None

    def kev(self, cve_id: str) -> dict[str, Any] | None:
        identity = cve_id.strip().upper()
        return self._store.kev(identity) if identity in self._ids else None

    def all_cves(self) -> list[dict[str, Any]]:
        # Point reads avoid loading or decoding any unrelated cached records.
        return [
            record for identity in sorted(self._ids) if (record := self.cve(identity)) is not None
        ]


def requested_cache(store: Any, cve_ids: Iterable[str]) -> RequestedCache:
    """After sync_cves succeeds, bound matching to a copied, normalized request set.

    This view neither establishes freshness on its own nor changes the shared cache.
    Missing requested records remain missing; full-catalog consumers can keep using store.
    """
    return RequestedCache(store, cve_ids)


def fetch_json(url: str, limit: int) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "vulnassess-intel/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(limit + 1)
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        raise IntelUnavailable("Public CVE intelligence source is unavailable") from error
    if len(raw) > limit:
        raise IntelUnavailable("Public CVE intelligence response exceeded its size limit")
    try:
        payload = json.loads(raw)
    except (UnicodeError, ValueError) as error:
        raise IntelUnavailable("Public CVE intelligence response was not JSON") from error
    if not isinstance(payload, dict):
        raise IntelUnavailable("Public CVE intelligence response has the wrong shape")
    return payload


def _fresh(value: str | None, now: datetime) -> bool:
    if not value:
        return False
    try:
        loaded = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return loaded.tzinfo is not None and -timedelta(minutes=1) <= now - loaded <= FRESH_FOR


def _digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def sync_cves(
    cve_ids: list[str],
    store,
    *,
    fetch_json: FetchJson = fetch_json,
    now: datetime | None = None,
    on_progress: Progress | None = None,
    force_refresh: bool = False,
) -> dict[str, int]:
    """Cache publisher facts for at most five scanner-named CVEs; fail before partial writes."""
    requested = sorted(set(item.strip().upper() for item in cve_ids))
    if (
        not requested
        or len(requested) > MAX_CVES
        or any(not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", item) for item in requested)
    ):
        raise IntelUnavailable("On-demand intelligence needs 1 to 5 valid scanner-named CVE IDs")
    if Path(store.path).name != "intel-cache.db":
        raise IntelUnavailable("On-demand intelligence requires the isolated intel-cache.db store")
    current = now or datetime.now(UTC)
    meta = store.feeds_meta()

    def emit(feed: str, state: str, detail: str) -> None:
        if on_progress is not None:
            on_progress(feed, state, detail)

    nvd_needed = [
        item
        for item in requested
        if force_refresh or not _fresh((store.cve(item) or {}).get("_fetched_at"), current)
    ]
    epss_meta = meta.get("epss", {})
    epss_needed = (
        force_refresh
        or epss_meta.get("path") != EPSS_URL
        or not _fresh(epss_meta.get("loaded_at"), current)
        or any(store.epss(item) is None for item in requested)
    )
    kev_meta = meta.get("kev", {})
    kev_needed = (
        force_refresh
        or kev_meta.get("path") != KEV_URL
        or not _fresh(kev_meta.get("loaded_at"), current)
    )

    nvd_records = []
    emit("nvd", "running", f"Looking up {len(nvd_needed)} uncached scanner-named CVEs at NVD")
    for index, cve_id in enumerate(nvd_needed):
        if index:
            time.sleep(7)  # NVD public no-key budget: at most five requests per 30 seconds.
        payload = fetch_json(f"{NVD_URL}?{urlencode({'cveId': cve_id})}", 2 * 1024 * 1024)
        entries = payload.get("vulnerabilities")
        if not isinstance(entries, list) or len(entries) > 1:
            raise IntelUnavailable("NVD returned an invalid targeted CVE response")
        for entry in entries:
            if not isinstance(entry, dict):
                raise IntelUnavailable("NVD returned an invalid CVE record")
            record = _compact_cve(entry)
            if record["id"] != cve_id:
                raise IntelUnavailable("NVD returned a CVE other than the requested identifier")
            record["_fetched_at"] = current.isoformat()
            nvd_records.append(record)

    epss_rows = []
    if epss_needed:
        emit("epss", "running", f"Looking up {len(requested)} CVE scores at FIRST EPSS")
        payload = fetch_json(f"{EPSS_URL}?{urlencode({'cve': ','.join(requested)})}", 128 * 1024)
        entries = payload.get("data")
        if (
            payload.get("status") != "OK"
            or not isinstance(entries, list)
            or len(entries) > len(requested)
        ):
            raise IntelUnavailable("FIRST EPSS returned an invalid CVE response")
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("cve") not in requested:
                raise IntelUnavailable("FIRST EPSS returned an unexpected CVE")
            try:
                score = float(entry["epss"])
                percentile = float(entry["percentile"])
            except (KeyError, TypeError, ValueError) as error:
                raise IntelUnavailable("FIRST EPSS returned invalid score data") from error
            if not (
                math.isfinite(score)
                and math.isfinite(percentile)
                and 0 <= score <= 1
                and 0 <= percentile <= 1
            ):
                raise IntelUnavailable("FIRST EPSS returned out-of-range score data")
            epss_rows.append((entry["cve"], score, percentile, str(entry.get("date") or "")))

    kev_records = []
    kev_date = current.date().isoformat()
    if kev_needed:
        emit("kev", "running", "Reading the CISA KEV catalog")
        payload = fetch_json(KEV_URL, 8 * 1024 * 1024)
        entries = payload.get("vulnerabilities")
        if not isinstance(entries, list) or not entries or payload.get("count") != len(entries):
            raise IntelUnavailable("CISA KEV returned an invalid catalog")
        if any(
            not isinstance(item, dict)
            or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", str(item.get("cveID", "")))
            for item in entries
        ):
            raise IntelUnavailable("CISA KEV returned an invalid CVE identifier")
        kev_records = entries
        kev_date = str(payload.get("dateReleased") or kev_date)[:10]

    # All publisher responses are checked before one atomic cache replacement.
    connection = store.connection
    with connection:
        if nvd_needed:
            connection.executemany("DELETE FROM cve WHERE id = ?", [(item,) for item in nvd_needed])
            connection.executemany(
                "INSERT INTO cve (id, json, cvss31_base, cvss40_base) VALUES (?, ?, ?, ?)",
                [
                    (item["id"], json.dumps(item), item["cvss31_base"], item["cvss40_base"])
                    for item in nvd_records
                ],
            )
            _save_meta(connection, "nvd", NVD_URL, nvd_records, current.date().isoformat(), current)
        if epss_needed:
            connection.executemany(
                "DELETE FROM epss WHERE cve = ?", [(item,) for item in requested]
            )
            connection.executemany(
                "INSERT INTO epss (cve, epss, percentile, score_date) VALUES (?, ?, ?, ?)",
                epss_rows,
            )
            score_date = max(
                (row[3] for row in epss_rows if row[3]), default=current.date().isoformat()
            )
            _save_meta(connection, "epss", EPSS_URL, epss_rows, score_date, current)
        if kev_needed:
            connection.execute("DELETE FROM kev")
            connection.executemany(
                "INSERT INTO kev (cve, json) VALUES (?, ?)",
                [(item["cveID"], json.dumps(item)) for item in kev_records],
            )
            _save_meta(connection, "kev", KEV_URL, kev_records, kev_date, current)
    result = {
        "nvd": sum(store.cve(item) is not None for item in requested),
        "epss": sum(store.epss(item) is not None for item in requested),
        "kev": sum(store.kev(item) is not None for item in requested),
    }
    for feed in ("nvd", "epss", "kev"):
        emit(
            feed,
            "complete",
            f"Checked {len(requested)} CVE IDs; {result[feed]} matched; on-demand cache, not full coverage",
        )
    return result


def _save_meta(connection, feed: str, url: str, rows: list, date: str, now: datetime) -> None:
    connection.execute(
        "INSERT INTO feeds_meta (feed, path, sha256, file_date, rows, loaded_at) VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(feed) DO UPDATE SET path=excluded.path, sha256=excluded.sha256, "
        "file_date=excluded.file_date, rows=excluded.rows, loaded_at=excluded.loaded_at",
        (feed, url, _digest(rows), date, len(rows), now.isoformat()),
    )

