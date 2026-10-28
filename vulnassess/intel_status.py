"""Read-only provenance of the isolated public-intelligence cache."""

import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vulnassess.errors import ConfigError
from vulnassess.store import Store

SOURCES = {
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "epss": "https://api.first.org/data/v1/epss",
    "kev": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
}
OFFICIAL_SOURCE_URLS = {name: {url} for name, url in SOURCES.items()}
OFFICIAL_SOURCE_URLS["epss"].add("https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")


def read_cached_intelligence(database, cve_id=None):
    """Inspect cached publisher facts; no fetch, scan, inference or cache write."""
    if cve_id is not None and (
        not isinstance(cve_id, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve_id)
    ):
        raise ConfigError("Provide one uppercase CVE identifier")
    status = read_cache_status(database)
    result = {
        "state": "missing",
        "cache": status,
        "cve_ids": [],
        "notice": "Cached intelligence is not proof that a CVE affects the selected target. Recorded assessment scores and evidence remain unchanged.",
        "network_requested": False,
    }
    if not isinstance(database, Path) or not database.with_name("intel-cache.db").is_file():
        return result
    with Store(database.with_name("intel-cache.db"), read_only=True) as store:
        meta = store.feeds_meta()
        if any(_fixture(item.get("path", "")) for item in meta.values()):
            result["state"] = "fixture"
            return result
        result["cve_ids"] = [
            row["id"]
            for row in store.connection.execute("SELECT id FROM cve ORDER BY id LIMIT 100")
        ]
        total = store.connection.execute("SELECT count(*) FROM cve").fetchone()[0]
        result["index_truncated"] = total > len(result["cve_ids"])
        result["total_cached_cves"] = total
        result["sources"] = {
            name: {
                "url": item.get("path") if item.get("path") in OFFICIAL_SOURCE_URLS[name] else None,
                "publisher_date": item.get("file_date"),
                "loaded_at": item.get("loaded_at"),
                "sha256": item.get("sha256"),
                "source_kind": "online"
                if item.get("path") in OFFICIAL_SOURCE_URLS[name]
                else "offline_snapshot",
            }
            for name, item in meta.items()
            if name in SOURCES
        }
        if cve_id is not None:
            from vulnassess.cpe_match import cached

            cve, epss, kev = store.cve(cve_id), store.epss(cve_id), store.kev(cve_id)
            result["record"] = {
                "cve": cve_id,
                "nvd": cve,
                "epss": epss,
                "kev": kev,
                "kev_listed": kev is not None if "kev" in meta else None,
                "cpe_match": cached(store, cve_id),
            }
            result["state"] = "cached" if cve or epss or kev else "not_found"
        else:
            result["state"] = "cached" if total else "missing"
    return result


def _fixture(path: str) -> bool:
    parts = path.replace("\\", "/").lower().split("/")
    return any(
        parts[index : index + 2] in (["tests", "synthetic"], ["tests", "fixtures"])
        for index in range(len(parts) - 1)
    )


def _fresh(value: str | None) -> bool:
    if not value:
        return False
    try:
        loaded = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if loaded.tzinfo is None:
        return False
    age = datetime.now(UTC) - loaded
    return -timedelta(minutes=1) <= age <= timedelta(hours=24)


def read_cache_status(database: Path | str) -> dict[str, Any]:
    """Report what is actually stored, without contacting publishers or scanning."""
    names = ("nvd", "epss", "kev")
    unavailable = {
        "mode": "not_cached",
        "feeds": [{"feed": name, "status": "missing"} for name in names],
    }
    if not isinstance(database, Path):
        return unavailable
    cache = database.with_name("intel-cache.db")
    if not cache.is_file():
        return unavailable
    try:
        with Store(cache, read_only=True) as store:
            meta = store.feeds_meta()
            counts = {
                name: store.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for name, table in (("nvd", "cve"), ("epss", "epss"), ("kev", "kev"))
            }
    except (OSError, sqlite3.DatabaseError):
        return {
            "mode": "unavailable",
            "feeds": [{"feed": name, "status": "unavailable"} for name in names],
        }
    feeds = []
    for name in names:
        item = meta.get(name)
        status = "missing"
        if item:
            if _fixture(item["path"]):
                status = "fixture"
            elif (
                item["path"] in OFFICIAL_SOURCE_URLS[name]
                and item["rows"] > 0
                and counts[name] >= item["rows"]
            ):
                status = "cached" if _fresh(item["loaded_at"]) else "stale"
            elif item["rows"] > 0 and counts[name] > 0:
                status = "offline_snapshot"
        feeds.append(
            {
                "feed": name,
                "status": status,
                "rows": counts[name],
                "date": item["file_date"] if item else None,
            }
        )
    return {
        "mode": "on_demand_cache"
        if all(item["status"] == "cached" for item in feeds)
        else "partial_cache",
        "feeds": feeds,
    }
