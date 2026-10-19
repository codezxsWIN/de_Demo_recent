"""Read-only provenance of the isolated public-intelligence cache."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vulnassess.store import Store

SOURCES = {
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "epss": "https://api.first.org/data/v1/epss",
    "kev": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
}


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
                item["path"] == SOURCES[name] and item["rows"] > 0 and counts[name] >= item["rows"]
            ):
                status = "cached" if _fresh(item["loaded_at"]) else "stale"
            elif item["rows"] > 0 and counts[name] > 0:
                status = "offline_snapshot"
        feeds.append(
            {
                "feed": name,
                "status": status,
                "rows": item["rows"] if item else 0,
                "date": item["file_date"] if item else None,
            }
        )
    return {
        "mode": "on_demand_cache"
        if all(item["status"] == "cached" for item in feeds)
        else "partial_cache",
        "feeds": feeds,
    }
