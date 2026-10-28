"""Bounded, read-only catalog of the union of cached publisher identifiers."""

import json
import math
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vulnassess.errors import ConfigError
from vulnassess.intel import is_fixture_source
from vulnassess.intel_status import OFFICIAL_SOURCE_URLS, SOURCES

NOTICE = (
    "Publisher reference intelligence, not evidence that a CVE affects any host. "
    "EPSS estimates exploitation probability; KEV records known exploitation. "
    "An absent cached record does not establish safety. Reading this catalog performs no network requests."
)
MAX_PAGE_SIZE = 100
MAX_OFFSET = 1_000_000
MAX_SUMMARY_JSON = 65_536
TABLES = {"nvd": ("cve", "id"), "epss": ("epss", "cve"), "kev": ("kev", "cve")}
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")


def _identifiers(source: str, search: str) -> tuple[str, list[str]]:
    # Table/column names come exclusively from this fixed mapping, never query input.
    selects, parameters = [], []
    for name, (table, column) in TABLES.items():
        if source != "all" and source != name:
            continue
        clause = ""
        if search:
            # A literal prefix range uses primary-key indexes, without LIKE wildcard semantics.
            clause = f" WHERE {column} >= ? AND {column} < ?"
            parameters.extend((search, search + "\uffff"))
        selects.append(f"SELECT {column} AS id FROM {table}{clause}")
    return " UNION ".join(selects), parameters


def _text(value: Any, limit: int = 240) -> str | None:
    return value[:limit] if isinstance(value, str) else None


def _number(value: Any, maximum: float) -> float | None:
    if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum:
        return float(value)
    return None


def _summary(raw: Any) -> tuple[dict[str, Any], bool]:
    if not isinstance(raw, str) or len(raw) > MAX_SUMMARY_JSON:
        return {}, False
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        return {}, False
    return (value, True) if isinstance(value, dict) else ({}, False)


def _record(row: sqlite3.Row, kev_checked: bool) -> dict[str, Any]:
    cve = row["id"]
    if not isinstance(cve, str) or not CVE.fullmatch(cve):
        raise ValueError("Invalid cached identifier")
    nvd, nvd_ok = _summary(row["nvd_json"])
    kev, kev_ok = _summary(row["kev_json"])
    sources = [name for name in TABLES if row[name + "_id"] is not None]
    return {
        "cve": cve,
        "sources": sources,
        "description": _text(nvd.get("description")),
        "cvss31_base": _number(row["cvss31_base"], 10),
        "cvss40_base": _number(row["cvss40_base"], 10),
        "published": _text(nvd.get("published"), 80),
        "epss": _number(row["epss"], 1),
        "epss_percentile": _number(row["percentile"], 1),
        "epss_date": _text(row["score_date"], 80),
        "kev_listed": ("kev" in sources) if kev_checked else None,
        "kev_date_added": _text(kev.get("dateAdded"), 80),
        "kev_due_date": _text(kev.get("dueDate"), 80),
        "kev_vendor": _text(kev.get("vendorProject"), 120),
        "kev_product": _text(kev.get("product"), 120),
        "kev_name": _text(kev.get("vulnerabilityName")),
        "summary_unavailable": [
            name for name, ok in (("nvd", nvd_ok), ("kev", kev_ok)) if name in sources and not ok
        ],
    }


def _provenance(name: str, meta: dict[str, Any], count: int) -> dict[str, Any]:
    path = meta.get("path")
    official = path in OFFICIAL_SOURCE_URLS[name]
    complete = type(meta.get("rows")) is int and meta["rows"] == count and count > 0
    if name == "epss" and official and path != SOURCES["epss"]:
        coverage = (
            "full daily snapshot"
            if complete
            else "daily snapshot source; stored coverage incomplete"
        )
    elif name == "kev" and official:
        coverage = "catalog snapshot"
    elif name == "nvd" and official:
        coverage = "on-demand CVE details; not full NVD coverage"
    else:
        coverage = "loaded rows only; full publisher coverage not established"
    status = "missing" if not meta or not count else "unknown"
    if meta and count:
        if not complete and name != "nvd":
            status = "incomplete"
        else:
            try:
                loaded = datetime.fromisoformat(meta["loaded_at"].replace("Z", "+00:00"))
                if loaded.tzinfo is not None:
                    age = datetime.now(UTC) - loaded
                    status = (
                        "fresh" if -timedelta(minutes=1) <= age <= timedelta(hours=24) else "stale"
                    )
            except (AttributeError, KeyError, TypeError, ValueError):
                pass
    return {
        "source_kind": "online" if official else "offline_snapshot" if path else "unknown",
        "path": path,
        "url": path if official else None,
        "publisher_date": meta.get("file_date") if name != "nvd" else None,
        "reference_date": meta.get("file_date"),
        "date_label": {
            "nvd": "Cache reference date",
            "epss": "EPSS score date",
            "kev": "KEV release date",
        }[name],
        "loaded_at": meta.get("loaded_at"),
        "sha256": meta.get("sha256"),
        "stored_rows": count,
        "declared_rows": meta.get("rows"),
        "coverage": coverage,
        "status": status,
    }


def read_catalog(
    database: Path | str,
    *,
    page: int = 1,
    page_size: int = 50,
    search: str = "",
    source: str = "all",
) -> dict[str, Any]:
    """Return one indexed ID page and its summaries, without opening a writable Store."""
    if type(page) is not int or page < 1:
        raise ConfigError("Catalog page must be a positive integer")
    if type(page_size) is not int or not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ConfigError(f"Catalog page size must be between 1 and {MAX_PAGE_SIZE}")
    if (page - 1) * page_size > MAX_OFFSET:
        raise ConfigError("Catalog page exceeds the supported offset")
    if not isinstance(source, str) or source not in {"all", *TABLES}:
        raise ConfigError("Catalog source must be all, nvd, epss or kev")
    if (
        not isinstance(search, str)
        or len(search) > 64
        or any(not 32 <= ord(c) <= 126 for c in search)
    ):
        raise ConfigError("Catalog search must be a CVE prefix of at most 64 printable characters")
    search = search.strip().upper()
    result: dict[str, Any] = {
        "state": "missing",
        "notice": NOTICE,
        "read_only": True,
        "network_requested": False,
        "search": search,
        "source": source,
        "counts": {"nvd": 0, "epss": 0, "kev": 0, "total": 0},
        "sources": {},
        "records": [],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_records": 0,
            "total_pages": 0,
            "returned": 0,
            "has_previous": False,
            "has_next": False,
        },
    }
    if not isinstance(database, Path):
        result["state"] = "not_cached"
        return result
    try:
        cache = database.with_name("intel-cache.db")
        if not cache.is_file():
            return result
        with closing(
            sqlite3.connect(cache.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
        ) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only = ON")
            db.execute("PRAGMA trusted_schema = OFF")
            db.execute("PRAGMA temp_store = MEMORY")
            db.execute("BEGIN")  # Keep counts, provenance and this page on the same snapshot.
            metadata = {
                row["feed"]: dict(row)
                for row in db.execute(
                    "SELECT * FROM feeds_meta WHERE feed IN (?, ?, ?)", tuple(TABLES)
                )
            }
            counts = {
                name: db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for name, (table, _) in TABLES.items()
            }
            all_ids, _ = _identifiers("all", "")
            counts["total"] = db.execute(f"SELECT count(*) FROM ({all_ids})").fetchone()[0]
            result["counts"] = counts
            result["sources"] = {
                name: _provenance(name, metadata.get(name, {}), counts[name]) for name in TABLES
            }
            if any(is_fixture_source(item.get("path", "")) for item in metadata.values()):
                result["state"] = "fixture"
                return result
            identifiers, parameters = _identifiers(source, search)
            total = (
                counts["total"]
                if source == "all" and not search
                else db.execute(f"SELECT count(*) FROM ({identifiers})", parameters).fetchone()[0]
            )
            rows = db.execute(
                f"""WITH selected AS (
                    {identifiers} ORDER BY id LIMIT ? OFFSET ?
                )
                SELECT selected.id, n.id AS nvd_id, e.cve AS epss_id, k.cve AS kev_id,
                    n.cvss31_base, n.cvss40_base, e.epss, e.percentile, e.score_date,
                    substr(n.json, 1, ?) AS nvd_json, substr(k.json, 1, ?) AS kev_json
                FROM selected
                LEFT JOIN cve n ON n.id = selected.id
                LEFT JOIN epss e ON e.cve = selected.id
                LEFT JOIN kev k ON k.cve = selected.id
                ORDER BY selected.id""",
                parameters
                + [page_size, (page - 1) * page_size, MAX_SUMMARY_JSON + 1, MAX_SUMMARY_JSON + 1],
            )
            kev_meta = metadata.get("kev", {})
            kev_checked = bool(
                kev_meta.get("path")
                and type(kev_meta.get("rows")) is int
                and kev_meta["rows"] == counts["kev"]
                and counts["kev"] > 0
            )
            records = [_record(row, kev_checked) for row in rows]
            result["records"] = records
            result["state"] = "cached" if counts["total"] else "empty"
            result["pagination"].update(
                total_records=total,
                total_pages=(total + page_size - 1) // page_size,
                returned=len(records),
                has_previous=page > 1 and total > 0,
                has_next=page * page_size < total,
            )
    except (OSError, sqlite3.DatabaseError, ValueError, TypeError, KeyError, OverflowError):
        result.update(
            state="unavailable",
            records=[],
            sources={},
            counts={"nvd": 0, "epss": 0, "kev": 0, "total": 0},
        )
    return result
