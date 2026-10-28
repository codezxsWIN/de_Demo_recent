"""Explicit full EPSS/KEV snapshot refresh, isolated from assessment evidence."""

import argparse
import csv
import gzip
import io
import json
import re
import sqlite3
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from vulnassess.errors import IntelUnavailable
from vulnassess.intel import _read_epss
from vulnassess.intel_online import EPSS_BULK_URL, KEV_URL
from vulnassess.store import Store

MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")


@dataclass(frozen=True)
class Snapshot:
    raw: bytes
    resolved_url: str


def _approved_url(url: str) -> bool:
    parsed = urlsplit(url)
    return url == KEV_URL or bool(
        parsed.scheme == "https"
        and parsed.netloc == "epss.empiricalsecurity.com"
        and re.fullmatch(
            r"/epss_scores-(?:current|[0-9]{4}-[0-9]{2}-[0-9]{2})\.csv\.gz", parsed.path
        )
        and not parsed.query
        and not parsed.fragment
    )


class _PublisherRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _approved_url(newurl) or urlsplit(req.full_url).netloc != urlsplit(newurl).netloc:
            raise IntelUnavailable("Intelligence download redirected outside its publisher")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_snapshot(url: str, limit: int) -> Snapshot:
    if not _approved_url(url):
        raise IntelUnavailable("Unapproved intelligence snapshot URL")
    request = urllib.request.Request(url, headers={"User-Agent": "vulnassess-intel/1.0"})
    try:
        with urllib.request.build_opener(_PublisherRedirect()).open(
            request, timeout=45
        ) as response:
            raw = response.read(limit + 1)
            resolved = response.url
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        raise IntelUnavailable("Public intelligence snapshot download failed") from error
    if len(raw) > limit:
        raise IntelUnavailable("Public intelligence snapshot exceeded its download limit")
    if not _approved_url(resolved):
        raise IntelUnavailable("Unexpected intelligence snapshot publisher")
    return Snapshot(raw, resolved)


def _publisher_date(value: str, now: datetime, feed: str) -> str:
    try:
        published = date.fromisoformat(value[:10])
    except (ValueError, TypeError) as error:
        raise IntelUnavailable(f"{feed} snapshot has no valid publisher date") from error
    if published > now.date() + timedelta(days=1):
        raise IntelUnavailable(f"{feed} snapshot publisher date is in the future")
    return published.isoformat()


def maintain_public_catalog(
    store, archive_root: Path, *, fetch=fetch_snapshot, now=None, force=False
) -> dict[str, Any]:
    """Keep an opted-in full catalog complete when a live assessment needs it.

    Explicit offline snapshots and legacy targeted caches keep their existing
    behavior. A full EPSS catalog is never silently downgraded to targeted mode.
    """
    current = now or datetime.now(UTC)
    meta = store.feeds_meta()
    if meta.get("epss", {}).get("path") != EPSS_BULK_URL:
        return {"state": "not_configured"}
    from vulnassess.intel_online import _fresh

    for feed, table, url in (("epss", "epss", EPSS_BULK_URL), ("kev", "kev", KEV_URL)):
        item = meta.get(feed, {})
        count = store.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
        if (
            force
            or item.get("path") != url
            or not _fresh(item.get("loaded_at"), current)
            or not count
            or item.get("rows") != count
        ):
            result = refresh_public_catalog(
                Path(store.path), archive_root, fetch=fetch, now=current
            )
            return {"state": "refreshed", "counts": result["counts"], "archive": result["archive"]}
    return {"state": "cached", "counts": {feed: meta[feed]["rows"] for feed in ("epss", "kev")}}


def refresh_public_catalog(cache: Path, archive_root: Path, *, fetch=fetch_snapshot, now=None):
    """Download and validate both feeds before atomically replacing their tables.

    NVD records, finding/CVE associations and saved assessments are never modified.
    Raw snapshots, exact source URLs and hashes remain available for reproduction.
    """
    cache, archive_root = Path(cache), Path(archive_root)
    if cache.name != "intel-cache.db":
        raise IntelUnavailable("Bulk intelligence requires the isolated intel-cache.db store")
    current = now or datetime.now(UTC)
    archive_root.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="public-feeds-", dir=archive_root))
    receipt = {
        "state": "incomplete",
        "started_at": current.isoformat(),
        "cache": str(cache.resolve()),
        "sources": [],
        "assessment_evidence_modified": False,
        "nvd_coverage": "Detailed CVEs fetched on demand; not a full NVD mirror",
    }
    try:
        epss = fetch(EPSS_BULK_URL, MAX_DOWNLOAD_BYTES)
        kev = fetch(KEV_URL, 8 * 1024 * 1024)
        for name, url, snapshot in (
            ("epss.csv.gz", EPSS_BULK_URL, epss),
            ("kev.json", KEV_URL, kev),
        ):
            if len(snapshot.raw) > (
                MAX_DOWNLOAD_BYTES if name.startswith("epss") else 8 * 1024 * 1024
            ):
                raise IntelUnavailable("Intelligence snapshot exceeded its size limit")
            if not _approved_url(snapshot.resolved_url) or (
                urlsplit(url).netloc != urlsplit(snapshot.resolved_url).netloc
            ):
                raise IntelUnavailable("Intelligence snapshot came from an unexpected publisher")
            (directory / name).write_bytes(snapshot.raw)
            receipt["sources"].append(
                {
                    "url": url,
                    "resolved_url": snapshot.resolved_url,
                    "file": name,
                    "sha256": sha256(snapshot.raw).hexdigest(),
                    "bytes": len(snapshot.raw),
                }
            )
        # Bound decompression before handing the snapshot to the shared parser.
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(epss.raw)) as handle:
                expanded = handle.read(MAX_EXPANDED_BYTES + 1)
                if len(expanded) > MAX_EXPANDED_BYTES:
                    raise IntelUnavailable("EPSS snapshot exceeded its decompressed size limit")
            text = expanded.decode("utf-8-sig")
        except (OSError, EOFError, UnicodeError) as error:
            raise IntelUnavailable("EPSS snapshot is not a valid gzip file") from error
        # The offline parser tolerates missing CVE cells; a full snapshot must not
        # silently drop malformed rows or accept an unexpected CSV layout.
        lines = text.splitlines()
        if not lines or not lines[0].startswith("#"):
            raise IntelUnavailable("EPSS daily snapshot is missing its dated header")
        try:
            reader = csv.DictReader(io.StringIO("\n".join(lines[1:])), strict=True)
            if reader.fieldnames != ["cve", "epss", "percentile"]:
                raise IntelUnavailable("EPSS snapshot has an unexpected CSV schema")
            for row in reader:
                if set(row) != {"cve", "epss", "percentile"} or not row.get("cve"):
                    raise IntelUnavailable("EPSS snapshot contains an incomplete CSV row")
        except csv.Error as error:
            raise IntelUnavailable("EPSS snapshot contains malformed CSV") from error
        epss_rows, score_date = _read_epss(directory / "epss.csv.gz")
        epss_date = _publisher_date(score_date or "", current, "EPSS")
        ids = [row[0] for row in epss_rows]
        if (
            not ids
            or len(ids) > 2_000_000
            or len(set(ids)) != len(ids)
            or any(not CVE_ID.fullmatch(identity) for identity in ids)
        ):
            raise IntelUnavailable("EPSS snapshot has empty, duplicate or invalid CVE identifiers")
        try:
            payload = json.loads(kev.raw)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise IntelUnavailable("KEV snapshot is not valid JSON") from error
        records = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(records, list) or not records or payload.get("count") != len(records):
            raise IntelUnavailable("KEV snapshot has an invalid catalog count")
        kev_ids = [item.get("cveID") if isinstance(item, dict) else None for item in records]
        if any(
            not isinstance(identity, str) or not CVE_ID.fullmatch(identity) for identity in kev_ids
        ):
            raise IntelUnavailable("KEV snapshot contains invalid CVE identifiers")
        if len(set(kev_ids)) != len(kev_ids):
            raise IntelUnavailable("KEV snapshot contains duplicate CVE identifiers")
        kev_date = _publisher_date(str(payload.get("dateReleased") or ""), current, "KEV")
        with Store(cache) as store:
            with sqlite3.connect(directory / "previous-cache.db") as backup:
                store.connection.backup(backup)
            with store.connection:
                store.connection.execute("DELETE FROM epss")
                store.connection.executemany(
                    "INSERT INTO epss (cve, epss, percentile, score_date) VALUES (?, ?, ?, ?)",
                    epss_rows,
                )
                store.connection.execute("DELETE FROM kev")
                store.connection.executemany(
                    "INSERT INTO kev (cve, json) VALUES (?, ?)",
                    [(item["cveID"], json.dumps(item)) for item in records],
                )
                for feed, url, raw, published, count in (
                    ("epss", EPSS_BULK_URL, epss.raw, epss_date, len(epss_rows)),
                    ("kev", KEV_URL, kev.raw, kev_date, len(records)),
                ):
                    store.connection.execute(
                        "INSERT INTO feeds_meta (feed, path, sha256, file_date, rows, loaded_at) "
                        "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(feed) DO UPDATE SET "
                        "path=excluded.path, sha256=excluded.sha256, file_date=excluded.file_date, "
                        "rows=excluded.rows, loaded_at=excluded.loaded_at",
                        (feed, url, sha256(raw).hexdigest(), published, count, current.isoformat()),
                    )
        receipt.update(
            state="complete",
            completed_at=datetime.now(UTC).isoformat(),
            counts={"epss": len(epss_rows), "kev": len(records)},
            publisher_dates={"epss": epss_date, "kev": kev_date},
        )
    finally:
        (directory / "manifest.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return {**receipt, "archive": str(directory.resolve())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path("data/intel-cache.db"))
    parser.add_argument("--archive", type=Path, default=Path("data/intelligence"))
    args = parser.parse_args()
    try:
        print(json.dumps(refresh_public_catalog(args.cache, args.archive), indent=2))
    except (IntelUnavailable, OSError, sqlite3.DatabaseError) as error:
        parser.exit(1, f"Intelligence refresh failed: {error}\n")


if __name__ == "__main__":
    main()
