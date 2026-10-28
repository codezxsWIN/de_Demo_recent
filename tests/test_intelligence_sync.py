import gzip
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from vulnassess import intel_online, intel_status, intelligence_sync
from vulnassess.errors import IntelUnavailable
from vulnassess.intelligence_sync import (
    EPSS_BULK_URL,
    Snapshot,
    _approved_url,
    refresh_public_catalog,
)
from vulnassess.store import Store

NOW = datetime(2026, 10, 27, 14, tzinfo=UTC)
CVE = "CVE-2022-0543"
EPSSTEXT = f"#model_version:v2025.03.14,score_date:2026-10-27T00:00:00Z\ncve,epss,percentile\n{CVE},0.9,0.99\nCVE-2021-44228,0.8,0.98\n"


def publisher(text=EPSSTEXT, kev=None):
    catalog = (
        kev
        if kev is not None
        else {
            "count": 1,
            "dateReleased": "2026-10-26T00:00:00Z",
            "vulnerabilities": [{"cveID": CVE, "vulnerabilityName": "Redis"}],
        }
    )

    def fetch(url, limit):
        if url == EPSS_BULK_URL:
            return Snapshot(gzip.compress(text.encode()), url.replace("current", "2026-10-27"))
        return Snapshot(json.dumps(catalog).encode(), intel_online.KEV_URL)

    return fetch


def seed(cache):
    with Store(cache) as store:
        store.put_cves(
            [{"id": CVE, "description": "Retain NVD proof", "_fetched_at": NOW.isoformat()}]
        )
        store.put_epss([("CVE-2000-0001", 0.1, 0.1, "2000-01-01")])
        store.put_kev([{"cveID": "CVE-2000-0001"}])


def test_bulk_import_replaces_only_public_scores_and_preserves_provenance(tmp_path):
    cache = tmp_path / "intel-cache.db"
    seed(cache)
    result = refresh_public_catalog(cache, tmp_path / "archives", fetch=publisher(), now=NOW)
    assert result["state"] == "complete"
    assert result["counts"] == {"epss": 2, "kev": 1}
    assert result["assessment_evidence_modified"] is False
    from pathlib import Path

    directory = Path(result["archive"])
    assert (directory / "previous-cache.db").is_file()
    assert json.loads((directory / "manifest.json").read_text())["sources"][0][
        "resolved_url"
    ].endswith("epss_scores-2026-10-27.csv.gz")
    with Store(cache, read_only=True) as store:
        assert store.cve(CVE)["description"] == "Retain NVD proof"
        assert store.epss(CVE)["score_date"] == "2026-10-27"
        assert store.epss("CVE-2000-0001") is None
        assert store.kev("CVE-2000-0001") is None
        meta = store.feeds_meta()
        assert meta["epss"]["path"] == EPSS_BULK_URL
        assert meta["epss"]["rows"] == 2
    backup = sqlite3.connect(directory / "previous-cache.db")
    assert backup.execute("SELECT cve FROM epss").fetchone()[0] == "CVE-2000-0001"
    backup.close()
    detail = intel_status.read_cached_intelligence(tmp_path / "assessment.db", CVE)
    assert detail["sources"]["epss"]["url"] == EPSS_BULK_URL
    assert detail["sources"]["epss"]["source_kind"] == "online"


@pytest.mark.parametrize(
    "text",
    [
        EPSSTEXT.replace("0.9,0.99", "nan,0.99"),
        EPSSTEXT.replace("0.9,0.99", "1.1,0.99"),
        EPSSTEXT.replace(CVE, "../../secret"),
        EPSSTEXT.replace("CVE-2021-44228", CVE),
        EPSSTEXT.replace("score_date:", "unknown_date:"),
        EPSSTEXT.replace("2026-10-27", "2099-10-27"),
        EPSSTEXT.replace(CVE, ""),
        EPSSTEXT.replace("cve,epss,percentile", "cve,epss,percentile,extra"),
        EPSSTEXT.replace("0.9,0.99", "0.9,0.99,extra"),
        "cve,epss,percentile\n",
    ],
)
def test_bad_epss_does_not_change_existing_cache(tmp_path, text):
    cache = tmp_path / "intel-cache.db"
    seed(cache)
    before = cache.read_bytes()
    with pytest.raises(IntelUnavailable):
        refresh_public_catalog(cache, tmp_path / "archives", fetch=publisher(text), now=NOW)
    assert cache.read_bytes() == before


@pytest.mark.parametrize(
    "kev",
    [
        [],
        {"count": 2, "vulnerabilities": [{"cveID": CVE}]},
        {"count": 1, "vulnerabilities": [{"cveID": "bad"}]},
        {"count": 2, "vulnerabilities": [{"cveID": CVE}, {"cveID": CVE}]},
        {"count": 1, "vulnerabilities": [{"cveID": CVE}], "dateReleased": "bad"},
    ],
)
def test_bad_kev_does_not_change_epss_either(tmp_path, kev):
    cache = tmp_path / "intel-cache.db"
    seed(cache)
    before = cache.read_bytes()
    with pytest.raises(IntelUnavailable):
        refresh_public_catalog(cache, tmp_path / "archives", fetch=publisher(kev=kev), now=NOW)
    assert cache.read_bytes() == before


def test_bulk_path_does_not_refetch_fresh_requested_scores(tmp_path):
    cache = tmp_path / "intel-cache.db"
    seed(cache)
    refresh_public_catalog(cache, tmp_path / "archives", fetch=publisher(), now=NOW)
    with Store(cache) as store:
        assert intel_online.sync_cves(
            [CVE],
            store,
            now=NOW,
            fetch_json=lambda *_: pytest.fail("Fresh bulk intelligence caused a network request"),
        ) == {"nvd": 1, "epss": 1, "kev": 1}


def test_publisher_redirects_and_wrong_database_fail_closed(tmp_path):
    assert _approved_url(EPSS_BULK_URL)
    assert _approved_url(EPSS_BULK_URL.replace("current", "2026-10-27"))
    for url in [
        "http://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        "https://evil.test/epss.csv.gz",
        EPSS_BULK_URL + "?token=123",
    ]:
        assert not _approved_url(url)
    with pytest.raises(IntelUnavailable, match="isolated"):
        refresh_public_catalog(
            tmp_path / "assessment.db",
            tmp_path / "archives",
            fetch=lambda *_: pytest.fail("called"),
        )
    with pytest.raises(IntelUnavailable, match="unexpected publisher"):
        refresh_public_catalog(
            tmp_path / "intel-cache.db",
            tmp_path / "archives",
            fetch=lambda *_: Snapshot(b"", "https://evil.test"),
        )
    assert not (tmp_path / "intel-cache.db").exists()


def test_transaction_failure_rolls_back_both_feeds(tmp_path):
    cache = tmp_path / "intel-cache.db"
    seed(cache)
    with Store(cache) as store:
        store.connection.execute(
            "CREATE TRIGGER fail_kev BEFORE INSERT ON kev BEGIN SELECT RAISE(ABORT, 'test'); END"
        )
        store.connection.commit()
    with pytest.raises(sqlite3.IntegrityError):
        refresh_public_catalog(cache, tmp_path / "archives", fetch=publisher(), now=NOW)
    with Store(cache, read_only=True) as store:
        assert store.epss("CVE-2000-0001") is not None
        assert store.epss(CVE) is None
        assert store.kev("CVE-2000-0001") is not None


def test_expanded_snapshot_limit_preserves_database(tmp_path, monkeypatch):
    cache = tmp_path / "intel-cache.db"
    seed(cache)
    before = cache.read_bytes()
    monkeypatch.setattr(intelligence_sync, "MAX_EXPANDED_BYTES", 16)
    with pytest.raises(IntelUnavailable, match="decompressed size"):
        refresh_public_catalog(cache, tmp_path / "archives", fetch=publisher(), now=NOW)
    assert cache.read_bytes() == before


def test_download_limit_and_cross_publisher_redirect_are_refused(monkeypatch):
    class Response:
        url = EPSS_BULK_URL

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, limit):
            return b"x" * limit

    class Opener:
        def open(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(intelligence_sync.urllib.request, "build_opener", lambda *_: Opener())
    with pytest.raises(IntelUnavailable, match="download limit"):
        intelligence_sync.fetch_snapshot(EPSS_BULK_URL, 16)
    request = intelligence_sync.urllib.request.Request(EPSS_BULK_URL)
    with pytest.raises(IntelUnavailable, match="outside its publisher"):
        intelligence_sync._PublisherRedirect().redirect_request(
            request, None, 302, "Found", {}, intel_online.KEV_URL
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        "https://epss.empiricalsecurity.com.evil.test/epss_scores-current.csv.gz",
        "https://user@epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        EPSS_BULK_URL + "?redirect=1",
        intel_online.KEV_URL + "#fragment",
    ],
)
def test_unapproved_snapshot_url_never_opens_transport(monkeypatch, url):
    monkeypatch.setattr(
        intelligence_sync.urllib.request,
        "build_opener",
        lambda *_: pytest.fail("Unapproved URL reached the transport"),
    )
    with pytest.raises(IntelUnavailable, match="Unapproved"):
        intelligence_sync.fetch_snapshot(url, 16)


def test_redirect_allows_only_approved_paths_on_original_publisher():
    handler = intelligence_sync._PublisherRedirect()
    request = intelligence_sync.urllib.request.Request(EPSS_BULK_URL)
    dated_url = EPSS_BULK_URL.replace("current", "2026-10-27")
    redirected = handler.redirect_request(request, None, 302, "Found", {}, dated_url)
    assert redirected.full_url == dated_url
    for url in (
        "https://epss.empiricalsecurity.com/private",
        "http://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        intel_online.KEV_URL,
    ):
        with pytest.raises(IntelUnavailable, match="outside its publisher"):
            handler.redirect_request(request, None, 302, "Found", {}, url)


def test_live_catalog_maintenance_refreshes_full_expired_feed_not_just_requested_rows(tmp_path):
    cache = tmp_path / "intel-cache.db"
    refresh_public_catalog(cache, tmp_path / "archives", fetch=publisher(), now=NOW)
    with Store(cache) as store:
        result = intelligence_sync.maintain_public_catalog(
            store,
            tmp_path / "archives",
            now=NOW,
            fetch=lambda *_: pytest.fail("Fresh catalog fetched again"),
        )
        assert result["state"] == "cached"
        result = intelligence_sync.maintain_public_catalog(
            store, tmp_path / "archives", now=NOW + timedelta(hours=25), fetch=publisher()
        )
        assert result["state"] == "refreshed" and result["counts"]["epss"] == 2
        assert store.feeds_meta()["epss"]["path"] == EPSS_BULK_URL
        assert store.epss("CVE-2021-44228") is not None


def test_full_daily_snapshot_missing_new_cve_is_unknown_without_catalog_downgrade(tmp_path):
    cache = tmp_path / "intel-cache.db"
    refresh_public_catalog(cache, tmp_path / "archives", fetch=publisher(), now=NOW)
    with Store(cache) as store:
        identity = "CVE-2026-9999"
        store.put_cves([{"id": identity, "_fetched_at": NOW.isoformat()}])
        result = intel_online.sync_cves(
            [identity],
            store,
            now=NOW,
            fetch_json=lambda *_: pytest.fail(
                "Complete daily score population was downgraded to a targeted query"
            ),
        )
        assert result["epss"] == 0 and store.epss(identity) is None
        assert store.feeds_meta()["epss"]["path"] == EPSS_BULK_URL
        assert store.feeds_meta()["epss"]["rows"] == 2


def test_forced_lookup_refreshes_bulk_catalog_without_changing_its_mode(tmp_path, monkeypatch):
    cache = tmp_path / "intel-cache.db"
    refresh_public_catalog(cache, tmp_path / "archives", fetch=publisher(), now=NOW)
    maintenance = intelligence_sync.maintain_public_catalog
    monkeypatch.setattr(
        intelligence_sync,
        "maintain_public_catalog",
        lambda store, archive_root, **kwargs: maintenance(
            store, archive_root, fetch=publisher(), **kwargs
        ),
    )
    calls = []

    def nvd_only(url, _limit):
        calls.append(url)
        assert url.startswith(intel_online.NVD_URL)
        return {"vulnerabilities": [{"cve": {"id": CVE}}]}

    with Store(cache) as store:
        intel_online.sync_cves([CVE], store, now=NOW, force_refresh=True, fetch_json=nvd_only)
        assert store.feeds_meta()["epss"]["path"] == EPSS_BULK_URL
        assert store.feeds_meta()["epss"]["rows"] == 2
        assert len(calls) == 1
