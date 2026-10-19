"""Synthetic snapshots cannot partially publish or inject invalid ranking inputs."""

import gzip
import json
import sqlite3
from pathlib import Path

import pytest

from tests.test_all import WEIGHTS
from vulnassess import intel, scoring
from vulnassess.errors import ConfigError, IntelUnavailable
from vulnassess.store import Store

CVE = "CVE-2099-9999"
OLD_CVE = "CVE-2099-8888"


@pytest.fixture
def feed_dir(tmp_path):
    directory = tmp_path / "synthetic-feeds"
    (directory / "nvd").mkdir(parents=True)
    (directory / "nvd" / "synthetic_page.json").write_text(
        json.dumps({"vulnerabilities": [{"cve": {"id": CVE}}]}), encoding="utf-8"
    )
    (directory / "epss.csv").write_text(f"cve,epss,percentile\n{CVE},0.2,0.7\n", encoding="utf-8")
    (directory / "kev.json").write_text(
        json.dumps({"vulnerabilities": [{"cveID": CVE}], "dateReleased": "2099-01-01"}),
        encoding="utf-8",
    )
    return directory


@pytest.fixture
def cache(tmp_path):
    with Store(tmp_path / "synthetic-cache.db") as store:
        store.put_cves([{"id": OLD_CVE, "description": "synthetic prior snapshot"}])
        store.put_epss([(OLD_CVE, 0.1, 0.3, "2098-01-01")])
        store.put_kev([{"cveID": OLD_CVE}])
        for feed in ("nvd", "epss", "kev"):
            store.put_feed_meta(feed, "synthetic-old", "old-hash", "2098-01-01", 1)
        yield store


def cache_snapshot(cache):
    return {
        table: [
            tuple(row) for row in cache.connection.execute(f"SELECT * FROM {table} ORDER BY rowid")
        ]
        for table in ("cve", "epss", "kev", "feeds_meta")
    }


@pytest.mark.parametrize("value", ["", "   ", "-0.1", "1.1", "NaN", "Infinity", "bad-number"])
@pytest.mark.parametrize("column", ["epss", "percentile"])
def test_invalid_epss_cannot_publish_any_feed(cache, feed_dir, column, value):
    before = cache_snapshot(cache)
    fields = {"epss": "0.2", "percentile": "0.7", column: value}
    (feed_dir / "epss.csv").write_text(
        f"cve,epss,percentile\n{CVE},{fields['epss']},{fields['percentile']}\n", encoding="utf-8"
    )

    with pytest.raises(IntelUnavailable, match="EPSS"):
        intel.load_feeds(feed_dir, cache)

    assert cache_snapshot(cache) == before


def test_invalid_late_kev_leaves_all_prior_rows_and_metadata_unchanged(cache, feed_dir):
    before = cache_snapshot(cache)
    (feed_dir / "kev.json").write_text('{"vulnerabilities":', encoding="utf-8")

    with pytest.raises(IntelUnavailable, match="not valid KEV JSON"):
        intel.load_feeds(feed_dir, cache)

    assert cache_snapshot(cache) == before


@pytest.mark.parametrize(
    "relative,payload",
    [
        ("nvd/synthetic_page.json", []),
        ("nvd/synthetic_page.json", {"vulnerabilities": [None]}),
        ("kev.json", []),
        ("kev.json", {"vulnerabilities": [None]}),
    ],
)
def test_malformed_feed_shapes_are_actionable_and_atomic(cache, feed_dir, relative, payload):
    before = cache_snapshot(cache)
    (feed_dir / relative).write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(IntelUnavailable, match="JSON"):
        intel.load_feeds(feed_dir, cache)

    assert cache_snapshot(cache) == before


def test_write_failure_rolls_back_rows_and_metadata(cache, feed_dir):
    before = cache_snapshot(cache)
    cache.connection.execute(
        "CREATE TRIGGER synthetic_fail_kev BEFORE INSERT ON kev BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END"
    )

    with pytest.raises(IntelUnavailable, match="commit|store|database") as error:
        intel.load_feeds(feed_dir, cache)

    assert isinstance(error.value.__cause__, sqlite3.Error)
    assert cache_snapshot(cache) == before


def test_successful_snapshot_replaces_obsolete_intelligence_not_assessment_evidence(
    cache, feed_dir
):
    assert intel.load_feeds(feed_dir, cache) == {"nvd": 1, "epss": 1, "kev": 1}
    assert cache.cve(OLD_CVE) is None
    assert cache.epss(OLD_CVE) is None
    assert cache.kev(OLD_CVE) is None
    assert cache.cve(CVE)["id"] == CVE
    assert cache.epss(CVE)["percentile"] == 0.7
    assert cache.kev(CVE)["cveID"] == CVE


def test_compressed_epss_cannot_expand_past_its_budget(cache, feed_dir, monkeypatch):
    before = cache_snapshot(cache)
    (feed_dir / "epss.csv").unlink()
    (feed_dir / "epss.csv.gz").write_bytes(gzip.compress(b"x" * 1000))
    monkeypatch.setattr(intel, "MAX_FEED_BYTES", 128, raising=False)

    with pytest.raises(IntelUnavailable, match="limit|maximum"):
        intel.load_feeds(feed_dir, cache)

    assert cache_snapshot(cache) == before


def test_feed_snapshot_read_permission_error_is_actionable(tmp_path, monkeypatch):
    path = tmp_path / "synthetic-feed.json"
    path.write_text("{}", encoding="utf-8")
    original_open = Path.open

    def deny_one(candidate, *args, **kwargs):
        if candidate == path:
            raise PermissionError("synthetic denied")
        return original_open(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_one)
    with pytest.raises(IntelUnavailable, match="unreadable") as error:
        intel._read_snapshot(path)
    assert isinstance(error.value.__cause__, PermissionError)


def test_feed_snapshot_read_rejects_growth_past_bound(tmp_path, monkeypatch):
    path = tmp_path / "synthetic-feed.json"
    path.write_bytes(b"12345")
    monkeypatch.setattr(intel, "MAX_FEED_BYTES", 4)
    with pytest.raises(IntelUnavailable, match="maximum size limit 4"):
        intel._read_snapshot(path)


def test_corrupt_gzip_epss_is_reported_as_invalid_snapshot(tmp_path):
    path = tmp_path / "synthetic-epss.csv.gz"
    path.write_bytes(b"not a gzip stream")
    with pytest.raises(IntelUnavailable, match="not a valid EPSS snapshot"):
        intel._read_epss(path)


def test_malformed_nested_nvd_record_keeps_old_feeds_atomic(cache, feed_dir):
    before = cache_snapshot(cache)
    (feed_dir / "nvd" / "synthetic_page.json").write_text(
        json.dumps({"vulnerabilities": [{"cve": "not-an-object"}]}), encoding="utf-8"
    )
    with pytest.raises(IntelUnavailable, match="NVD JSON record data"):
        intel.load_feeds(feed_dir, cache)
    assert cache_snapshot(cache) == before


@pytest.mark.parametrize("percentile", [-0.1, 1.1, float("nan"), float("inf"), True, "0.7"])
def test_corrupt_cached_percentile_cannot_become_a_canonical_priority(percentile):
    with pytest.raises(ConfigError, match="EPSS"):
        scoring.risk(4.0, percentile, False, None, WEIGHTS, True)
