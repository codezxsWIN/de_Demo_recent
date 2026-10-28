"""Stored counts and feed provenance in the read-only cache status."""

from vulnassess.intel_status import SOURCES, read_cache_status, read_cached_intelligence
from vulnassess.store import Store


def test_status_counts_all_stored_rows_without_changing_batch_provenance(tmp_path):
    cache = tmp_path / "intel-cache.db"
    database = tmp_path / "assessment.db"
    with Store(cache) as store:
        store.put_cves({"id": f"CVE-2026-{10000 + i}"} for i in range(22))
        store.put_epss([("CVE-2026-10000", 0.5, 0.9, "2026-10-27")])
        store.put_kev([{"cveID": "CVE-2026-10000"}, {"cveID": "CVE-2026-10001"}])
        store.put_feed_meta("nvd", SOURCES["nvd"], "a" * 64, "2026-10-27", 5)
        store.put_feed_meta("epss", "tests/fixtures/intel/epss.csv", "b" * 64, "2026-10-26", 9)
        # KEV has data but no metadata; it must still be reported as missing.
        original_meta = store.feeds_meta()

    status = read_cache_status(database)
    feeds = {feed["feed"]: feed for feed in status["feeds"]}
    assert feeds["nvd"] == {"feed": "nvd", "status": "cached", "rows": 22, "date": "2026-10-27"}
    assert feeds["epss"] == {"feed": "epss", "status": "fixture", "rows": 1, "date": "2026-10-26"}
    assert feeds["kev"] == {"feed": "kev", "status": "missing", "rows": 2, "date": None}
    assert status["mode"] == "partial_cache"
    assert read_cached_intelligence(database)["cache"] == status
    with Store(cache, read_only=True) as store:
        assert store.feeds_meta() == original_meta
        assert store.feeds_meta()["nvd"]["rows"] == 5


def test_count_does_not_make_incomplete_metadata_look_cached(tmp_path):
    with Store(tmp_path / "intel-cache.db") as store:
        store.put_cves([{"id": "CVE-2026-10000"}])
        store.put_feed_meta("nvd", SOURCES["nvd"], "c" * 64, "2026-10-27", 5)

    nvd = read_cache_status(tmp_path / "assessment.db")["feeds"][0]
    assert nvd["rows"] == 1
    assert nvd["status"] == "offline_snapshot"
