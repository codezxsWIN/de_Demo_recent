"""Bounded public-intelligence lookup for scanner-observed CVE IDs."""

from datetime import UTC, datetime

import pytest

from vulnassess import intel_online
from vulnassess.errors import IntelUnavailable
from vulnassess.store import Store


def test_on_demand_lookup_populates_real_feed_cache_and_reuses_it(tmp_path):
    calls = []
    now = datetime.now(UTC)
    cve_id = "CVE-2021-44228"

    def fetch(url, limit):
        calls.append(url)
        if "nvd.nist.gov" in url:
            return {"vulnerabilities": [{"cve": {"id": cve_id, "descriptions": [], "metrics": {}}}]}
        if "api.first.org" in url:
            return {
                "status": "OK",
                "data": [
                    {"cve": cve_id, "epss": "0.91", "percentile": "0.99", "date": "2026-09-26"}
                ],
            }
        if "cisagov/kev-data" in url:
            return {
                "count": 1,
                "dateReleased": "2026-09-26T00:00:00Z",
                "vulnerabilities": [{"cveID": cve_id, "dateAdded": "2026-09-26"}],
            }
        raise AssertionError(f"unexpected URL: {url}")

    with Store(tmp_path / "intel-cache.db") as store:
        result = intel_online.sync_cves([cve_id], store, fetch_json=fetch, now=now)
        assert result == {"nvd": 1, "epss": 1, "kev": 1}
        assert store.cve(cve_id)["id"] == cve_id
        assert store.epss(cve_id)["epss"] == 0.91
        assert store.feeds_meta()["epss"]["file_date"] == "2026-09-26"
        assert store.kev(cve_id)["cveID"] == cve_id
        assert all("tests" not in meta["path"] for meta in store.feeds_meta().values())
        assert intel_online.sync_cves([cve_id], store, fetch_json=fetch, now=now) == result
        assert len(calls) == 3
        assert (
            intel_online.sync_cves([cve_id], store, fetch_json=fetch, now=now, force_refresh=True)
            == result
        )
    assert len(calls) == 6


def test_on_demand_lookup_rejects_unbounded_or_invalid_ids_before_network(tmp_path):
    with Store(tmp_path / "intel-cache.db") as store:
        for ids in (["not-a-cve"], [f"CVE-2026-{1000 + index}" for index in range(6)]):
            with pytest.raises(IntelUnavailable):
                intel_online.sync_cves(
                    ids,
                    store,
                    fetch_json=lambda *_: (_ for _ in ()).throw(AssertionError("network called")),
                )


def test_failed_publisher_response_does_not_mark_cache_loaded(tmp_path):
    with Store(tmp_path / "intel-cache.db") as store:
        with pytest.raises(IntelUnavailable):
            intel_online.sync_cves(
                ["CVE-2021-44228"], store, fetch_json=lambda *_: {"unexpected": "shape"}
            )
        assert store.feeds_meta() == {}


def test_refresh_removes_stale_positive_matches(tmp_path):
    cve_id = "CVE-2021-44228"
    first = datetime.now(UTC)

    def initial(url, limit):
        if "nvd.nist.gov" in url:
            return {"vulnerabilities": [{"cve": {"id": cve_id}}]}
        if "api.first.org" in url:
            return {
                "status": "OK",
                "data": [
                    {
                        "cve": cve_id,
                        "epss": "0.8",
                        "percentile": "0.9",
                        "date": first.date().isoformat(),
                    }
                ],
            }
        return {
            "count": 1,
            "dateReleased": first.isoformat(),
            "vulnerabilities": [{"cveID": cve_id}],
        }

    def refreshed(url, limit):
        if "nvd.nist.gov" in url:
            return {"vulnerabilities": []}
        if "api.first.org" in url:
            return {"status": "OK", "data": []}
        return {
            "count": 1,
            "dateReleased": first.isoformat(),
            "vulnerabilities": [{"cveID": "CVE-2026-9999"}],
        }

    with Store(tmp_path / "intel-cache.db") as store:
        assert intel_online.sync_cves([cve_id], store, fetch_json=initial, now=first) == {
            "nvd": 1,
            "epss": 1,
            "kev": 1,
        }
        assert intel_online.sync_cves(
            [cve_id],
            store,
            fetch_json=refreshed,
            now=first + intel_online.FRESH_FOR + intel_online.timedelta(minutes=1),
        ) == {"nvd": 0, "epss": 0, "kev": 0}
