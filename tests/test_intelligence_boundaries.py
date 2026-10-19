"""Publisher data must be bounded, validated and committed atomically."""

import io
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock
from urllib.error import URLError

import pytest

from vulnassess import intel_online, intel_status
from vulnassess.errors import IntelUnavailable
from vulnassess.store import Store

CVE = "CVE-2021-44228"
NOW = datetime(2026, 10, 9, tzinfo=UTC)


@pytest.mark.parametrize(
    "raw,reason",
    [(b"x" * 33, "size limit"), (b"no", "not JSON"), (b"\xff", "not JSON"), (b"[]", "wrong shape")],
)
def test_fetch_rejects_bad_publisher_responses(raw, reason, monkeypatch):
    send = Mock(return_value=io.BytesIO(raw))
    monkeypatch.setattr("urllib.request.urlopen", send)
    with pytest.raises(IntelUnavailable, match=reason):
        intel_online.fetch_json("https://example.invalid", 32)
    send.assert_called_once()
    assert send.call_args.kwargs == {"timeout": 20}


def test_fetch_success(monkeypatch):
    send = Mock(return_value=io.BytesIO(b'{"data":[]}'))
    monkeypatch.setattr("urllib.request.urlopen", send)
    assert intel_online.fetch_json("https://example.invalid", 32) == {"data": []}
    assert send.call_args.args[0].get_header("User-agent") == "vulnassess-intel/1.0"


@pytest.mark.parametrize(
    "error", [URLError("private"), TimeoutError("private"), OSError("private")]
)
def test_fetch_connection_failure_does_not_leak_details(error, monkeypatch):
    send = Mock(side_effect=error)
    monkeypatch.setattr("urllib.request.urlopen", send)
    with pytest.raises(IntelUnavailable, match="unavailable") as caught:
        intel_online.fetch_json("https://example.invalid", 32)
    assert "private" not in str(caught.value)
    send.assert_called_once()


@pytest.mark.parametrize("value", [None, "", "invalid", "2026-10-09T00:00:00"])
def test_online_freshness_rejects_unknown_or_naive_times(value):
    assert intel_online._fresh(value, NOW) is False


@pytest.mark.parametrize(
    "age,expected",
    [(timedelta(hours=24), True), (timedelta(hours=25), False), (timedelta(minutes=-2), False)],
)
def test_online_freshness_boundaries(age, expected):
    assert intel_online._fresh((NOW - age).isoformat(), NOW) is expected


def valid_feed(url, _limit):
    if url.startswith(intel_online.NVD_URL):
        return {"vulnerabilities": [{"cve": {"id": CVE}}]}
    if url.startswith(intel_online.EPSS_URL):
        return {"status": "OK", "data": [{"cve": CVE, "epss": "0.5", "percentile": "0.9"}]}
    return {"count": 1, "vulnerabilities": [{"cveID": CVE}]}


@pytest.mark.parametrize(
    "feed,payload,reason",
    [
        ("nvd", {"vulnerabilities": [None]}, "invalid CVE record"),
        ("nvd", {"vulnerabilities": [{"cve": {"id": "CVE-2020-1234"}}]}, "other than"),
        ("epss", {"status": "ERROR", "data": []}, "invalid CVE response"),
        ("epss", {"status": "OK", "data": [None]}, "unexpected CVE"),
        ("epss", {"status": "OK", "data": [{"cve": CVE}]}, "invalid score data"),
        (
            "epss",
            {"status": "OK", "data": [{"cve": CVE, "epss": "nan", "percentile": 0.5}]},
            "out-of-range",
        ),
        (
            "epss",
            {"status": "OK", "data": [{"cve": CVE, "epss": 0.5, "percentile": 2}]},
            "out-of-range",
        ),
        ("kev", {"count": 0, "vulnerabilities": []}, "invalid catalog"),
        ("kev", {"count": 1, "vulnerabilities": [{"cveID": "wrong"}]}, "invalid CVE identifier"),
    ],
)
def test_bad_refresh_preserves_prior_records_and_provenance(tmp_path, feed, payload, reason):
    urls = {"nvd": intel_online.NVD_URL, "epss": intel_online.EPSS_URL, "kev": intel_online.KEV_URL}

    def fetch(url, limit):
        return payload if url.startswith(urls[feed]) else valid_feed(url, limit)

    with Store(tmp_path / "intel-cache.db") as store:
        assert intel_online.sync_cves([CVE], store, fetch_json=valid_feed, now=NOW) == {
            "nvd": 1,
            "epss": 1,
            "kev": 1,
        }
        before = (store.feeds_meta(), store.cve(CVE), store.epss(CVE), store.kev(CVE))
        with pytest.raises(IntelUnavailable, match=reason):
            intel_online.sync_cves(
                [CVE], store, fetch_json=fetch, now=NOW + timedelta(days=1), force_refresh=True
            )
        assert (store.feeds_meta(), store.cve(CVE), store.epss(CVE), store.kev(CVE)) == before


def test_refresh_refuses_assessment_database(tmp_path):
    fetch = Mock(side_effect=AssertionError("network"))
    with Store(tmp_path / "assessment.db") as store:
        with pytest.raises(IntelUnavailable, match="isolated"):
            intel_online.sync_cves([CVE], store, fetch_json=fetch)
        assert store.feeds_meta() == {}
    fetch.assert_not_called()


def test_multiple_cves_are_throttled_and_progress_is_recorded(tmp_path, monkeypatch):
    sleep = Mock()
    monkeypatch.setattr(intel_online.time, "sleep", sleep)
    progress = Mock()

    def fetch(url, limit):
        if url.startswith(intel_online.NVD_URL):
            return {"vulnerabilities": []}
        return valid_feed(url, limit)

    with Store(tmp_path / "intel-cache.db") as store:
        assert intel_online.sync_cves(
            [CVE, "CVE-2020-1234"], store, fetch_json=fetch, now=NOW, on_progress=progress
        ) == {"nvd": 0, "epss": 1, "kev": 1}
    sleep.assert_called_once_with(7)
    assert [call.args[:2] for call in progress.call_args_list] == [
        (name, state) for state in ("running", "complete") for name in ("nvd", "epss", "kev")
    ]


@pytest.mark.parametrize("value", [None, "", "bad-date", "2026-10-09T00:00:00"])
def test_cache_freshness_handles_invalid_or_naive_timestamps(value):
    assert intel_status._fresh(value) is False


def test_cache_status_bad_database_is_unavailable(tmp_path):
    (tmp_path / "intel-cache.db").write_bytes(b"not sqlite")
    assert intel_status.read_cache_status(tmp_path / "assessment.db") == {
        "mode": "unavailable",
        "feeds": [{"feed": name, "status": "unavailable"} for name in ("nvd", "epss", "kev")],
    }


def test_string_database_does_not_open_a_cache():
    assert intel_status.read_cache_status("postgresql://unused")["mode"] == "not_cached"
