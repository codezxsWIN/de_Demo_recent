import copy
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from scripts import verify_intelligence_sources
from tests.test_assessment_report import setup_report
from tests.test_intelligence_submission import publisher
from vulnassess import cpe_match, intel_online
from vulnassess.errors import IntelUnavailable
from vulnassess.store import Store

CVE = "CVE-2022-0543"


def response():
    return {
        "startIndex": 0,
        "totalResults": 1,
        "timestamp": "2026-10-25T00:00:00Z",
        "matchStrings": [
            {
                "matchString": {
                    "matchCriteriaId": "12345678-1234-1234-1234-123456789abc",
                    "criteria": "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
                    "status": "Active",
                    "versionEndExcluding": "6.0.16",
                    "matches": [],
                }
            }
        ],
    }


def test_bounded_lookup_preserves_criteria_without_claiming_applicability():
    calls = []

    def fetch(url, limit):
        calls.append((url, limit))
        return response()

    result = cpe_match.lookup(CVE, fetch=fetch)
    assert parse_qs(urlsplit(calls[0][0]).query) == {
        "cveId": [CVE],
        "resultsPerPage": ["50"],
        "startIndex": ["0"],
    }
    assert calls[0][1] == 2 * 1024 * 1024
    assert result["coverage"] == "complete"
    assert result["records"][0]["versionEndExcluding"] == "6.0.16"
    assert len(result["response_sha256"]) == 64
    assert "No finding or score" in result["notice"]


@pytest.mark.parametrize("total,coverage", [(0, "complete"), (2, "partial")])
def test_zero_and_partial_results_are_not_host_verdicts(total, coverage):
    payload = response()
    payload["totalResults"] = total
    if not total:
        payload["matchStrings"] = []
    result = cpe_match.lookup(CVE, fetch=lambda *_: payload)
    assert result["coverage"] == coverage
    assert "target is vulnerable" in result["notice"]


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"startIndex": False, "totalResults": 0, "matchStrings": []},
        {"startIndex": 0, "totalResults": 1, "matchStrings": []},
        {"startIndex": 0, "totalResults": True, "matchStrings": []},
    ],
)
def test_invalid_coverage_rejected(payload):
    with pytest.raises(IntelUnavailable):
        cpe_match.lookup(CVE, fetch=lambda *_: payload)


@pytest.mark.parametrize(
    "field,value",
    [
        ("matchCriteriaId", "not-a-uuid"),
        ("criteria", "redis"),
        ("status", "Unknown"),
    ],
)
def test_invalid_criteria_rejected(field, value):
    payload = response()
    payload["matchStrings"][0]["matchString"][field] = value
    with pytest.raises(IntelUnavailable):
        cpe_match.lookup(CVE, fetch=lambda *_: payload)


def test_duplicate_uuid_case_variants_rejected():
    payload = response()
    second = copy.deepcopy(payload["matchStrings"][0])
    second["matchString"]["matchCriteriaId"] = second["matchString"]["matchCriteriaId"].upper()
    payload["matchStrings"].append(second)
    payload["totalResults"] = 2
    with pytest.raises(IntelUnavailable):
        cpe_match.lookup(CVE, fetch=lambda *_: payload)


def test_invalid_input_never_fetches():
    with pytest.raises(IntelUnavailable):
        cpe_match.lookup("https://other.invalid", fetch=lambda *_: pytest.fail("fetch"))


def test_cached_applicability_is_visible_read_only_without_score_changes(tmp_path):
    app, directory = setup_report(tmp_path)
    before = (directory / "case.json").read_bytes()
    path = app.database.with_name("intel-cache.db")
    with Store(path) as store:
        intel_online.sync_cves([CVE], store, fetch_json=publisher)
        original = store.cve(CVE)
        assert cpe_match.cached(store, CVE) is None
        cpe_match.save(store, CVE, cpe_match.lookup(CVE, fetch=lambda *_: response()))
        assert store.cve(CVE) == original
        assert store.connection.execute("SELECT count(*) FROM findings").fetchone()[0] == 0
    cache_before = path.read_bytes()
    data = json.loads(app.get("/api/intelligence?cve=" + CVE).body)
    assert data["record"]["cpe_match"]["returned"] == 1
    assert data["record"]["nvd"]["cvss31_base"] == 10
    assert path.read_bytes() == cache_before
    assert (directory / "case.json").read_bytes() == before
    with Store(app.database) as store, pytest.raises(IntelUnavailable, match="isolated"):
        cpe_match.save(store, CVE, {})


@pytest.mark.parametrize("unavailable", [False, True])
def test_verification_opt_in_archives_source_or_records_failure(tmp_path, monkeypatch, unavailable):
    monkeypatch.setattr(verify_intelligence_sources.time, "sleep", lambda _: None)

    def fetch(url, limit):
        if "/cpematch/" in url:
            if unavailable:
                raise IntelUnavailable("Synthetic outage")
            return response()
        return publisher(url, limit)

    directory, result = verify_intelligence_sources.verify(
        [CVE],
        tmp_path,
        fetch=fetch,
        include_cpe_matches=True,
    )
    row = result["results"][0]
    assert row["cvss31_base"] == 10
    assert row["cve_applies_to_scanned_host"] == "not evaluated"
    assert row["cpe_match_status"].startswith("unavailable" if unavailable else "complete")
    manifest = json.loads((directory / "manifest.json").read_text())
    assert len(manifest["sources"]) == (3 if unavailable else 4)
    assert result["scanner_launched"] is False
