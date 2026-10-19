from copy import deepcopy

from vulnassess.live_assessment import assessment_summary


def payload():
    return {
        "findings": [
            {
                "id": "f1",
                "title": "Redis Lua configuration",
                "tool": "redis-check",
                "port": 6379,
                "evidence": "Fixed inspection returned table:function",
                "provenance": {"raw_path": "redis-lua-check.json"},
                "cve_ids": ["CVE-2022-0543"],
            }
        ],
        "scores": [
            {"finding_id": "f1", "cve_id": "CVE-2022-0543", "risk": 100, "band": "Critical"}
        ],
        "enrichments": [
            {
                "finding_id": "f1",
                "cve_id": "CVE-2022-0543",
                "cvss31_base": 10.0,
                "epss": 0.99351,
                "kev": True,
                "feed_dates": {"nvd": "2026-09-29", "epss": "2026-09-29", "kev": "2026-09-29"},
            }
        ],
        "feed_status": ["nvd", "epss", "kev"],
        "context": [],
    }


def summary(data):
    return assessment_summary("http://pentest-ground.com:6379/", "178.79.134.182", [], data)


def test_confirmed_cve_display_joins_evidence_intelligence_and_canonical_score():
    data = payload()
    original = deepcopy(data)
    row = summary(data)["cve_evidence"][0]
    assert row["cve_id"] == "CVE-2022-0543"
    assert row["evidence"] == data["findings"][0]["evidence"]
    assert row["raw_path"] == "redis-lua-check.json"
    assert row["cvss_base"] == 10.0
    assert row["epss"] == 0.99351
    assert row["kev_status"] == "listed"
    assert row["priority"] == {"risk": 100, "band": "Critical"}
    assert row["feed_dates"]["epss"] == "2026-09-29"
    assert data == original


def test_missing_lookup_is_unknown_not_a_negative_result():
    data = payload()
    data["enrichments"] = []
    data["feed_status"] = []
    row = summary(data)["cve_evidence"][0]
    assert row["cvss_base"] is None
    assert row["epss"] is None
    assert row["kev_status"] == "not_checked"


def test_checked_kev_nonmembership_is_distinct_from_not_checked():
    data = payload()
    data["enrichments"][0]["kev"] = False
    assert summary(data)["cve_evidence"][0]["kev_status"] == "not_listed"


def test_unknown_enrichment_identifiers_do_not_create_displayed_cves():
    data = payload()
    data["enrichments"].append({"finding_id": "f1", "cve_id": "CVE-2099-9999"})
    assert [row["cve_id"] for row in summary(data)["cve_evidence"]] == ["CVE-2022-0543"]


def test_no_findings_means_no_cve_cards():
    data = payload()
    data["findings"] = []
    data["scores"] = []
    data["enrichments"] = []
    result = summary(data)
    assert result["cve_evidence"] == []
    assert result["priorities"] == []
    assert result["intelligence"]["matched_findings"] == 0
