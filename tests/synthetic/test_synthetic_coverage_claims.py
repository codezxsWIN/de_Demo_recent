"""Summary wording cannot invent scan coverage or completed deterministic scoring."""

from copy import deepcopy

import pytest

from vulnassess.errors import ConfigError
from vulnassess.live_assessment import assessment_summary


def case():
    return {"findings": [], "scores": [], "enrichments": [], "context": []}


def summarize(payload):
    return assessment_summary("synthetic.invalid", "172.28.0.10", [], payload)


@pytest.mark.parametrize("status", ["missing", None])
def test_missing_collection_status_is_unknown_not_implicitly_complete(status):
    payload = case()
    if status != "missing":
        payload["scan_status"] = status
    result = summarize(payload)
    assert result["scan_status"] == "unknown"


@pytest.mark.parametrize("status", [True, False, 0, "failed", "", [], {}])
def test_invalid_collection_status_cannot_be_published_as_a_summary(status):
    payload = {**case(), "scan_status": status}
    with pytest.raises(ConfigError, match="collection status"):
        summarize(payload)


@pytest.mark.parametrize("status", ["complete", "partial"])
def test_explicit_supported_collection_status_is_preserved(status):
    assert summarize({**case(), "scan_status": status})["scan_status"] == status


@pytest.mark.parametrize("coverage", [None, {}, {"nmap": None}, {"nmap": False}, {"nmap": []}])
def test_missing_nmap_coverage_is_unknown_not_a_claimed_top_100_scan(coverage):
    payload = case()
    if coverage is not None:
        payload["scanner_coverage"] = coverage
    result = summarize(payload)
    gaps = " ".join(result["coverage_gaps"])
    assert "100" not in gaps and "light service detection" not in gaps
    assert "Nmap coverage was not recorded" in gaps
    assert "Nikto coverage was not recorded" in gaps
    assert "Nessus coverage was not recorded" in gaps
    assert "No Nessus report was imported" not in gaps


def test_recorded_coverage_is_repeated_without_inventing_a_different_profile():
    payload = case()
    payload["scanner_coverage"] = {
        "nmap": "SYNTHETIC full 65535-port TCP profile",
        "nikto": "skipped: SYNTHETIC no HTTP service",
        "nessus": "complete: SYNTHETIC report import, not a live scan",
    }
    original = deepcopy(payload)
    result = summarize(payload)
    gaps = " ".join(result["coverage_gaps"])
    assert payload["scanner_coverage"]["nmap"] in gaps
    assert payload["scanner_coverage"]["nessus"] in gaps
    assert "100 TCP ports" not in gaps and "light service detection" not in gaps
    assert "No Nessus report was imported" not in gaps
    assert payload == original


def test_explicit_live_noncoverage_is_retained_as_noncoverage():
    payload = case()
    payload["scanner_coverage"] = {
        "nmap": "top 100 TCP ports; explicit TCP/8080 check failed",
        "nikto": "failed: SYNTHETIC missing Perl dependency",
        "nessus": "no .nessus report imported; no Nessus scan claimed",
    }
    result = summarize(payload)
    gaps = " ".join(result["coverage_gaps"])
    for value in payload["scanner_coverage"].values():
        assert value in gaps
    assert result["scanner_coverage"] == payload["scanner_coverage"]


@pytest.mark.parametrize("count", [0, 1, 2])
def test_findings_without_scores_do_not_become_completed_priorities(count):
    payload = case()
    payload["findings"] = [{"id": "synthetic-a"}, {"id": "synthetic-b"}]
    payload["scores"] = [
        {"finding_id": identity, "risk": 30.0, "band": "Low"}
        for identity in ("synthetic-a", "synthetic-b")[:count]
    ]
    result = summarize(payload)
    assert result["scored_finding_count"] == count
    assert result["unscored_finding_count"] == 2 - count
    if count < 2:
        assert "2 scanner findings have deterministic priorities" not in result["conclusion"]
        assert (
            "unscored" in result["conclusion"]
            or "no deterministic priorities" in result["conclusion"]
        )
    else:
        assert "2 scanner findings have deterministic priorities" in result["conclusion"]


@pytest.mark.parametrize(
    "damage",
    [
        "orphan",
        "duplicate",
        "wrong-host",
        "nan",
        "boolean",
        "missing-band",
        "unknown-band",
        "large-int",
    ],
)
def test_an_unsupported_score_record_cannot_be_published_as_a_priority(damage):
    payload = case()
    payload["findings"] = [{"id": "synthetic-a"}]
    score = {"finding_id": "synthetic-a", "risk": 30.0, "band": "Low"}
    payload["scores"] = [score]
    if damage == "orphan":
        score["finding_id"] = "synthetic-not-in-findings"
    elif damage == "duplicate":
        payload["scores"].append(dict(score))
    elif damage == "wrong-host":
        score["host_ip"] = "192.0.2.1"
    elif damage == "nan":
        score["risk"] = float("nan")
    elif damage == "boolean":
        score["risk"] = True
    elif damage == "missing-band":
        del score["band"]
    elif damage == "unknown-band":
        score["band"] = "synthetic-unrecognized-band"
    else:
        score["risk"] = 10**400
    with pytest.raises(ConfigError, match="score|priority"):
        summarize(payload)


def test_an_orphaned_enrichment_does_not_inflate_the_enriched_finding_count():
    payload = case()
    payload["enrichments"] = [{"finding_id": "synthetic-not-in-findings"}]
    with pytest.raises(ConfigError, match="enrichment"):
        summarize(payload)


@pytest.mark.parametrize(
    "findings", [None, [None], [{}], [{"id": []}], [{"id": ""}], [{"id": "a"}, {"id": "a"}]]
)
def test_invalid_finding_identities_cannot_create_a_completed_summary(findings):
    payload = case()
    payload["findings"] = findings
    with pytest.raises(ConfigError, match="finding"):
        summarize(payload)
