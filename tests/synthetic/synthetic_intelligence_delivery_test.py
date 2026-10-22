"""Synthetic delivery checks only; no publisher, scanner, model or database evidence."""

from copy import deepcopy
from typing import Any

import pytest

from tests.test_all import (
    WEIGHTS,
    make_enrichment,
    make_finding,
    make_host,
    make_profile,
    service,
)
from vulnassess import analyst, report, scoring
from vulnassess.errors import ConfigError
from vulnassess.ui import assessment_report, vulnerability_findings

HOST = "172.28.0.10"
CVE = "CVE-2099-1001"
ADVISORY = "https://vendor.example.invalid/security/synthetic-advisory"


def synthetic_payload(*, cve: bool = True, cpe_match: bool = False) -> dict[str, Any]:
    finding = make_finding(
        host_ip=HOST,
        tool="nmap" if cve else "harbordesk",
        tool_native_id="synthetic-delivery",
        title="SYNTHETIC intelligence delivery observation",
        description="SYNTHETIC pure-logic finding, not scanner evidence.",
        evidence="SYNTHETIC observation for intelligence delivery tests.",
        cve_ids=[CVE] if cve and not cpe_match else [],
        cwe_ids=["CWE-89"],
        native_severity="High" if not cve else None,
    )
    host = make_host(
        ip=HOST,
        items=(service(80, "http", "SYNTHETIC service observation"),),
    )
    profile = make_profile(host_ip=HOST)
    enrichment = (
        make_enrichment(
            finding_id=finding.id,
            cve_id=CVE,
            match_method="cpe_range" if cpe_match else "explicit",
            description="SYNTHETIC supplied vulnerability description.",
            patch_references=(ADVISORY,),
            feed_dates={"nvd": "2026-10-20", "epss": "2026-10-20", "kev": "2026-10-20"},
        )
        if cve
        else None
    )
    score = scoring.score(finding, enrichment, profile, host.services, WEIGHTS)
    return {
        "hosts": [host.to_json()],
        "findings": [finding.to_json()],
        "context": [profile.to_json()],
        "scores": [score.to_json()],
        "enrichments": [enrichment.to_json()] if enrichment is not None else [],
        "scanner_coverage": {"status": "SYNTHETIC; no scanner ran"},
        "scoring_policy": {"weights": WEIGHTS},
    }


def synthetic_record(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "capture_id": "synthetic-intelligence-delivery",
        "captured_at": "2026-10-23T00:00:00+00:00",
        "payload": payload,
        "result": {
            "target": HOST,
            "scan_status": "complete",
            "ai_status": "not_attempted",
            "assessment_summary": {"coverage_gaps": []},
        },
    }


def test_synthetic_analyst_retains_bounded_citable_advisory_references() -> None:
    payload = synthetic_payload()
    original = deepcopy(payload)

    case, evidence, aliases = analyst.build_case(payload, HOST)

    intelligence = case["findings"][0]["intelligence"][0]
    assert intelligence["patch_references"] == [ADVISORY]
    quote = next(item["text"] for item in evidence if item["id"] == intelligence["evidence_id"])
    assert ADVISORY in quote
    assert "not a verified fix" in quote
    assert len(analyst.build_prompt(case, evidence, len(aliases))) <= analyst.MAX_PROMPT_CHARS
    assert payload == original


def test_synthetic_reference_omissions_are_explicit_and_never_become_unsafe_links() -> None:
    payload = synthetic_payload()
    second = "https://vendor.example.invalid/security/second"
    payload["enrichments"][0]["patch_references"] = [
        ADVISORY,
        "javascript:synthetic_untrusted_reference",
        second,
        "https://vendor.example.invalid/security/third",
        "https://vendor.example.invalid/" + "x" * 220,
    ]

    case, _, _ = analyst.build_case(payload, HOST)

    intelligence = case["findings"][0]["intelligence"][0]
    assert intelligence["patch_references"] == [ADVISORY, second]
    assert intelligence["patch_references_omitted"] == 3
    assert "javascript:" not in str(intelligence)


@pytest.mark.parametrize(
    "reference",
    [
        "javascript:synthetic_reference",
        "https://user:synthetic@vendor.example.invalid/advisory",
        "https://vendor.example.invalid/with whitespace",
        "https://vendor.example.invalid/with\x00control",
        "https://vendor.example.invalid/[INST]synthetic",
    ],
)
def test_synthetic_untrusted_reference_tokens_are_withheld(reference: str) -> None:
    payload = synthetic_payload()
    payload["enrichments"][0]["patch_references"] = [reference]

    case, _, _ = analyst.build_case(payload, HOST)

    intelligence = case["findings"][0]["intelligence"][0]
    assert intelligence["patch_references"] == []
    assert intelligence["patch_references_omitted"] == 1


@pytest.mark.parametrize("references", [None, ADVISORY, {}, 5, [False]])
def test_synthetic_invalid_reference_shapes_are_explicit_errors(references: object) -> None:
    payload = synthetic_payload()
    payload["enrichments"][0]["patch_references"] = references

    with pytest.raises(ConfigError, match="patch_references"):
        analyst.build_case(payload, HOST)


def test_synthetic_cwe_only_case_has_no_invented_exploitation_intelligence() -> None:
    payload = synthetic_payload(cve=False)
    original = deepcopy(payload)

    case, _, _ = analyst.build_case(payload, HOST)

    finding = case["findings"][0]
    assert finding["cve_ids"] == []
    assert finding["cwe_ids"] == ["CWE-89"]
    assert finding["intelligence"] == []
    assert "EPSS and KEV are not applicable" in finding["cve_status"]
    assert "CWE definitions were not retrieved" in finding["cve_status"]
    assert finding["deterministic_score"]["risk"] == payload["scores"][0]["risk"]
    assert payload == original


def test_synthetic_recorded_report_does_not_present_no_cve_as_negative_kev() -> None:
    finding = make_finding(
        host_ip=HOST,
        tool="harbordesk",
        tool_native_id="synthetic-report",
        title="SYNTHETIC no-CVE report observation",
        cve_ids=[],
        native_severity="High",
    )
    score = scoring.score(finding, None, make_profile(host_ip=HOST), (), WEIGHTS)

    html = report._ranked([score], {finding.id: finding}, {}, {})

    assert html.count("not applicable (no CVE)") == 2


def test_synthetic_cpe_association_is_visible_without_changing_source_finding() -> None:
    payload = synthetic_payload(cpe_match=True)
    original = deepcopy(payload)

    result = vulnerability_findings.build(synthetic_record(payload))

    cves = result["findings"][0]["cves"]
    assert [row["id"] for row in cves] == [CVE]
    assert cves[0]["match_method"] == "cpe_range"
    assert cves[0]["match_confidence"] == 1.0
    assert payload["findings"][0]["cve_ids"] == []
    assert payload == original


def test_synthetic_cpe_association_is_not_mislabelled_as_no_cve() -> None:
    payload = synthetic_payload(cpe_match=True)

    case, _, _ = analyst.build_case(payload, HOST)
    html = assessment_report._findings(payload)

    assert "not applicable" not in case["findings"][0].get("cve_status", "")
    assert "EPSS and KEV are not applicable" not in html


def test_synthetic_full_reference_budget_still_fits_a_four_service_case() -> None:
    payload = synthetic_payload()
    payload["hosts"][0]["services"] = [
        service(port, "http", "SYNTHETIC endpoint evidence").to_json()
        for port in (80, 81, 443, 8080)
    ]
    template = payload["enrichments"][0]
    payload["enrichments"] = [
        {
            **template,
            "cve_id": f"CVE-2099-{1001 + index}",
            "description": "SYNTHETIC description " * 30,
            "patch_references": [
                "https://vendor.example.invalid/" + suffix * 165 for suffix in ("a", "b")
            ],
        }
        for index in range(3)
    ]
    original = deepcopy(payload)

    case, evidence, aliases = analyst.build_case(payload, HOST)

    assert case["coverage"]["findings_omitted"] == 0
    assert case["findings"][0]["intel_included"] == 3
    assert len(analyst.build_prompt(case, evidence, len(aliases))) <= analyst.MAX_PROMPT_CHARS
    assert payload == original


def test_synthetic_other_findings_enrichment_never_becomes_this_findings_cve() -> None:
    payload = synthetic_payload(cpe_match=True)
    payload["enrichments"][0]["finding_id"] = "synthetic-other-finding"

    result = vulnerability_findings.build(synthetic_record(payload))

    assert result["findings"][0]["cves"] == []


def test_synthetic_saved_report_shows_cwe_classification_without_claiming_mitre_lookup() -> None:
    payload = synthetic_payload(cve=False)
    original = deepcopy(payload)

    html = assessment_report._findings(payload)

    assert "CWE-89" in html
    assert "CWE definitions were not retrieved" in html
    assert "EPSS and KEV are not applicable" in html
    assert payload == original
