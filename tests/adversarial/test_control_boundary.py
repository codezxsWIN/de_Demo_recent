"""SYNTHETIC adversarial control records; no scanner or network execution."""

from dataclasses import replace

import pytest

from tests.test_all import (
    BASE_VECTOR,
    WEIGHTS,
    make_enrichment,
    make_finding,
    make_profile,
    service,
)
from vulnassess import scoring
from vulnassess.control_applicability import profile_for_finding
from vulnassess.errors import ConfigError
from vulnassess.schema import Feature


def test_model_derived_control_cannot_enter_canonical_score() -> None:
    quote = "SYNTHETIC cf-ray: lab"
    finding = make_finding(evidence=quote)
    profile = replace(make_profile(), controls={"waf": Feature("Cloudflare", 1.0, "llm", quote)})
    with pytest.raises(ConfigError, match="human-approved"):
        scoring.score(
            finding,
            make_enrichment(finding_id=finding.id),
            profile,
            (service(80, "http", "http"),),
            WEIGHTS,
        )


def test_finding_evidence_cannot_borrow_control_from_other_host() -> None:
    quote = "SYNTHETIC cf-ray: lab"
    finding = make_finding(evidence=quote)
    profile = make_profile(host_ip="172.28.0.20", waf="Cloudflare", waf_evidence=quote)
    services = (service(80, "http", "http"),)
    # Canonical scoring now rejects the foreign profile, not just its control credit.
    with pytest.raises(ConfigError, match="host_ip"):
        scoring.score(finding, make_enrichment(finding_id=finding.id), profile, services, WEIGHTS)
    scoped, decisions = profile_for_finding(profile, finding, services, 0.5)
    _, modifications = scoring.environmental_vector(BASE_VECTOR, scoped, WEIGHTS)
    assert "MAC" not in modifications
    assert decisions["waf"]["reason_code"] == "control_belongs_to_other_host"


@pytest.mark.parametrize("protocol, port", [("udp", 80), ("tcp", None), (None, 80)])
def test_web_quote_with_unbound_protocol_or_port_cannot_reduce_score(
    protocol: str | None, port: int | None
) -> None:
    quote = "SYNTHETIC cf-ray: lab"
    finding = make_finding(protocol=protocol, port=port, evidence=quote)
    profile = make_profile(waf="Cloudflare", waf_evidence=quote)
    result = scoring.score(finding, make_enrichment(finding_id=finding.id), profile, (), WEIGHTS)
    assert "MAC" not in result.env_modifications


@pytest.mark.parametrize(
    "url",
    [
        "http://172.28.0.20/affected",
        "http://172.28.0.10:81/affected",
        "https://172.28.0.10/affected",
        "http://unverified.example.invalid/affected",
        "http://user@172.28.0.10/affected",
        "http://[invalid/affected",
    ],
)
def test_unbound_import_url_cannot_earn_control_credit(url: str) -> None:
    quote = "SYNTHETIC cf-ray: lab"
    finding = make_finding(evidence=quote, url=url)
    profile = make_profile(waf="Cloudflare", waf_evidence=quote)
    result = scoring.score(finding, make_enrichment(finding_id=finding.id), profile, (), WEIGHTS)
    assert "MAC" not in result.env_modifications


def test_real_finding_id_with_different_quote_is_insufficient_control_evidence() -> None:
    finding = make_finding(evidence="SYNTHETIC Apache response")
    profile = make_profile(waf="Cloudflare", waf_evidence="SYNTHETIC Cloudflare response")
    result = scoring.score(
        finding,
        make_enrichment(finding_id=finding.id),
        profile,
        (service(80, "http", "http"),),
        WEIGHTS,
    )
    assert "MAC" not in result.env_modifications
    assert result.inputs["control_applicability"]["waf"]["status"] == "withheld"
