"""Synthetic control eligibility must agree with observed protocol classification."""

from copy import deepcopy
from dataclasses import replace

import pytest

from tests.test_all import WEIGHTS, make_enrichment, make_finding, make_profile
from vulnassess import protocols, scoring
from vulnassess.control_applicability import POLICY_VERSION, profile_for_finding
from vulnassess.schema import Feature, Service

QUOTES = {
    "waf": "SYNTHETIC affected response cf-ray: example",
    "auth_required": 'HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm="SYNTHETIC"',
    "rate_limiting": "SYNTHETIC affected response HTTP/1.1 429 Too Many Requests",
}


def inputs(key, label, protocol="tcp", *, url=None):
    finding = make_finding(evidence=QUOTES[key], url=url)
    profile = replace(make_profile(), controls={key: Feature(True, 1.0, "rule", QUOTES[key])})
    observed = (Service(finding.port, protocol, name=label),)
    enrichment = make_enrichment(finding_id=finding.id, kev=False, epss_percentile=None)
    return finding, profile, observed, enrichment


@pytest.mark.parametrize("key", list(QUOTES))
@pytest.mark.parametrize(
    "label",
    [
        "http-invalid-synthetic",
        "https_unknown",
        "http-proxy-exploit",
        "http-database",
        "ssl/http-invalid",
        "tls/http-invalid",
        "prefix/http",
        "http\nSYNTHETIC instructions",
        "redis",
        None,
    ],
)
def test_unsupported_service_label_cannot_earn_web_control_credit(key, label):
    finding, profile, observed, enrichment = inputs(key, label)
    before = deepcopy(profile.to_json())
    assert not protocols.is_http(observed[0])
    scoped, decisions = profile_for_finding(profile, finding, observed, 0.5)
    assert decisions[key]["status"] == "withheld"
    assert decisions[key]["reason_code"] == "web_control_not_applicable_to_affected_service"
    assert scoped.controls[key].value is None
    assert scoped.controls[key].confidence == 0
    assert profile.to_json() == before
    result = scoring.score(finding, enrichment, profile, observed, WEIGHTS)
    baseline = scoring.score(finding, enrichment, replace(profile, controls={}), observed, WEIGHTS)
    assert "MAC" not in result.env_modifications
    assert "MPR" not in result.env_modifications
    assert result.risk == baseline.risk
    assert result.inputs["observed_controls"][key] == before["controls"][key]


@pytest.mark.parametrize("key", list(QUOTES))
def test_every_supported_tcp_http_label_preserves_eligible_control_observation(key):
    for label in sorted(protocols.HTTP_NAMES):
        finding, profile, observed, enrichment = inputs(key, label)
        assert protocols.is_http(observed[0])
        scoped, decisions = profile_for_finding(profile, finding, observed, 0.5)
        assert decisions[key]["status"] == "eligible", label
        assert scoped.controls[key] == profile.controls[key], label
        result = scoring.score(finding, enrichment, profile, observed, WEIGHTS)
        if key == "waf":
            assert result.env_modifications["MAC"] == "H", label
        elif key == "auth_required":
            assert result.env_modifications["MPR"] == "L", label
        else:
            assert "MAC" not in result.env_modifications
            assert "MPR" not in result.env_modifications


@pytest.mark.parametrize("protocol", ["udp", "sctp", "unknown"])
@pytest.mark.parametrize("key", list(QUOTES))
def test_other_transport_cannot_borrow_a_tcp_finding_control_quote(protocol, key):
    finding, profile, observed, enrichment = inputs(key, "http", protocol)
    _, decisions = profile_for_finding(profile, finding, observed, 0.5)
    assert decisions[key]["status"] == "withheld"
    result = scoring.score(finding, enrichment, profile, observed, WEIGHTS)
    assert "MAC" not in result.env_modifications and "MPR" not in result.env_modifications


@pytest.mark.parametrize("key", list(QUOTES))
def test_literal_import_url_cannot_override_a_conflicting_observed_service(key):
    finding, profile, observed, _ = inputs(key, "ssh", url="http://172.28.0.10/affected")
    _, decisions = profile_for_finding(profile, finding, observed, 0.5)
    assert decisions[key]["status"] == "withheld"
    _, without_fingerprint = profile_for_finding(profile, finding, (), 0.5)
    assert without_fingerprint[key]["status"] == "eligible"


def test_supported_label_normalisation_does_not_bypass_evidence_binding():
    finding, profile, observed, enrichment = inputs("waf", "  TLS/HTTP-PROXY  ")
    assert protocols.is_http(observed[0])
    result = scoring.score(finding, enrichment, profile, observed, WEIGHTS)
    assert result.env_modifications["MAC"] == "H"
    unrelated = replace(finding, evidence="SYNTHETIC unrelated observation")
    result = scoring.score(unrelated, enrichment, profile, observed, WEIGHTS)
    assert "MAC" not in result.env_modifications
    assert (
        result.inputs["control_applicability"]["waf"]["reason_code"]
        == "control_not_bound_to_finding_evidence"
    )
    assert result.inputs["context_policy"] == POLICY_VERSION == "finding-scoped-controls-v2"


def test_historical_scoped_policy_keeps_its_uncertainty_without_rewriting_score():
    finding, profile, observed, enrichment = inputs("waf", "http")
    current = scoring.score(finding, enrichment, profile, observed, WEIGHTS)
    old = replace(
        current, inputs={**current.inputs, "context_policy": "finding-scoped-controls-v1"}
    )
    before = old.to_json()
    reason = scoring.describe(old, profile)
    assert "recorded signal under legacy eligibility policy" in reason
    assert "affected HTTP record" not in reason
    assert "mitigation unverified" in reason and "behind" not in reason
    assert old.to_json() == before
