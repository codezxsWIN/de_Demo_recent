"""Synthetic, pure-logic regressions for finding-scoped context scoring."""

from dataclasses import replace
from typing import Sequence

from tests.test_all import (
    CONTROLS,
    WEIGHTS,
    make_enrichment,
    make_finding,
    make_host,
    make_profile,
    service,
)
from vulnassess import context, explain, report, scoring
from vulnassess.schema import ContextProfile, Feature, ScoreBreakdown, Service


def assess(
    port: int,
    services: Sequence[Service],
    evidence: str = "SYNTHETIC vulnerability observation",
    *,
    url: str | None = None,
) -> tuple[ScoreBreakdown, ContextProfile]:
    finding = make_finding(port=port, evidence=evidence, url=url)
    host = make_host(items=tuple(services))
    profile = replace(
        make_profile(exposure="internet_facing"),
        controls=context.detect_controls(host, [finding], CONTROLS),
    )
    enrichment = make_enrichment(finding_id=finding.id, kev=False, epss_percentile=0.5)
    return scoring.score(finding, enrichment, profile, host.services, WEIGHTS), profile


def test_http_controls_cannot_lower_ssh_or_redis_priority() -> None:
    web = service(80, "http", "80/tcp http nginx Cloudflare login")
    for port, name in ((22, "ssh"), (6379, "redis")):
        target = service(port, name, f"{port}/tcp {name}")
        baseline, _ = assess(port, [target])
        result, profile = assess(port, [web, target])
        assert result.risk == baseline.risk
        assert "MAC" not in result.env_modifications
        assert "MPR" not in result.env_modifications
        assert profile.controls["waf"].value == "Cloudflare"
        assert profile.controls["auth_required"].value is True


def test_control_on_port_80_cannot_lower_https_finding() -> None:
    result, _ = assess(
        443,
        [service(80, "http", "80/tcp http Cloudflare login"), service(443, "http", "https")],
    )
    assert "MAC" not in result.env_modifications
    assert "MPR" not in result.env_modifications


def test_generic_login_or_403_is_not_an_authentication_precondition() -> None:
    for text in ("HTTP/1.1 403 Forbidden", "login password form"):
        result, profile = assess(80, [service(80, "http", text)], evidence=text)
        assert profile.controls["auth_required"].value is True
        assert "MPR" not in result.env_modifications
        assert result.inputs["control_applicability"]["auth_required"]["status"] == "withheld"


def test_finding_bound_authentication_challenge_can_apply_configured_mapping() -> None:
    challenge = "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=lab"
    result, _ = assess(
        80,
        [service(80, "http", challenge)],
        evidence=challenge,
        url="http://172.28.0.10/admin",
    )
    assert result.env_modifications["MPR"] == "L"
    assert result.inputs["control_applicability"]["auth_required"]["status"] == "applied"


def test_authentication_challenge_on_another_path_is_withheld() -> None:
    challenge = "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=lab"
    result, _ = assess(
        80,
        [service(80, "http", challenge)],
        evidence="SYNTHETIC public endpoint observation",
        url="http://172.28.0.10/public",
    )
    assert "MPR" not in result.env_modifications


def test_vendor_banner_alone_is_not_finding_bound_waf_evidence() -> None:
    result, _ = assess(80, [service(80, "http", "80/tcp http Cloudflare")])
    assert "MAC" not in result.env_modifications
    assert result.inputs["control_applicability"]["waf"]["status"] == "withheld"


def test_scoped_web_control_preserves_configured_mapping_and_raw_observation() -> None:
    evidence = "SYNTHETIC affected response headers: cf-ray: lab-observation"
    result, profile = assess(
        80,
        [service(80, "http", "80/tcp http")],
        evidence=evidence,
        url="http://172.28.0.10/affected",
    )
    assert result.env_modifications["MAC"] == "H"
    decision = result.inputs["control_applicability"]["waf"]
    assert decision["status"] == "applied"
    assert decision["evidence"] == profile.controls["waf"].evidence
    assert "mitigation" in decision["limitation"].lower()


def test_decisions_are_deterministic_and_do_not_mutate_profile() -> None:
    services = [service(80, "http", "80/tcp http Cloudflare login"), service(22, "ssh", "ssh")]
    first, profile = assess(22, services)
    raw = profile.to_json()
    second, _ = assess(22, services)
    assert first.to_json() == second.to_json()
    assert profile.to_json() == raw
    assert first.inputs["observed_controls"]["waf"]["value"] == "Cloudflare"
    assert "behind Cloudflare" not in first.reason


def test_explanation_facts_do_not_restore_withheld_host_controls() -> None:
    result, profile = assess(
        22, [service(80, "http", "80/tcp http Cloudflare login"), service(22, "ssh", "ssh")]
    )
    facts = explain.facts_for(result, profile, make_finding(port=22))
    assert "Cloudflare" not in facts["compensating control"]
    assert "withheld" in facts["compensating control"]


def test_explanation_discloses_that_scoped_waf_signal_is_not_proven_mitigation() -> None:
    evidence = "SYNTHETIC affected response headers: cf-ray: lab-observation"
    result, profile = assess(80, [service(80, "http", "http")], evidence=evidence)
    facts = explain.facts_for(result, profile, make_finding(evidence=evidence))
    assert "Cloudflare" in facts["compensating control"]
    assert "unverified" in facts["compensating control"]
    assert "behind" not in facts["compensating control"]


def test_report_shows_control_decision_without_rewriting_host_observations() -> None:
    result, profile = assess(
        22, [service(80, "http", "80/tcp http Cloudflare login"), service(22, "ssh", "ssh")]
    )
    html = report.render(
        {"run_id": "SYNTHETIC-context-regression"},
        [result],
        [make_finding(port=22)],
        [profile],
        {},
        WEIGHTS,
        "synthetic-config",
    )
    assert "Control applicability by finding" in html
    assert "finding-scoped-controls-v2" in html
    assert "web_control_not_applicable_to_affected_service" in html
    assert "withheld" in html
    assert "Cloudflare" in html  # original host observation is still visible


def test_report_escapes_attacker_controlled_decision_evidence() -> None:
    evidence = "Cloudflare <script>alert('SYNTHETIC')</script>"
    result, profile = assess(22, [service(80, "http", evidence), service(22, "ssh", "ssh")])
    html = report.render(
        {"run_id": "SYNTHETIC-escape"},
        [result],
        [make_finding(port=22)],
        [profile],
        {},
        WEIGHTS,
        "synthetic-config",
    )
    assert "&lt;script&gt;" in html
    assert "<script>" not in html


def test_low_confidence_finding_bound_control_does_not_reduce_score() -> None:
    evidence = "SYNTHETIC Cloudflare response"
    finding = make_finding(evidence=evidence)
    profile = replace(
        make_profile(), controls={"waf": Feature("Cloudflare", 0.1, "rule", evidence)}
    )
    result = scoring.score(
        finding,
        make_enrichment(finding_id=finding.id),
        profile,
        (service(80, "http", "http"),),
        WEIGHTS,
    )
    assert "MAC" not in result.env_modifications
    assert (
        result.inputs["control_applicability"]["waf"]["reason_code"] == "below_confidence_threshold"
    )


def test_title_is_not_raw_control_evidence() -> None:
    finding = make_finding(title="Cloudflare login", evidence="SYNTHETIC unrelated response")
    controls = context.detect_controls(
        make_host(items=(service(80, "http", "http"),)), [finding], CONTROLS
    )
    assert not controls["waf"].value
    assert not controls["auth_required"].value


def test_tls_observation_is_scoped_to_affected_service() -> None:
    result, profile = assess(
        22, [service(443, "https", "https", tls=True), service(22, "ssh", "ssh")]
    )
    assert profile.controls["tls"].value is True
    assert result.inputs["controls"]["tls"]["value"] is None
    assert (
        result.inputs["control_applicability"]["tls"]["reason_code"]
        == "tls_not_bound_to_affected_service"
    )


def test_imported_http_finding_can_scope_control_without_service_fingerprint() -> None:
    evidence = "SYNTHETIC HTTP response cf-ray: lab"
    result, _ = assess(8080, [], evidence=evidence, url="http://172.28.0.10:8080/affected")
    assert result.env_modifications["MAC"] == "H"


def test_tls_decision_cites_matching_service_and_preserves_host_quote() -> None:
    result, profile = assess(
        8443,
        [
            service(443, "https", "SYNTHETIC first TLS service", tls=True),
            service(8443, "https", "SYNTHETIC affected TLS service", tls=True),
        ],
    )
    assert profile.controls["tls"].evidence == "SYNTHETIC first TLS service"
    assert result.inputs["observed_controls"]["tls"]["evidence"] == profile.controls["tls"].evidence
    assert (
        result.inputs["control_applicability"]["tls"]["evidence"]
        == "SYNTHETIC affected TLS service"
    )
    assert result.inputs["controls"]["tls"]["evidence"] == "SYNTHETIC affected TLS service"
    assert result.inputs["control_applicability"]["tls"]["status"] == "observed"


def test_native_fallback_does_not_claim_that_eligible_control_changed_score() -> None:
    evidence = "SYNTHETIC Cloudflare response"
    finding = make_finding(evidence=evidence)
    profile = make_profile(waf="Cloudflare", waf_evidence=evidence)
    result = scoring.score(finding, None, profile, (service(80, "http", "http"),), WEIGHTS)
    decision = result.inputs["control_applicability"]["waf"]
    assert decision["status"] == "eligible"
    assert "metric" not in decision
    assert result.env_modifications == {}
