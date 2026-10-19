"""Synthetic Stage 5 provenance and scoring regressions; no empirical evidence."""

import copy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from tests.test_all import CONTROLS, ROLES, WEIGHTS, make_enrichment, make_finding, make_profile
from vulnassess import context, scoring
from vulnassess.schema import ContextProfile, Feature, Host, Service
from vulnassess.settings import Scope

SYNTHETIC_NAME = "SYNTHETIC exposure target"
EXTERNAL_QUOTE = f"scope.yaml lab_targets[{SYNTHETIC_NAME}].tags.vantage=external"


def synthetic_scope(ip: str, tags: dict[str, Any], *, network: bool = True) -> Scope:
    """Validate in-memory scope input; the diagnostic path is never read or written."""
    return Scope(
        {
            "allowed_cidrs": [f"{ip}/32"] if network else [],
            "allowed_hosts": [] if network else [ip],
            "vantage": "internal",
            "lab_targets": [{"name": SYNTHETIC_NAME, "ip": ip, "tags": tags}],
        },
        Path("tests/synthetic/synthetic_scope.yaml"),
    )


def synthetic_host(ip: str = "172.28.0.12") -> Host:
    return Host(
        ip=ip,
        services=(
            Service(
                port=80,
                protocol="tcp",
                name="http",
                banner="SYNTHETIC 80/tcp http nginx",
            ),
        ),
    )


@pytest.mark.parametrize("ip", ["172.28.0.12", "8.8.8.8"])
@pytest.mark.parametrize("network", [True, False])
def test_actual_external_vantage_inference_is_manual_with_unchanged_details(
    ip: str, network: bool
) -> None:
    host = synthetic_host(ip)
    scope = synthetic_scope(ip, {"vantage": "external"}, network=network)
    before_host = copy.deepcopy(host.to_json())
    before_tags = scope.tags(ip)

    exposure, segment = context.infer_exposure(host, scope)

    assert exposure == Feature("internet_facing", 0.9, "manual", EXTERNAL_QUOTE)
    assert segment == (f"{ip}/32" if network else None)
    assert host.to_json() == before_host
    assert scope.tags(ip) == before_tags


@pytest.mark.parametrize("tags", [{}, {"environment": "test"}, {"criticality": 4}])
def test_actual_profile_build_preserves_every_field_except_external_source(
    tags: dict[str, Any],
) -> None:
    host = synthetic_host()
    finding = make_finding(host_ip=host.ip)
    scope = synthetic_scope(host.ip, {**tags, "vantage": "external"})
    before_finding = copy.deepcopy(finding.to_json())

    profile = context.build_profile(host, [finding], scope, ROLES, CONTROLS)

    assert (
        profile.to_json()
        == ContextProfile(
            host_ip=host.ip,
            role=context.infer_role(host, ROLES),
            exposure=Feature("internet_facing", 0.9, "manual", EXTERNAL_QUOTE),
            segment=f"{host.ip}/32",
            controls=context.detect_controls(host, [finding], CONTROLS),
            manual={
                key: Feature(
                    value,
                    1.0,
                    "manual",
                    f"scope.yaml lab_targets[{SYNTHETIC_NAME}].tags.{key}={value}",
                )
                for key, value in tags.items()
            },
        ).to_json()
    )
    assert "vantage" not in profile.manual
    assert scope.tags(host.ip) == {**tags, "vantage": "external"}
    assert finding.to_json() == before_finding


@pytest.mark.parametrize(
    "ip,value,confidence,quote",
    [
        (
            "172.28.0.12",
            "internal",
            0.85,
            "ip 172.28.0.12 is private (RFC1918/loopback/link-local/CGNAT)",
        ),
        ("8.8.8.8", "internet_facing", 0.9, "ip 8.8.8.8 is globally routable"),
    ],
)
@pytest.mark.parametrize(
    "tags",
    [
        {},
        {"environment": "test"},
        {"criticality": 5},
        {"environment": "prod", "vantage": "internal"},
    ],
)
def test_address_inference_stays_rule_and_unrelated_metadata_cannot_change_it(
    ip: str, value: str, confidence: float, quote: str, tags: dict[str, Any]
) -> None:
    host = synthetic_host(ip)
    scope = synthetic_scope(ip, tags)
    expected = Feature(value, confidence, "rule", quote)

    assert context.infer_exposure(host, scope) == (expected, f"{ip}/32")
    profile = context.build_profile(host, [], scope, ROLES, CONTROLS)
    baseline = context.build_profile(host, [], synthetic_scope(ip, {}), ROLES, CONTROLS)

    assert profile.exposure == baseline.exposure == expected
    assert profile.role == baseline.role
    assert profile.controls == baseline.controls
    assert profile.segment == baseline.segment == f"{ip}/32"
    assert set(profile.manual) == set(tags) - {"vantage"}
    assert scope.tags(ip) == tags


def test_building_new_profile_does_not_relabel_old_profile_or_serialized_input() -> None:
    host = synthetic_host()
    old = make_profile(host_ip=host.ip, exposure="internet_facing")
    old = replace(old, exposure=Feature("internet_facing", 0.9, "rule", EXTERNAL_QUOTE))
    old_payload = copy.deepcopy(old.to_json())
    restored = ContextProfile.from_json(old_payload)

    new = context.build_profile(
        host, [], synthetic_scope(host.ip, {"vantage": "external"}), ROLES, CONTROLS
    )

    assert new.exposure == replace(old.exposure, source="manual")
    assert old.exposure.source == restored.exposure.source == "rule"
    assert old.to_json() == restored.to_json() == old_payload
    assert ContextProfile.from_json(old_payload).to_json() == old_payload


@pytest.mark.parametrize(
    "tags", [{}, {"environment": "test"}, {"environment": "prod", "criticality": 4}]
)
@pytest.mark.parametrize("basis", ["observed_epss", "missing_epss", "kev", "native"])
def test_new_manual_profile_has_deterministic_scores_equal_to_otherwise_identical_old_rule(
    tags: dict[str, Any], basis: str
) -> None:
    host = synthetic_host()
    finding = make_finding(host_ip=host.ip)
    enrichment = (
        None
        if basis == "native"
        else make_enrichment(
            finding_id=finding.id,
            epss_percentile=None if basis == "missing_epss" else 0.12,
            epss=None if basis == "missing_epss" else 0.94321,
            kev=basis == "kev",
        )
    )
    new = context.build_profile(
        host, [finding], synthetic_scope(host.ip, {**tags, "vantage": "external"}), ROLES, CONTROLS
    )
    assert new.exposure.source == "manual"
    old = replace(new, exposure=replace(new.exposure, source="rule"))
    before_new = copy.deepcopy(new.to_json())
    before_old = copy.deepcopy(old.to_json())
    before_finding = copy.deepcopy(finding.to_json())
    before_enrichment = copy.deepcopy(enrichment.to_json()) if enrichment is not None else None
    weights = copy.deepcopy(WEIGHTS)

    old_score = scoring.score(finding, enrichment, old, host.services, weights)
    new_score = scoring.score(finding, enrichment, new, host.services, weights)
    repeated = scoring.score(finding, enrichment, new, host.services, weights)

    assert new_score.risk == old_score.risk
    assert new_score.band == old_score.band
    assert new_score.env_vector == old_score.env_vector
    assert new_score.env_score == old_score.env_score
    assert new_score.env_modifications == old_score.env_modifications
    assert new_score.threat_multiplier == old_score.threat_multiplier
    assert old_score.inputs["exposure"]["source"] == "rule"
    assert new_score.inputs["exposure"]["source"] == "manual"
    expected = copy.deepcopy(old_score.to_json())
    expected["inputs"]["exposure"]["source"] = "manual"
    assert new_score.to_json() == expected
    assert repeated.to_json() == new_score.to_json()
    assert new.to_json() == before_new
    assert old.to_json() == before_old
    assert finding.to_json() == before_finding
    assert (enrichment.to_json() if enrichment is not None else None) == before_enrichment
    assert weights == WEIGHTS
