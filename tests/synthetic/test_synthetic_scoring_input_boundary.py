"""Synthetic pure-logic boundary cases; not scanner or feed integration evidence."""

from copy import deepcopy
from dataclasses import replace

import pytest

from tests.test_all import BASE_VECTOR, WEIGHTS, make_enrichment, make_finding, make_profile
from vulnassess import scoring
from vulnassess.errors import ConfigError
from vulnassess.schema import Feature


def synthetic_score(profile=None, enrichment=None):
    finding = make_finding()
    matched = make_enrichment(finding_id=finding.id) if enrichment is None else enrichment
    return scoring.score(finding, matched, profile or make_profile(), (), WEIGHTS)


@pytest.mark.parametrize("field", ["role", "exposure"])
@pytest.mark.parametrize("value", [None, True, 1, [], {}, "invented", ""])
def test_invalid_context_enum_never_receives_a_priority(field, value):
    original = make_profile()
    profile = replace(original, **{field: replace(getattr(original, field), value=value)})
    with pytest.raises(ConfigError, match=field):
        synthetic_score(profile)
    assert original == make_profile()


@pytest.mark.parametrize("key", ["waf", "auth_required", "tls", "rate_limiting"])
@pytest.mark.parametrize("value", [0, 1, [], {}, "false"])
def test_invalid_controls_never_receive_a_priority(key, value):
    if key == "waf" and isinstance(value, str):
        value = " "  # WAF additionally allows a nonblank observed vendor string.
    profile = make_profile()
    controls = {**profile.controls, key: replace(profile.controls[key], value=value)}
    with pytest.raises(ConfigError, match=key):
        synthetic_score(replace(profile, controls=controls))


@pytest.mark.parametrize("value", [None, True, False, 0, 6, "5", 4.9, {}, [], 10**100])
def test_invalid_manual_criticality_rejected_before_canonical_scoring(value):
    profile = replace(
        make_profile(), manual={"criticality": Feature(value, 1.0, "manual", "synthetic")}
    )
    with pytest.raises(ConfigError, match="criticality"):
        synthetic_score(profile)


@pytest.mark.parametrize("value", [None, True, 0, [], {}, "production", ""])
def test_invalid_manual_environment_is_not_silently_ignored(value):
    profile = replace(
        make_profile(), manual={"environment": Feature(value, 1.0, "manual", "synthetic")}
    )
    with pytest.raises(ConfigError, match="environment"):
        synthetic_score(profile)


@pytest.mark.parametrize("field", ["controls", "manual"])
@pytest.mark.parametrize("value", [None, [], {"invented": Feature(True, 1.0, "rule", "synthetic")}])
def test_invalid_feature_maps_fail_closed(field, value):
    with pytest.raises(ConfigError, match=field):
        synthetic_score(replace(make_profile(), **{field: value}))


@pytest.mark.parametrize("field", ["role", "exposure"])
@pytest.mark.parametrize("value", [None, {}, "web_frontend"])
def test_invalid_feature_containers_fail_closed(field, value):
    with pytest.raises(ConfigError, match=field):
        synthetic_score(replace(make_profile(), **{field: value}))


def test_profile_of_another_host_cannot_score_this_finding():
    with pytest.raises(ConfigError, match="host_ip"):
        synthetic_score(make_profile(host_ip="172.28.0.12"))


def test_foreign_enrichment_cannot_score_this_finding():
    with pytest.raises(ConfigError, match="finding_id"):
        synthetic_score(enrichment=make_enrichment(finding_id="synthetic-other"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("kev", "false"),
        ("kev", 1),
        ("match_confidence", True),
        ("match_confidence", float("nan")),
        ("cvss31_base", float("nan")),
        ("cvss31_base", 11),
        ("cvss31_base", 1.0),
        ("cvss40_base", "9.8"),
        ("epss", float("inf")),
        ("epss", True),
        ("epss_percentile", "0.9"),
        ("cvss31_vector", []),
        ("cvss31_vector", "not-a-vector"),
        ("match_method", "invented"),
        ("cve_id", ""),
    ],
)
def test_malformed_enrichment_cannot_enter_selection_or_scoring(field, value):
    finding = make_finding()
    item = replace(make_enrichment(finding_id=finding.id), **{field: value})
    with pytest.raises(ConfigError, match=field):
        scoring.best_enrichment([item])
    with pytest.raises(ConfigError, match=field):
        synthetic_score(enrichment=item)


@pytest.mark.parametrize("value", [True, "9.8", float("nan"), float("inf"), -1, 11])
def test_risk_environmental_input_is_not_coerced(value):
    with pytest.raises(ConfigError, match="env_score"):
        scoring.risk(value, None, False, None, WEIGHTS, False)


@pytest.mark.parametrize("value", [True, "50", float("nan"), float("inf"), -1, 101])
def test_risk_native_input_is_not_coerced(value):
    with pytest.raises(ConfigError, match="native_key"):
        scoring.risk(None, None, False, value, WEIGHTS, False)


@pytest.mark.parametrize("field", ["kev", "internet_facing"])
@pytest.mark.parametrize("value", [None, 0, 1, "false"])
def test_risk_flags_are_actual_booleans(field, value):
    kwargs = dict(
        env_score=5.0,
        epss_percentile=None,
        kev=False,
        native_key=None,
        weights=WEIGHTS,
        internet_facing=False,
    )
    kwargs[field] = value
    with pytest.raises(ConfigError, match=field):
        scoring.risk(**kwargs)


@pytest.mark.parametrize("value", [True, "50", float("nan"), float("inf"), -float("inf")])
def test_band_does_not_label_invalid_numbers_low(value):
    with pytest.raises(ConfigError, match="band"):
        scoring.band(value, WEIGHTS)


@pytest.mark.parametrize("criticality", ["4", 4.9, True])
def test_legacy_environmental_helper_does_not_coerce_invalid_optional_criticality(criticality):
    profile = make_profile()
    malformed = replace(
        profile, manual={"criticality": Feature(criticality, 1.0, "manual", "synthetic")}
    )
    assert scoring.environmental_vector(BASE_VECTOR, malformed, WEIGHTS) == (
        scoring.environmental_vector(BASE_VECTOR, profile, WEIGHTS)
    )


def test_invalid_context_cannot_hide_behind_an_empty_batch():
    with pytest.raises(ConfigError, match="exposure"):
        scoring.score_available([], [], make_profile(exposure="invented"), (), WEIGHTS)


@pytest.mark.parametrize(
    "role",
    [
        "database",
        "web_frontend",
        "app_server",
        "domain_controller",
        "mail",
        "file_share",
        "iot_embedded",
        "workstation",
        "network_device",
        "unknown",
    ],
)
def test_valid_context_still_scores_deterministically_without_mutation(role):
    profile = make_profile(role=role, criticality=5, environment="test")
    before = deepcopy(profile.to_json())
    first, second = synthetic_score(profile), synthetic_score(profile)
    assert first.to_json() == second.to_json()
    assert profile.to_json() == before
    assert 0 <= first.risk <= 100


def test_finite_band_mapping_and_unscored_low_level_math_stay_compatible():
    assert scoring.band(-1.0, WEIGHTS) == "Low"
    assert scoring.band(101.0, WEIGHTS) == "Critical"
    assert scoring.risk(None, None, False, None, WEIGHTS, False) == (0.0, None)


def test_mixed_owner_enrichment_selection_is_not_a_worst_finding_selector():
    with pytest.raises(ConfigError, match="finding_id"):
        scoring.best_enrichment([make_enrichment(), make_enrichment(finding_id="synthetic-other")])


@pytest.mark.parametrize("item", [None, {}, "synthetic-bad-enrichment"])
def test_invalid_enrichment_container_cannot_hide_in_selection_or_empty_batch(item):
    with pytest.raises(ConfigError, match="enrichment"):
        scoring.best_enrichment([item])
    with pytest.raises(ConfigError, match="enrichment"):
        scoring.score_available([], [item], make_profile(), (), WEIGHTS)


@pytest.mark.parametrize("field", ["segment", "native_severity"])
@pytest.mark.parametrize("value", [True, [], {}])
def test_invalid_optional_strings_are_not_coerced(field, value):
    finding = make_finding()
    profile = make_profile()
    if field == "segment":
        profile = replace(profile, segment=value)
    else:
        finding = replace(finding, native_severity=value)
    with pytest.raises(ConfigError, match=field):
        scoring.score(finding, None, profile, (), WEIGHTS)


def test_non_profile_container_is_controlled():
    with pytest.raises(ConfigError, match="ContextProfile"):
        scoring.score(make_finding(), None, {}, (), WEIGHTS)


def test_oversized_integer_is_controlled_in_band_before_float_overflow():
    with pytest.raises(ConfigError, match="finite"):
        scoring.band(10**1000, WEIGHTS)


@pytest.mark.parametrize("confidence", [True, float("nan")])
def test_invalid_feature_state_is_rechecked_at_scoring_boundary(confidence):
    profile = deepcopy(make_profile())
    # Simulate an invalid in-memory decoder bypass, not a supported constructor.
    object.__setattr__(profile.role, "confidence", confidence)
    with pytest.raises(ConfigError, match="role.confidence"):
        synthetic_score(profile)


def test_empty_feature_quote_is_rechecked_at_scoring_boundary():
    profile = deepcopy(make_profile())
    object.__setattr__(profile.role, "evidence", " ")
    with pytest.raises(ConfigError, match="role.evidence"):
        synthetic_score(profile)


def test_all_valid_control_values_remain_accepted():
    for value in (None, False, True):
        profile = make_profile()
        profile.controls = {
            key: replace(item, value=value) for key, item in profile.controls.items()
        }
        assert 0 <= synthetic_score(profile).risk <= 100
    assert 0 <= synthetic_score(make_profile(waf="Synthetic vendor")).risk <= 100


def test_valid_batch_ignores_unrelated_well_formed_enrichments_without_mutation():
    finding = make_finding()
    matching = make_enrichment(finding_id=finding.id)
    unrelated = make_enrichment(finding_id="synthetic-unrelated")
    items = [unrelated, matching]
    before = deepcopy([item.to_json() for item in items])
    scores, unscored = scoring.score_available([finding], items, make_profile(), (), WEIGHTS)
    assert [item.finding_id for item in scores] == [finding.id] and unscored == []
    assert [item.to_json() for item in items] == before
    assert scoring.best_enrichment([]) is None


@pytest.mark.parametrize("cves", [[], ["CVE-1999-9001"]])
def test_explicit_cve_must_be_named_by_its_own_finding(cves):
    finding = make_finding(cve_ids=cves)
    enrichment = make_enrichment(finding_id=finding.id, cve_id="CVE-1999-9002")
    before = deepcopy((finding.to_json(), enrichment.to_json()))
    with pytest.raises(ConfigError, match="cve_id.*explicit"):
        scoring.score(finding, enrichment, make_profile(), (), WEIGHTS)
    with pytest.raises(ConfigError, match="cve_id.*explicit"):
        scoring.score_available([finding], [enrichment], make_profile(), (), WEIGHTS)
    assert (finding.to_json(), enrichment.to_json()) == before


def test_cpe_candidate_need_not_be_explicitly_named_in_raw_finding():
    finding = make_finding(cve_ids=[])
    enrichment = make_enrichment(finding_id=finding.id, match_method="cpe_range")
    result = scoring.score(finding, enrichment, make_profile(), (), WEIGHTS)
    assert result.cve_id == enrichment.cve_id
    assert finding.cve_ids == ()


@pytest.mark.parametrize("cves", ["CVE-1999-9001", {"CVE-1999-9001": True}, (None,), ("",)])
def test_cve_container_cannot_launder_membership(cves):
    finding = replace(make_finding(), cve_ids=cves)
    with pytest.raises(ConfigError, match="cve_ids"):
        scoring.score(finding, None, make_profile(), (), WEIGHTS)
