"""Synthetic scoring hypotheses: not independent evidence of real-world risk accuracy."""

import copy
import json
from dataclasses import replace

import pytest

from tests.test_all import WEIGHTS, make_enrichment, make_finding, make_profile
from vulnassess import assessment_snapshot, network_triage, scoring
from vulnassess.errors import ConfigError
from vulnassess.priority_trace import priority_trace
from vulnassess.schema import Feature, Provenance

CASES = [
    ("ftp", "authentication", {"require_auth": True}, {"anonymous_accepted": True}, "login", 30),
    (
        "ssh",
        "credential",
        {"reject_test_credential": True},
        {"test_credential_accepted": True},
        "login",
        30,
    ),
    (
        "smb",
        "authentication",
        {"require_auth": True, "share": "OWNER", "read_path": "permitted.txt"},
        {"anonymous_accepted": True, "files_read": True, "read_bytes": 31},
        "file_read",
        50,
    ),
    (
        "mqtt",
        "authentication",
        {"require_auth": True, "publish_topic": "owner/nonce"},
        {"anonymous_accepted": True, "message_exchange_confirmed": True, "topic": "owner/nonce"},
        "message_exchange",
        50,
    ),
    (
        "snmp",
        "authentication",
        {"require_auth": True},
        {"public_community_read": True},
        "management_read",
        20,
    ),
    (
        "smb",
        "signing",
        {"require_signing": True},
        {"signing_required": False},
        "signing_optional",
        20,
    ),
    (
        "tls",
        "certificate",
        {"require_unexpired_certificate": True},
        {"expired": True},
        "expired_certificate",
        10,
    ),
]


def synthetic_finding(index=0):
    service, condition, expected, observed, _, _ = CASES[index]
    protocol = "udp" if service == "snmp" else "tcp"
    entry = {"service": service, "port": 49222, "transport": protocol, **expected}
    evidence = {
        "target_ip": "172.28.0.10",
        "port": 49222,
        "protocol": protocol,
        "policy_sha256": "a" * 64,
        "expected_policy": entry,
        "observed": {"protocol_confirmed": True, **observed},
    }
    return make_finding(
        port=49222,
        protocol=protocol,
        tool="service-network",
        cve_ids=[],
        native_severity="Medium",
        title="SYNTHETIC endpoint policy violation",
        description="SYNTHETIC pure score input",
        tool_native_id=f"policy:{service}:49222:{condition}",
        evidence=json.dumps(evidence),
        provenance=Provenance("service-network", "synthetic/receipt.json", 0, "synthetic"),
    )


def synthetic_profile(*, external=False, environment="test", criticality=3, confidence=1):
    return replace(
        make_profile(),
        exposure=Feature(
            "internet_facing" if external else "internal",
            confidence,
            "manual",
            "SYNTHETIC scope vantage",
        ),
        manual={
            "environment": Feature(
                environment, confidence, "manual", "SYNTHETIC owner environment"
            ),
            "criticality": Feature(
                criticality, confidence, "manual", "SYNTHETIC owner criticality"
            ),
        },
    )


def scored(finding=None, profile=None, weights=None):
    return scoring.score(
        finding or synthetic_finding(), None, profile or synthetic_profile(), (), weights or WEIGHTS
    )


@pytest.mark.parametrize("index", range(len(CASES)))
def test_protocol_proof_category_is_not_just_a_port_or_title(index):
    finding = synthetic_finding(index)
    result = scored(finding)
    assert result.risk == CASES[index][-1]
    assert result.inputs["native_triage"]["category"] == CASES[index][-2]
    assert result.cve_id is None and result.base_vector is None and result.env_score is None
    assert result.epss_percentile is None and not result.kev
    assert "Uncalibrated local policy" in result.reason
    assert priority_trace(result.to_json(), WEIGHTS)["status"] == "verified"


def test_same_observation_gets_explicit_context_effect_without_changing_the_evidence():
    finding = synthetic_finding(2)
    before = copy.deepcopy(finding.to_json())
    local = scored(finding, synthetic_profile())
    production = scored(
        finding, synthetic_profile(external=True, environment="prod", criticality=5)
    )
    assert local.risk == 50 and production.risk == 85
    assert local.inputs["native_triage"]["base"] == production.inputs["native_triage"]["base"] == 60
    assert production.inputs["native_triage"]["steps"][1]["value"] == 15
    assert production.inputs["native_triage"]["steps"][3]["value"] == 10
    assert "expert-validated" in production.inputs["native_triage"]["limitation"]
    assert finding.to_json() == before


def test_low_confidence_context_does_not_earn_a_reduction_or_addition():
    profile = synthetic_profile(external=True, criticality=5, confidence=0.49)
    assert scored(profile=profile).risk == 40
    profile = replace(profile, manual={})
    assert scored(profile=profile).risk == 40


def test_role_and_unrelated_control_changes_never_adjust_native_triage():
    profile = synthetic_profile()
    other = replace(
        profile,
        role=Feature("database", 1, "rule", "SYNTHETIC role"),
        controls={
            "waf": Feature("vendor", 1, "rule", "SYNTHETIC other service"),
            "auth_required": Feature(True, 1, "rule", "SYNTHETIC other login"),
            "tls": Feature(True, 1, "rule", "SYNTHETIC other TLS"),
        },
    )
    assert scored(profile=profile).risk == scored(profile=other).risk == 30


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(target_ip="172.28.0.11"),
        lambda e: e.update(port=49223),
        lambda e: e.update(protocol="udp"),
        lambda e: e.update(policy_sha256="not-a-hash"),
        lambda e: e["expected_policy"].update(require_auth=False),
        lambda e: e["expected_policy"].update(port=True),
        lambda e: e["observed"].update(protocol_confirmed=False),
        lambda e: e["observed"].update(anonymous_accepted="true"),
    ],
)
def test_bad_or_unbound_proof_retains_generic_severity_instead_of_getting_context_score(mutate):
    finding = synthetic_finding()
    raw = json.loads(finding.evidence)
    mutate(raw)
    result = scored(replace(finding, evidence=json.dumps(raw)))
    assert result.risk == 40
    assert "native_triage" not in result.inputs


@pytest.mark.parametrize(
    "evidence", ["{}", "null", "[]", "{", '{"target_ip": 1, "target_ip": 2}', "x" * 2048]
)
def test_malformed_or_truncated_json_does_not_gain_a_custom_score(evidence):
    assert "native_triage" not in scored(replace(synthetic_finding(), evidence=evidence)).inputs


def test_mqtt_connect_only_is_not_treated_as_publish_permission():
    finding = synthetic_finding(3)
    raw = json.loads(finding.evidence)
    raw["observed"]["message_exchange_confirmed"] = False
    result = scored(replace(finding, evidence=json.dumps(raw)))
    assert result.risk == 30 and result.inputs["native_triage"]["category"] == "login"


def test_empty_file_does_not_gain_nonempty_file_read_category():
    finding = synthetic_finding(2)
    raw = json.loads(finding.evidence)
    raw["observed"]["read_bytes"] = 0
    assert "native_triage" not in scored(replace(finding, evidence=json.dumps(raw))).inputs


def test_policy_absent_preserves_legacy_native_path():
    weights = {key: value for key, value in WEIGHTS.items() if key != "service_network_triage"}
    result = scored(weights=weights)
    assert result.risk == 40 and result.native_fallback == "service-network:Medium=40"


@pytest.mark.parametrize("tool", ["harbordesk", "network-lab", "zap", "nessus", "nikto", "nmap"])
def test_other_scanners_and_harbordesk_keep_their_scores(tool):
    finding = replace(synthetic_finding(), tool=tool)
    before = {key: value for key, value in WEIGHTS.items() if key != "service_network_triage"}
    old, current = scored(finding, weights=before), scored(finding)
    assert replace(current, weights_hash=old.weights_hash) == old
    assert "native_triage" not in current.inputs


def test_cve_enrichment_never_uses_native_context_hypothesis():
    finding = replace(synthetic_finding(), cve_ids=("CVE-1999-9001",))
    enrichment = make_enrichment(finding_id=finding.id)
    result = scoring.score(finding, enrichment, synthetic_profile(), (), WEIGHTS)
    assert result.cvss_version_used == "3.1"
    assert "native_triage" not in result.inputs


@pytest.mark.parametrize(
    "key,value",
    [
        ("internet_facing_add", -1),
        ("internet_facing_add", 21),
        ("criticality_step_add", True),
        ("test_environment_subtract", "10"),
        ("min_confidence", float("nan")),
        ("min_confidence", float("inf")),
        ("min_confidence", 1.1),
        ("version", "unsupported"),
        ("base", {}),
    ],
)
def test_invalid_policy_cannot_change_a_score(key, value):
    policy = copy.deepcopy(WEIGHTS["service_network_triage"])
    policy[key] = value
    with pytest.raises(ConfigError):
        network_triage.validate(policy)


def test_native_trace_refuses_tampered_steps_and_frozen_snapshot_replay_detects_it():
    expected = scored().to_json()
    before = copy.deepcopy(expected)
    changed = copy.deepcopy(expected)
    changed["inputs"]["native_triage"]["steps"][1]["value"] = 15
    assert priority_trace(changed, WEIGHTS)["status"] == "unavailable"
    with pytest.raises(ValueError, match="native_triage"):
        assessment_snapshot._check_current_replay(changed, expected)
    changed = copy.deepcopy(expected)
    del changed["inputs"]["native_triage"]
    assert "inputs.native_triage" in assessment_snapshot._check_current_replay(changed, expected)
    assert expected == before


def test_changed_policy_is_not_used_to_rewrite_a_historical_priority():
    record = scored().to_json()
    different = copy.deepcopy(WEIGHTS)
    different["service_network_triage"]["base"]["login"] = 99
    assert priority_trace(record, different)["status"] == "retained_only"
    assert priority_trace(record)["status"] == "retained_only"
    assert record["risk"] == 30


@pytest.mark.parametrize("category", sorted(network_triage.CATEGORIES))
def test_priority_is_bounded_and_monotonic_with_explicit_owner_criticality(category):
    policy = copy.deepcopy(WEIGHTS["service_network_triage"])
    for external in (False, True):
        values = [
            network_triage.calculate(
                category,
                synthetic_profile(external=external, environment="prod", criticality=level),
                policy,
            )["risk"]
            for level in range(1, 6)
        ]
        assert values == sorted(values) and all(0 <= value <= 100 for value in values)
    policy["base"][category] = 100
    assert (
        network_triage.calculate(category, synthetic_profile(external=True, criticality=5), policy)[
            "risk"
        ]
        == 100
    )
    policy["base"][category] = 0
    assert network_triage.calculate(category, synthetic_profile(), policy)["risk"] == 0


def test_unapproved_learned_manual_tags_do_not_adjust_the_hypothesis():
    profile = synthetic_profile()
    profile = replace(
        profile,
        manual={key: replace(value, source="rule") for key, value in profile.manual.items()},
    )
    assert scored(profile=profile).risk == 40
    with pytest.raises(ConfigError, match="affected host"):
        network_triage.for_finding(
            synthetic_finding(), replace(profile, host_ip="172.28.0.11"), WEIGHTS
        )


def test_enormous_integer_is_a_configuration_error():
    policy = copy.deepcopy(WEIGHTS["service_network_triage"])
    policy["internet_facing_add"] = 10**1000
    with pytest.raises(ConfigError):
        network_triage.validate(policy)


@pytest.mark.parametrize("index", range(len(CASES)))
def test_guidance_is_protocol_specific_and_keeps_proof_limits(index):
    from vulnassess.network_service_checks import guidance

    result = guidance(synthetic_finding(index).to_json())
    assert result and result["patch"] and result["verify"]
    checks = [
        ("authentication rejection", "did not list"),
        ("owner's approved key", "No commands"),
        ("access denied", "does not establish that sensitive shares"),
        ("anonymous CONNECT", "only if message_exchange_confirmed=true"),
        ("silence alone", "not write access"),
        ("signing_required=true", "No relay"),
        ("expired=false", "Expiry alone does not establish issuer trust"),
    ]
    assert checks[index][0] in result["verify"][0]
    assert checks[index][1] in result["meaning"]


def test_ai_receives_the_basis_and_caveat_but_cannot_change_it():
    from tests.synthetic.synthetic_intelligence_delivery_test import synthetic_payload
    from vulnassess import analyst

    payload = synthetic_payload(cve=False)
    finding = synthetic_finding(2)
    payload["findings"] = [finding.to_json()]
    payload["scores"] = [scored(finding).to_json()]
    before = copy.deepcopy(payload)
    case, evidence, aliases = analyst.build_case(payload, finding.host_ip)
    basis = case["findings"][0]["deterministic_score"]["native_triage"]
    assert basis["category"] == "file_read" and basis["base"] == 60
    assert "not CVSS" in basis["limitation"]
    assert (
        len(analyst.build_prompt(case, evidence, len(aliases)))
        <= analyst.MAX_PROMPT_CHARS - analyst.CORRECTION_RESERVE
    )
    assert payload == before


def test_html_and_download_show_the_same_native_arithmetic(tmp_path):
    from tests.test_assessment_report import setup_report
    from vulnassess import capture_history
    from vulnassess.ui import assessment_report

    _, directory = setup_report(tmp_path, ai=False)
    record = capture_history.load(directory.parent, directory.name)
    record["payload"]["findings"] = [synthetic_finding(2).to_json()]
    record["payload"]["scores"] = [scored(synthetic_finding(2)).to_json()]
    before = copy.deepcopy(record)
    for standalone in (True, False):
        html = assessment_report.render(record, policy=WEIGHTS, standalone=standalone)
        assert "native context triage" in html
        assert "Trace: verified" in html and "Declared test environment" in html
        assert "not CVSS" in html and "expert-validated ranking" in html
        assert "not ranked by vulnerability severity" not in html
    assert record == before
