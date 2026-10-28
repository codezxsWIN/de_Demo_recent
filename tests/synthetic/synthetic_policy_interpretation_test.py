"""Synthetic operation-scope tests; they do not establish protocol accuracy."""

import copy
import json
from dataclasses import replace

import pytest

from tests.synthetic.synthetic_network_triage_test import CASES, synthetic_finding
from vulnassess import analyst
from vulnassess import network_policy_facts as facts
from vulnassess.errors import LLMUnavailable


def setup(index=0, text=None):
    finding = synthetic_finding(index).to_json()
    observation = facts.observation(finding)
    evidence = [{"id": "E1", "kind": "service-network_finding", "text": finding["evidence"]}]
    text = text or observation["statement"]
    result = {
        "summary": text,
        "claims": [{"path": "summary", "label": "observed", "evidence_ids": ["E1"]}],
        "investigations": [],
        "uncertainties": [],
    }
    return finding, evidence, result


@pytest.mark.parametrize("index", range(len(CASES)))
def test_canonical_operation_survives_live_and_saved_bindings(index):
    finding, evidence, result = setup(index)
    bound = facts.bindings([finding], evidence)
    assert len(bound) == 1
    facts.validate_interpretation(result, bound, require_summary=True)
    operation = facts.observation(finding)
    prepared = {
        "id": "F1",
        "port": finding["port"],
        "protocol": finding["protocol"],
        "evidence_id": "E1",
        "protocol_observation": operation,
    }
    assert facts.bindings([prepared], evidence, prepared=True)[0] == bound[0]
    analyst.validate_control_grounding(
        result, [], [result["summary"]], evidence=evidence, policy_findings=[finding]
    )


@pytest.mark.parametrize(
    "index,text",
    [
        (0, "An unauthenticated FTP login was accepted on port 49222."),
        (2, "An unauthenticated SMB read of the proof file succeeded on port 49222."),
        (3, "An unauthenticated MQTT publish/subscribe exchange succeeded on port 49222."),
    ],
)
def test_direct_operation_can_support_a_cited_negative_auth_claim(index, text):
    finding, evidence, result = setup(index, text)
    before = copy.deepcopy((finding, evidence, result))
    analyst.validate_control_grounding(
        result, [], [text], evidence=evidence, policy_findings=[finding]
    )
    assert (finding, evidence, result) == before


@pytest.mark.parametrize(
    "index,text",
    [
        (0, "An unauthenticated FTP login was accepted on port 49223."),
        (0, "An unauthenticated FTP login permits reading all files."),
        (2, "Unauthenticated SMB reads expose sensitive files."),
        (2, "An unauthenticated SMB write succeeded."),
        (3, "An unauthenticated MQTT exchange permits all topics."),
        (3, "Unauthenticated MQTT device commands succeeded."),
        (1, "The SSH service permits unauthenticated login."),
        (4, "The SNMP service has no authentication."),
    ],
)
def test_access_proof_cannot_be_borrowed_for_a_different_endpoint_operation_or_control(index, text):
    finding, evidence, result = setup(index, text)
    with pytest.raises(LLMUnavailable, match="unsupported control assertion"):
        analyst.validate_control_grounding(
            result, [], [text], evidence=evidence, policy_findings=[finding]
        )


def test_mqtt_connect_only_cannot_justify_publish_access():
    finding, evidence, result = setup(3, "An unauthenticated MQTT publish succeeded.")
    proof = json.loads(finding["evidence"])
    proof["observed"]["message_exchange_confirmed"] = False
    finding["evidence"] = json.dumps(proof)
    evidence[0]["text"] = finding["evidence"]
    with pytest.raises(LLMUnavailable, match="unsupported control assertion"):
        analyst.validate_control_grounding(
            result, [], [result["summary"]], evidence=evidence, policy_findings=[finding]
        )


@pytest.mark.parametrize(
    "changed", ["missing_citation", "wrong_kind", "changed_raw", "duplicate_key"]
)
def test_uncited_or_unbound_proof_never_authorises_auth_prose(changed):
    finding, evidence, result = setup(0, "An unauthenticated FTP login was accepted.")
    if changed == "missing_citation":
        result["claims"][0]["evidence_ids"] = ["E2"]
    elif changed == "wrong_kind":
        evidence[0]["kind"] = "nmap_service"
    elif changed == "changed_raw":
        evidence[0]["text"] += " changed"
    else:
        finding["evidence"] = finding["evidence"].replace(
            '"port": 49222', '"port": 49222, "port": 49223', 1
        )
        evidence[0]["text"] = finding["evidence"]
    with pytest.raises(LLMUnavailable):
        analyst.validate_control_grounding(
            result, [], [result["summary"]], evidence=evidence, policy_findings=[finding]
        )


@pytest.mark.parametrize(
    "text",
    [
        "The SMB signing is disabled.",
        "There is no SMB signing.",
        "SMB does not support signing.",
    ],
)
def test_optional_signing_is_not_disabled_signing(text):
    finding, evidence, result = setup(5, text)
    with pytest.raises(LLMUnavailable, match="optional signing"):
        analyst.validate_control_grounding(
            result, [], [text], evidence=evidence, policy_findings=[finding]
        )


@pytest.mark.parametrize(
    "index,text",
    [
        (3, "Review finding F1; control status is not established by this scan."),
        (3, "MQTT authentication is unknown."),
        (4, "Internal telemetry recorded low risk service behavior."),
        (0, "An FTP login was accepted but FTP authentication is unknown."),
    ],
)
def test_generic_or_contradictory_summary_is_not_published_as_a_policy_assessment(index, text):
    finding, evidence, result = setup(index, text)
    with pytest.raises(LLMUnavailable, match="network policy interpretation"):
        analyst.validate_control_grounding(
            result, [], [text], evidence=evidence, policy_findings=[finding]
        )


def test_summary_cannot_label_a_proven_observation_as_unknown():
    finding, evidence, result = setup()
    result["claims"][0]["label"] = "unknown"
    with pytest.raises(LLMUnavailable, match="as observed"):
        analyst.validate_control_grounding(
            result, [], [result["summary"]], evidence=evidence, policy_findings=[finding]
        )


def test_no_proof_field_from_an_untrusted_stored_finding_is_accepted_without_raw_validation():
    finding, evidence, _ = setup()
    finding["evidence"] = "invalid"
    finding["protocol_observation"] = {"service": "ftp", "category": "login"}
    assert facts.bindings([finding], evidence) == []
    assert facts.observation(replace(synthetic_finding(), tool="harbordesk").to_json()) is None


def test_mixed_and_nonpolicy_cases_do_not_gain_an_observed_summary_requirement():
    finding, evidence, result = setup()
    result["summary"] = "SYNTHETIC another finding requires review."
    facts.validate_interpretation(
        result, facts.bindings([finding], evidence), require_summary=False
    )
    analyst.validate_control_grounding(
        result,
        [],
        [result["summary"]],
        evidence=evidence,
        policy_findings=[finding, {"tool": "nmap"}],
    )


def test_owner_authentication_requirement_is_not_an_observed_host_control():
    from vulnassess.context import detect_controls
    from vulnassess.schema import Host, Service

    finding = synthetic_finding()
    host = Host(
        ip=finding.host_ip, services=(Service(port=finding.port, protocol="tcp", name="ftp"),)
    )
    signatures = {"auth_required": [{"regex": "require_auth"}]}
    assert detect_controls(host, [finding], signatures)["auth_required"].value is None
    # Existing non-policy scanner interpretation is unaffected.
    ordinary = replace(finding, tool="nmap")
    assert detect_controls(host, [ordinary], signatures)["auth_required"].value is True


@pytest.mark.parametrize("index", range(len(CASES)))
def test_report_decisions_describe_the_exact_proven_operation_and_outcome(index):
    from vulnassess.assessment_derivations import derive
    from vulnassess.ui.assessment_report import _ai_highlights

    finding = synthetic_finding(index).to_json()
    record = {
        "capture_id": "assessment-synthetic-policy",
        "result": {"resolved_ip": finding["host_ip"]},
        "payload": {"findings": [finding]},
    }
    before = copy.deepcopy(record)
    card = derive(record)[0]
    assert card["kind"] == "endpoint-policy"
    assert facts.observation(finding)["statement"] in card["conclusion"]["text"]
    assert facts.observation(finding)["limit"] in card["limits"]
    assert "timeout is inconclusive" in card["actions"][1]["if_fail"]
    assert (
        card["actions"][0]["task"]
        != "Ask the service owner to verify the exact reported condition and applicability."
    )
    html = _ai_highlights([], {}, record["payload"])
    assert "1 endpoint-policy violations reproduced" in html
    assert "verification leads" not in html
    assert record == before


def test_report_decision_cannot_promote_mismatched_or_malformed_policy_proof():
    from vulnassess.assessment_derivations import derive

    finding = synthetic_finding().to_json()
    record = {
        "capture_id": "assessment-synthetic-policy",
        "result": {"resolved_ip": "192.0.2.7"},
        "payload": {"findings": [finding]},
    }
    assert derive(record)[0]["kind"] == "scanner-lead"
    record["result"]["resolved_ip"] = finding["host_ip"]
    finding["evidence"] = "malformed"
    assert derive(record)[0]["kind"] == "scanner-lead"
