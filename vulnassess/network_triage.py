"""Versioned local triage hypothesis for observed endpoint-policy violations.

This is neither CVSS nor a calibrated risk/compromise probability. Only explicit
protocol proof selects a category. Role guesses and unrelated host controls earn
no adjustment. Pure functions keep the result replayable from retained inputs.
"""

import hashlib
import json
import re
from math import isfinite
from typing import Any

from vulnassess.errors import ConfigError
from vulnassess.schema import ContextProfile, Finding

VERSION = "service-network-triage-v1"
CATEGORIES = {
    "login",
    "file_read",
    "message_exchange",
    "management_read",
    "signing_optional",
    "expired_certificate",
}
KEYS = {
    "version",
    "base",
    "internet_facing_add",
    "test_environment_subtract",
    "criticality_step_add",
    "min_confidence",
}


def validate(policy):
    if not isinstance(policy, dict) or set(policy) != KEYS or policy["version"] != VERSION:
        raise ConfigError("service_network_triage requires its complete supported versioned policy")
    if not isinstance(policy["base"], dict) or set(policy["base"]) != CATEGORIES:
        raise ConfigError("service_network_triage.base must declare every supported proof category")
    values = {**policy["base"], **{key: policy[key] for key in KEYS - {"version", "base"}}}
    for key, value in values.items():
        limit = 1 if key == "min_confidence" else 20 if key not in CATEGORIES else 100
        try:
            valid = type(value) in (float, int) and isfinite(value) and 0 <= value <= limit
        except OverflowError:
            valid = False
        if not valid:
            raise ConfigError(f"service_network_triage.{key} must be finite in [0, {limit}]")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate evidence key")
        result[key] = value
    return result


def proof_category(finding: Finding) -> tuple[str, str] | None:
    """Select a proof category only from endpoint-bound owner-policy evidence."""
    try:
        record = json.loads(finding.evidence, object_pairs_hook=_object)
        entry, proof = record["expected_policy"], record["observed"]
        if (
            not isinstance(entry, dict)
            or not isinstance(proof, dict)
            or proof.get("protocol_confirmed") is not True
            or record["target_ip"] != finding.host_ip
            or type(record["port"]) is not int
            or record["port"] != finding.port
            or record["protocol"] != finding.protocol
            or type(entry.get("port")) is not int
            or entry.get("port") != finding.port
            or entry.get("transport") != finding.protocol
            or not re.fullmatch(r"[a-f0-9]{64}", record["policy_sha256"])
            or finding.provenance.tool != "service-network"
        ):
            return None
        service = entry.get("service")
        prefix = f"policy:{service}:{finding.port}:"
        if not finding.tool_native_id.startswith(prefix):
            return None
        condition = finding.tool_native_id[len(prefix) :]
        transport = "udp" if service == "snmp" else "tcp"
        if finding.protocol != transport:
            return None
        category = None
        if condition == "authentication" and entry.get("require_auth") is True:
            if service == "ftp" and proof.get("anonymous_accepted") is True:
                category = "login"
            elif (
                service == "smb"
                and proof.get("anonymous_accepted") is True
                and proof.get("files_read") is True
                and type(proof.get("read_bytes")) is int
                and 0 < proof["read_bytes"] <= 1024
                and entry.get("share")
                and entry.get("read_path")
            ):
                category = "file_read"
            elif service == "mqtt" and proof.get("anonymous_accepted") is True:
                category = (
                    "message_exchange"
                    if proof.get("message_exchange_confirmed") is True
                    and entry.get("publish_topic") == proof.get("topic")
                    and isinstance(proof.get("topic"), str)
                    else "login"
                )
            elif service == "snmp" and proof.get("public_community_read") is True:
                category = "management_read"
        elif condition == "signing" and service == "smb":
            if entry.get("require_signing") is True and proof.get("signing_required") is False:
                category = "signing_optional"
        elif condition == "credential" and service == "ssh":
            if (
                entry.get("reject_test_credential") is True
                and proof.get("test_credential_accepted") is True
            ):
                category = "login"
        elif condition == "certificate" and service == "tls":
            if entry.get("require_unexpired_certificate") is True and proof.get("expired") is True:
                category = "expired_certificate"
        return (category, record["policy_sha256"]) if category else None
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return None


def _eligible(feature, minimum):
    return (
        feature.source in {"manual", "rule"}
        and feature.confidence >= minimum
        and bool(feature.evidence.strip())
        and feature.evidence != "none observed"
    )


def calculate(category: str, profile: ContextProfile, policy: dict[str, Any]) -> dict[str, Any]:
    """Return each additive term, with context provenance and explicit bounds."""
    validate(policy)
    if category not in CATEGORIES:
        raise ConfigError("Unsupported network triage proof category")
    minimum = policy["min_confidence"]
    base = float(policy["base"][category])
    exposure = profile.exposure
    environment = profile.manual.get("environment")
    criticality = profile.manual.get("criticality")
    external = exposure.value == "internet_facing" and _eligible(exposure, minimum)
    test = (
        environment is not None
        and environment.source == "manual"
        and environment.value == "test"
        and _eligible(environment, minimum)
    )
    steps = (
        max(0, criticality.value - 3)
        if criticality is not None
        and type(criticality.value) is int
        and criticality.source == "manual"
        and 1 <= criticality.value <= 5
        and _eligible(criticality, minimum)
        else 0
    )
    terms = [
        {"label": "Observed access category", "value": base, "detail": category},
        {
            "label": "Internet-facing context",
            "value": float(policy["internet_facing_add"]) if external else 0.0,
            "detail": exposure.evidence
            if external
            else "No eligible external-exposure addition; internal does not prove segmentation.",
        },
        {
            "label": "Declared test environment",
            "value": -float(policy["test_environment_subtract"]) if test else 0.0,
            "detail": environment.evidence
            if test and environment is not None
            else "No eligible test-environment reduction.",
        },
        {
            "label": "Owner criticality above 3",
            "value": steps * float(policy["criticality_step_add"]),
            "detail": criticality.evidence
            if steps and criticality is not None
            else "No eligible criticality addition.",
        },
    ]
    total = sum(term["value"] for term in terms)
    value = round(min(100.0, max(0.0, total)), 1)
    terms.append(
        {
            "label": "Final native triage",
            "value": value,
            "detail": f"Clamp {total:g} to [0, 100], then round to one decimal. Uncalibrated policy hypothesis; not CVSS.",
        }
    )
    return {
        "version": VERSION,
        "category": category,
        "base": base,
        "risk": value,
        "steps": terms,
        "limitation": "Local operational triage hypothesis; not CVSS, exploit probability, proof of business impact or expert-validated ranking. No role, WAF, TLS or authentication mitigation bonus is inferred.",
    }


def for_finding(
    finding: Finding, profile: ContextProfile, weights: dict[str, Any]
) -> dict[str, Any] | None:
    policy = weights.get("service_network_triage")
    if finding.tool != "service-network" or policy is None or finding.cve_ids:
        return None
    if profile.host_ip != finding.host_ip:
        raise ConfigError("Native triage context must identify the affected host")
    selection = proof_category(finding)
    if selection is None:
        return None
    category, policy_hash = selection
    result = calculate(category, profile, policy)
    result["endpoint_policy_sha256"] = policy_hash
    result["finding_evidence_sha256"] = hashlib.sha256(finding.evidence.encode()).hexdigest()
    return result
