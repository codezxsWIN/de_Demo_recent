"""Pure finding-scoped eligibility checks; observed host facts are never rewritten.

These checks fence the existing Environmental mappings, not prove mitigation.
Only finding-bound HTTP evidence can earn a web-control mapping. A header can
still be spoofed; every eligible control discloses that limitation.
"""

import re
from dataclasses import replace
from typing import Any

from vulnassess.protocols import is_http
from vulnassess.schema import ContextProfile, Feature, Finding, Service

POLICY_VERSION = "finding-scoped-controls-v2"
AUTH_CHALLENGE = re.compile(r"^HTTP/\d(?:\.\d)?\s+401\b", re.IGNORECASE | re.MULTILINE)


def _bound_http_url(finding: Finding) -> bool:
    """No DNS guessing: a URL alone must identify the recorded IP and TCP port."""
    # Recognise only the literal recorded endpoint, not arbitrary URLs. This
    # intentionally conservative predicate neither resolves DNS nor imports I/O.
    host = f"[{finding.host_ip}]" if ":" in finding.host_ip else finding.host_ip
    match = re.fullmatch(
        r"(https?)://" + re.escape(host) + r"(?::([0-9]{1,5}))?(?:[/?#][^\s]*)?",
        finding.url or "",
    )
    if match is None:
        return False
    port = int(match[2]) if match[2] is not None else (443 if match[1] == "https" else 80)
    return port == finding.port


def profile_for_finding(
    profile: ContextProfile,
    finding: Finding,
    services: tuple[Service, ...],
    minimum: float,
) -> tuple[ContextProfile, dict[str, dict[str, Any]]]:
    """Return an isolated scoring view and deterministic decisions with original quotes."""
    # Existing pure counterfactual callers may compare the same finding with
    # another host profile. They must not borrow that other host's controls.
    same_host = finding.host_ip == profile.host_ip
    matching = tuple(
        item for item in services if item.port == finding.port and item.protocol == finding.protocol
    )
    web = (
        same_host
        and finding.protocol == "tcp"
        and finding.port is not None
        and (any(is_http(item) for item in matching) or (not matching and _bound_http_url(finding)))
    )
    controls: dict[str, Feature] = {}
    decisions: dict[str, dict[str, Any]] = {}
    for key, feature in sorted(profile.controls.items()):
        scoped_feature = feature
        reason = "not_observed"
        status = "unknown"
        if feature.value:
            status = "withheld"
            if not same_host:
                reason = "control_belongs_to_other_host"
            elif feature.confidence < minimum:
                reason = "below_confidence_threshold"
            elif key == "tls":
                tls_service = next((item for item in matching if item.tls), None)
                if tls_service is not None:
                    status, reason = "observed", "tls_on_affected_service"
                    scoped_feature = replace(
                        feature,
                        evidence=tls_service.banner or f"{tls_service.port}/{tls_service.protocol}",
                    )
                else:
                    reason = "tls_not_bound_to_affected_service"
            elif not web:
                reason = "web_control_not_applicable_to_affected_service"
            elif feature.evidence == "none observed" or feature.evidence not in finding.evidence:
                reason = "control_not_bound_to_finding_evidence"
            elif key == "auth_required" and not (
                AUTH_CHALLENGE.search(finding.evidence)
                and "www-authenticate:" in finding.evidence.lower()
            ):
                reason = "login_or_denial_does_not_establish_authentication_precondition"
            else:
                status, reason = "eligible", "control_signal_in_affected_http_record"
        controls[key] = (
            scoped_feature
            if status in {"eligible", "observed"}
            else replace(feature, value=None, confidence=0.0)
        )
        decisions[key] = {
            "status": status,
            "reason_code": reason,
            "evidence": scoped_feature.evidence,
            "source": feature.source,
            "confidence": feature.confidence,
            "host_ip": finding.host_ip,
            "port": finding.port,
            "protocol": finding.protocol,
            "url": finding.url,
            "limitation": (
                "Observed control signals do not prove mitigation of the vulnerability; "
                "the configured Environmental mapping remains a hypothesis."
                if status == "eligible"
                else "No score reduction is justified by this observation."
            ),
        }
    return replace(profile, controls=controls), decisions
