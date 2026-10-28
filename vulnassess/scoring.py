"""The ranking formula. Pure: given the same inputs it returns the same numbers, always.

Only deterministic standard-library helpers and the project's pure modules are used;
no clock, file, socket or random source can reach a rank.
"""

import hashlib
import json
from dataclasses import replace
from math import isfinite
from typing import Any, Sequence, cast

from vulnassess import cvss31
from vulnassess.control_applicability import POLICY_VERSION, profile_for_finding
from vulnassess.errors import ConfigError, IntelUnavailable
from vulnassess.network_triage import for_finding as network_triage
from vulnassess.schema import ContextProfile, Enrichment, Feature, Finding, ScoreBreakdown, Service
from vulnassess.score_facts import threat_description

Weights = dict[str, Any]

STEP_UP = {"L": "M", "M": "H", "H": "H"}
REQUIREMENT_KEYS = ("CR", "IR", "AR")
_ROLES = (
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
)
_CONTROLS = ("waf", "auth_required", "tls", "rate_limiting")


def _number(
    value: object, label: str, minimum: float | None = None, maximum: float | None = None
) -> float:
    """Reject coercion and non-finite values before any ranking arithmetic."""
    if type(value) not in (int, float):
        raise ConfigError(f"{label} must be a finite number, not a boolean or numeric string")
    try:
        number = float(cast("int | float", value))
    except OverflowError as error:
        raise ConfigError(f"{label} must be a finite number") from error
    if (
        not isfinite(number)
        or (minimum is not None and number < minimum)
        or (maximum is not None and number > maximum)
    ):
        raise ConfigError(f"{label} must be a finite number in [{minimum}, {maximum}]")
    return number


def _text(value: object, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label} must be a nonblank string")


def _optional_string(value: object, label: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ConfigError(f"{label} must be a string or null")


def _validate_cves(values: object) -> None:
    if not isinstance(values, tuple):
        raise ConfigError("finding.cve_ids must be the canonical identifier tuple")
    for cve in cast("tuple[object, ...]", values):
        _text(cve, "finding.cve_ids entry")


def _feature(value: object, label: str) -> Feature:
    if not isinstance(value, Feature):
        raise ConfigError(f"{label} must be a Feature")
    _number(value.confidence, f"{label}.confidence", 0, 1)
    _text(value.evidence, f"{label}.evidence")
    if value.source not in ("rule", "manual"):
        raise ConfigError(
            f"{label}: canonical scoring from learned context requires a human-approved "
            "context-source ADR"
        )
    return value


def _validate_profile(profile: object, *, legacy_optional_criticality: bool = False) -> None:
    if not isinstance(profile, ContextProfile):
        raise ConfigError("context profile must be a ContextProfile")
    _text(profile.host_ip, "context.host_ip")
    role = _feature(profile.role, "context.role")
    if not isinstance(role.value, str) or role.value not in _ROLES:
        raise ConfigError("context.role.value is not a declared role")
    exposure = _feature(profile.exposure, "context.exposure")
    if exposure.value not in ("internal", "internet_facing"):
        raise ConfigError("context.exposure.value must be internal or internet_facing")
    _optional_string(profile.segment, "context.segment")
    for name, allowed in (("controls", _CONTROLS), ("manual", ("criticality", "environment"))):
        values: object = getattr(profile, name)
        if not isinstance(values, dict):
            raise ConfigError(f"context.{name} must be a feature mapping")
        for key, value in cast("dict[object, object]", values).items():
            if not isinstance(key, str) or key not in allowed:
                raise ConfigError(f"context.{name} contains an undeclared key")
            feature = _feature(value, f"context.{name}.{key}")
            fact = feature.value
            if name == "controls":
                vendor = key == "waf" and isinstance(fact, str) and bool(fact.strip())
                if fact is not None and type(fact) is not bool and not vendor:
                    raise ConfigError(f"context.controls.{key} has an invalid value type")
            elif key == "environment" and fact not in ("prod", "test"):
                raise ConfigError("context.manual.environment must be prod or test")
            elif key == "criticality" and not legacy_optional_criticality:
                if type(fact) is not int or not 1 <= fact <= 5:
                    raise ConfigError("context.manual.criticality must be an integer in [1, 5]")


def _validate_enrichment(item: object) -> None:
    if not isinstance(item, Enrichment):
        raise ConfigError("enrichment must be an Enrichment")
    for name in ("finding_id", "cve_id"):
        _text(getattr(item, name), f"enrichment.{name}")
    if item.match_method not in ("explicit", "cpe_range"):
        raise ConfigError("enrichment.match_method must be explicit or cpe_range")
    _number(item.match_confidence, "enrichment.match_confidence", 0, 1)
    for name, maximum in (
        ("cvss31_base", 10),
        ("cvss40_base", 10),
        ("epss", 1),
        ("epss_percentile", 1),
    ):
        value = getattr(item, name)
        if value is not None:
            _number(value, f"enrichment.{name}", 0, maximum)
    if type(item.kev) is not bool:
        raise ConfigError("enrichment.kev must be a boolean")
    for name in ("cvss31_vector", "cvss40_vector"):
        value = getattr(item, name)
        if value is not None:
            _text(value, f"enrichment.{name}")
    if item.cvss31_vector is not None:
        try:
            base = cvss31.base_score(cvss31.parse(item.cvss31_vector))
        except ValueError as error:
            raise ConfigError(f"enrichment.cvss31_vector: {error}") from error
        if item.cvss31_base is not None and item.cvss31_base != base:
            raise ConfigError("enrichment.cvss31_base contradicts cvss31_vector")


def weights_hash(weights: Weights) -> str:
    payload = json.dumps(weights, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def environmental_vector(
    base_vector: str, profile: ContextProfile, weights: Weights
) -> tuple[str, dict[str, str]]:
    """Auto-fill the CVSS Environmental metrics from inferred context."""
    # This low-level helper historically ignores malformed optional criticality.
    # Canonical score() is stricter and rejects it before producing any priority.
    _validate_profile(profile, legacy_optional_criticality=True)
    metrics = cvss31.parse(base_vector)
    settings = weights["environmental"]
    minimum = float(settings.get("min_confidence_to_apply", 0.5))
    modifications: dict[str, str] = {}

    def apply(changes: dict[str, str] | None) -> None:
        for key, value in (changes or {}).items():
            metrics[key] = value
            modifications[key] = value

    exposure = profile.exposure
    if exposure.value == "internal" and metrics["AV"] == "N" and exposure.confidence >= minimum:
        apply(settings.get("internal_when_av_network"))

    waf = profile.controls.get("waf")
    if waf is not None and waf.value and waf.confidence >= minimum:
        apply(settings.get("waf_present"))

    auth = profile.controls.get("auth_required")
    if auth is not None and auth.value and metrics["PR"] == "N" and auth.confidence >= minimum:
        apply(settings.get("auth_required_when_pr_none"))

    role_requirements = settings.get("role_requirements", {})
    role = profile.role.value if profile.role.confidence >= minimum else "unknown"
    requirements = dict(role_requirements.get(role) or role_requirements.get("unknown") or {})

    environment = profile.manual.get("environment")
    if environment is not None and environment.value == "test":
        requirements = dict(settings.get("environment_test") or requirements)

    criticality = profile.manual.get("criticality")
    if criticality is not None and type(criticality.value) is int and 1 <= criticality.value <= 5:
        steps = criticality.value - int(settings.get("criticality_step_above", 3))
        for _ in range(max(steps, 0)):
            requirements = {key: STEP_UP[value] for key, value in requirements.items()}

    apply({key: requirements[key] for key in REQUIREMENT_KEYS if key in requirements})
    return cvss31.to_vector(metrics), modifications


def risk(
    env_score: float | None,
    epss_percentile: float | None,
    kev: bool,
    native_key: float | None,
    weights: Weights,
    internet_facing: bool,
) -> tuple[float, float | None]:
    """Combine environmental severity with observed threat. Missing EPSS stays unscored."""
    if env_score is not None:
        _number(env_score, "env_score", 0, 10)
    if native_key is not None:
        _number(native_key, "native_key", 0, 100)
    for label, value in (("kev", kev), ("internet_facing", internet_facing)):
        if type(value) is not bool:
            raise ConfigError(f"{label} must be a boolean")
    if epss_percentile is not None and (
        type(epss_percentile) not in (float, int) or not 0 <= epss_percentile <= 1
    ):
        raise ConfigError("EPSS percentile must be a finite number in [0, 1]")
    threat = weights["threat"]
    if env_score is None:
        base = float(native_key or 0.0)
        multiplier: float | None = None
    else:
        base = float(env_score) * 10.0
        multiplier = (
            None
            if epss_percentile is None
            else float(threat["base_multiplier"])
            + float(threat["epss_weight"]) * float(epss_percentile)
        )
        if kev:
            multiplier = max(multiplier or 0.0, float(threat["kev_multiplier"]))

    value = base if multiplier is None else base * multiplier
    if kev:
        value += float(threat["kev_boost"])
        if internet_facing:
            value = max(value, float(threat["kev_floor_internet_facing"]))
    return round(min(value, 100.0), 1), multiplier


def band(value: float, weights: Weights) -> str:
    _number(value, "band value")
    bands = weights["bands"]
    if value >= float(bands["Critical"]):
        return "Critical"
    if value >= float(bands["High"]):
        return "High"
    if value >= float(bands["Medium"]):
        return "Medium"
    return "Low"


def _threat_phrase(breakdown_kev: bool, percentile: float | None) -> str:
    return threat_description(breakdown_kev, percentile)


def describe(breakdown: ScoreBreakdown, profile: ContextProfile) -> str:
    """The deterministic one-line reason. Stands in for the model; invents nothing."""
    exposure = "internet-facing" if profile.exposure.value == "internet_facing" else "internal"
    role = str(profile.role.value).replace("_", " ")
    parts = [f"{exposure} {role}"]
    environment = profile.manual.get("environment")
    if environment is not None and environment.value == "test":
        parts.append("test environment")
    parts.append(_threat_phrase(breakdown.kev, breakdown.epss_percentile))
    waf = profile.controls.get("waf")
    if waf is not None and waf.value:
        if breakdown.inputs.get("context_policy") == POLICY_VERSION:
            parts.append(f"{waf.value} signal on affected HTTP record (mitigation unverified)")
        elif breakdown.inputs.get("context_policy") == "finding-scoped-controls-v1":
            parts.append(
                f"{waf.value} recorded signal under legacy eligibility policy (mitigation unverified)"
            )
        else:
            parts.append(f"{waf.value} recorded signal (applicability and mitigation unverified)")
    else:
        parts.append("no compensating control observed")
    return f"{breakdown.band}: " + ", ".join(parts) + "."


def fix_text(
    finding: Finding, enrichment: Enrichment | None, host_services: tuple[Service, ...]
) -> str:
    service = next(
        (item for item in host_services if finding.port and item.port == finding.port), None
    )
    if enrichment is not None and enrichment.version_end and service and service.product:
        reference = enrichment.patch_references[0] if enrichment.patch_references else ""
        suffix = f" ({reference})" if reference else ""
        version = service.version or ""
        boundary = (
            "inclusive"
            if enrichment.version_end_inclusive is True
            else "exclusive"
            if enrichment.version_end_inclusive is False
            else "inclusion unknown"
        )
        return (
            f"Verify the vendor-fixed release for {service.product} {version}".rstrip()
            + f" before upgrading{suffix}. The matched vulnerable range ends at "
            + f"{enrichment.version_end} ({boundary}); this boundary alone does not "
            + "establish a fixed release."
        )
    if enrichment is not None and enrichment.patch_references:
        return f"Apply the vendor fix: {enrichment.patch_references[0]}"
    if finding.reference_urls:
        return f"Review {finding.reference_urls[0]}"
    if finding.cwe_ids:
        return f"Remediate {finding.cwe_ids[0]}: {finding.title}"
    return f"Review: {finding.title}"


def best_enrichment(enrichments: list[Enrichment]) -> Enrichment | None:
    """When several CVEs matched one finding, score the worst of them."""
    if not enrichments:
        return None
    for item in enrichments:
        _validate_enrichment(item)
        if item.finding_id != enrichments[0].finding_id:
            raise ConfigError("enrichment.finding_id must identify one finding during selection")
    return min(
        enrichments,
        key=lambda item: (not item.kev, -(item.cvss31_base or 0.0), item.cve_id),
    )


def _native_value(finding: Finding, weights: Weights) -> tuple[float | None, str | None]:
    # YAML config is dynamically shaped; the casts name the shapes this formula handles.
    fallback = cast("dict[str, Any] | None", weights.get("native_fallback", {}))
    if fallback is None:
        return None, None
    table = cast("dict[str, Any] | float | int | str | None", fallback.get(finding.tool))
    if table is None:
        return None, None
    if isinstance(table, dict):
        severity = finding.native_severity
        value = table.get(severity or "")
        if value is None:
            return None, None
        return float(value), f"{finding.tool}:{severity}={value}"
    return float(table), f"{finding.tool}:default={table}"


def score(
    finding: Finding,
    enrichment: Enrichment | None,
    profile: ContextProfile,
    host_services: tuple[Service, ...],
    weights: Weights,
) -> ScoreBreakdown:
    _validate_profile(profile)
    _text(finding.id, "finding.id")
    _text(finding.host_ip, "finding.host_ip")
    _validate_cves(finding.cve_ids)
    if profile.host_ip != finding.host_ip:
        raise ConfigError("context.host_ip does not match finding.host_ip")
    _optional_string(finding.native_severity, "finding.native_severity")
    if enrichment is not None:
        _validate_enrichment(enrichment)
        if enrichment.finding_id != finding.id:
            raise ConfigError("enrichment.finding_id does not match finding.id")
        if enrichment.match_method == "explicit" and enrichment.cve_id not in finding.cve_ids:
            raise ConfigError("enrichment.cve_id is not explicit in this finding's cve_ids")
    observed_controls = {key: value.to_json() for key, value in sorted(profile.controls.items())}
    profile, control_decisions = profile_for_finding(
        profile,
        finding,
        host_services,
        float(weights["environmental"].get("min_confidence_to_apply", 0.5)),
    )
    internet_facing = profile.exposure.value == "internet_facing"
    inputs: dict[str, Any] = {
        "role": profile.role.to_json(),
        "exposure": profile.exposure.to_json(),
        "controls": {key: value.to_json() for key, value in sorted(profile.controls.items())},
        "manual": {key: value.to_json() for key, value in sorted(profile.manual.items())},
        "observed_controls": observed_controls,
        "control_applicability": control_decisions,
        "context_policy": POLICY_VERSION,
    }
    digest = weights_hash(weights)

    if enrichment is not None and enrichment.cvss31_vector:
        metrics = cvss31.parse(enrichment.cvss31_vector)
        base = cvss31.base_score(metrics)
        env_vector, modifications = environmental_vector(enrichment.cvss31_vector, profile, weights)
        for key, metric in (("waf", "MAC"), ("auth_required", "MPR")):
            if key in control_decisions and metric in modifications:
                control_decisions[key]["status"] = "applied"
                control_decisions[key]["metric"] = metric
        env = cvss31.environmental_score(cvss31.parse(env_vector))
        value, multiplier = risk(
            env, enrichment.epss_percentile, enrichment.kev, None, weights, internet_facing
        )
        breakdown = ScoreBreakdown(
            finding_id=finding.id,
            host_ip=finding.host_ip,
            cve_id=enrichment.cve_id,
            cvss_version_used="3.1",
            base_vector=enrichment.cvss31_vector,
            base_score=base,
            env_vector=env_vector,
            env_score=env,
            env_modifications=modifications,
            epss_percentile=enrichment.epss_percentile,
            threat_multiplier=multiplier,
            kev=enrichment.kev,
            native_fallback=None,
            risk=value,
            band=band(value, weights),
            inputs=inputs,
            weights_hash=digest,
            reason="",
            fix=fix_text(finding, enrichment, host_services),
        )
    else:
        native_key, label = _native_value(finding, weights)
        if native_key is None:
            raise IntelUnavailable(
                f"MISSING: severity basis for finding {finding.id}; a usable CVSS 3.1 "
                f"vector or explicit native_fallback.{finding.tool} mapping for the "
                "reported severity is required; no priority or Low band was assigned"
            )
        triage = network_triage(finding, profile, weights) if enrichment is None else None
        if triage is not None:
            native_key = triage["risk"]
            label = f"service-network:{triage['category']}={triage['base']:g} (context-adjusted)"
            inputs["native_triage"] = triage
        percentile = enrichment.epss_percentile if enrichment is not None else None
        kev = enrichment.kev if enrichment is not None else False
        value, multiplier = risk(None, percentile, kev, native_key, weights, internet_facing)
        breakdown = ScoreBreakdown(
            finding_id=finding.id,
            host_ip=finding.host_ip,
            cve_id=enrichment.cve_id if enrichment is not None else None,
            cvss_version_used=None,
            base_vector=None,
            base_score=None,
            env_vector=None,
            env_score=None,
            env_modifications={},
            epss_percentile=percentile,
            threat_multiplier=multiplier,
            kev=kev,
            native_fallback=label,
            risk=value,
            band=band(value, weights),
            inputs=inputs,
            weights_hash=digest,
            reason="",
            fix=fix_text(finding, enrichment, host_services),
        )

    reason = describe(breakdown, profile)
    if "native_triage" in inputs:
        triage = inputs["native_triage"]
        adjustments = "; ".join(
            f"{step['label']} {step['value']:+g}" for step in triage["steps"][1:-1]
        )
        reason = (
            f"{breakdown.band}: native triage {triage['category']} base {triage['base']:g}; "
            f"{adjustments}; final {breakdown.risk:g}/100. "
            "Uncalibrated local policy, not CVSS or exploit probability; "
            "host role and unrelated control signals do not adjust this score."
        )
    withheld = sorted(
        key for key, decision in control_decisions.items() if decision["status"] == "withheld"
    )
    if withheld:
        reason = reason.rstrip(".") + f"; control signals withheld: {', '.join(withheld)}."
    return replace(breakdown, reason=reason)


def score_available(
    findings: Sequence[Finding],
    enrichments: Sequence[Enrichment],
    profile: ContextProfile,
    host_services: tuple[Service, ...],
    weights: Weights,
) -> tuple[list[ScoreBreakdown], list[dict[str, str]]]:
    """Retain unsupported findings alongside, never inside, the numerical queue."""
    _validate_profile(profile)
    for item in enrichments:
        _validate_enrichment(item)
    scores: list[ScoreBreakdown] = []
    unscored: list[dict[str, str]] = []
    for finding in findings:
        try:
            result = score(
                finding,
                best_enrichment([item for item in enrichments if item.finding_id == finding.id]),
                profile,
                host_services,
                weights,
            )
        except IntelUnavailable as error:
            unscored.append(
                {"finding_id": finding.id, "title": finding.title, "reason": str(error)}
            )
        else:
            scores.append(result)
    return sorted(scores, key=lambda item: (-item.risk, item.finding_id)), unscored
