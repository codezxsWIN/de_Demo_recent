"""Pure report explanations of retained priority arithmetic, never replacement scores."""

import json
from math import isfinite
from typing import cast

from vulnassess import cvss31
from vulnassess.errors import ConfigError
from vulnassess.network_triage import VERSION as NATIVE_VERSION
from vulnassess.network_triage import calculate as native_calculate
from vulnassess.schema import ContextProfile
from vulnassess.scoring import risk, weights_hash

_REQUIRED = (
    "cvss_version_used",
    "native_fallback",
    "env_score",
    "env_modifications",
    "epss_percentile",
    "threat_multiplier",
    "kev",
    "risk",
    "weights_hash",
    "inputs",
)
_THREAT = (
    "base_multiplier",
    "epss_weight",
    "kev_multiplier",
    "kev_boost",
    "kev_floor_internet_facing",
)


def _number(value: object, label: str, maximum: float) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{label} must be a finite nonboolean number")
    try:
        number = float(cast("int | float", value))
    except OverflowError as error:
        raise ValueError(f"{label} must be finite") from error
    if not isfinite(number) or not 0 <= number <= maximum:
        raise ValueError(f"{label} must be finite and in [0, {maximum:g}]")
    return number


def _step(label: str, value: object, detail: str) -> dict:
    return {"label": label, "value": value, "detail": detail}


def _result(status: str, reason: str, steps: list, matched_hash: bool) -> dict:
    return {"status": status, "reason": reason, "steps": steps, "matched_hash": matched_hash}


def _requirements(value: object) -> str:
    if not isinstance(value, dict) or any(
        value.get(key) not in ("L", "M", "H") for key in ("CR", "IR", "AR")
    ):
        raise ValueError("Unsupported Environmental requirement mapping")
    return ", ".join(f"{key}={value[key]}" for key in ("CR", "IR", "AR"))


def _native_trace(score, weights):
    matched = False
    try:
        retained = score["inputs"]["native_triage"]
        if retained["version"] != NATIVE_VERSION:
            raise ValueError("Unsupported retained native triage version")
        value = _number(score["risk"], "risk", 100)
        if (
            not str(score.get("native_fallback", "")).startswith("service-network:")
            or score.get("cvss_version_used") is not None
            or score.get("cve_id") is not None
            or score.get("kev") is not False
            or score.get("threat_multiplier") is not None
        ):
            raise ValueError("Native triage contradicts retained scoring basis")
        if not isinstance(weights, dict) or weights_hash(weights) != score["weights_hash"]:
            return _result(
                "retained_only",
                "No matching retained policy; native triage arithmetic unverified.",
                [],
                False,
            )
        matched = True
        profile = ContextProfile.from_json({**score["inputs"], "host_ip": score["host_ip"]})
        expected = native_calculate(
            retained["category"], profile, weights["service_network_triage"]
        )
        label = f"service-network:{expected['category']}={expected['base']:g} (context-adjusted)"
        if score["native_fallback"] != label:
            raise ValueError("Retained native fallback label contradicts matching policy")
        for key in ("version", "category", "base", "risk", "steps"):
            if json.dumps(retained[key], sort_keys=True) != json.dumps(
                expected[key], sort_keys=True
            ):
                raise ValueError(
                    f"Retained native triage {key} contradicts matching policy arithmetic"
                )
        if value != expected["risk"]:
            raise ValueError("Retained risk contradicts native triage arithmetic")
        result = _result(
            "verified",
            "Matching policy reproduces native triage arithmetic; protocol evidence and business impact are not independently verified here.",
            expected["steps"],
            True,
        )
        result["computed_risk"] = value
        return result
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        OverflowError,
        RecursionError,
        ConfigError,
    ) as error:
        return _result("unavailable", str(error), [], matched)


def priority_trace(score: dict, weights: dict | None = None) -> dict:
    """Explain a CVSS 3.1 priority without modifying either argument.

    ``verified`` means the supplied policy hash matches and priority arithmetic
    reproduces both retained risk and multiplier, starting at retained env_score.
    It does not verify Environmental derivation, context, or external feed truth.
    ``retained_only`` means no matching policy was supplied; ``unavailable`` means
    required data is invalid, missing, unsupported, or contradicts the policy.
    matched_hash is a boolean, independent of arithmetic validity. computed_risk
    is included only for verified results. No policy is loaded or assumed.
    """
    if (
        isinstance(score, dict)
        and isinstance(score.get("inputs"), dict)
        and "native_triage" in score["inputs"]
    ):
        return _native_trace(score, weights)
    matched = False
    steps: list[dict] = []
    try:
        if not isinstance(score, dict):
            raise ValueError("score must be a mapping")
        missing = [key for key in _REQUIRED if key not in score]
        if missing:
            raise ValueError("Missing retained fields: " + ", ".join(missing))
        if score["native_fallback"] is not None:
            raise ValueError("Native fallback arithmetic is unsupported by this trace")
        if score["cvss_version_used"] != "3.1":
            raise ValueError("Only CVSS 3.1 environmental priority arithmetic is supported")
        env = _number(score["env_score"], "env_score", 10)
        retained_risk = _number(score["risk"], "risk", 100)
        percentile = score["epss_percentile"]
        if percentile is not None:
            percentile = _number(percentile, "epss_percentile", 1)
        retained_multiplier = score["threat_multiplier"]
        if retained_multiplier is not None:
            retained_multiplier = _number(retained_multiplier, "threat_multiplier", 1)
        if type(score["kev"]) is not bool:
            raise ValueError("kev must be a boolean")
        kev = score["kev"]
        for field, maximum in (("base_score", 10), ("epss", 1), ("epss_score", 1)):
            if score.get(field) is not None:
                _number(score[field], field, maximum)
        digest = score["weights_hash"]
        if not isinstance(digest, str) or not digest.strip():
            raise ValueError("Missing retained weights_hash")
        inputs = score["inputs"]
        if not isinstance(inputs, dict) or not isinstance(inputs.get("exposure"), dict):
            raise ValueError("Missing retained inputs.exposure")
        exposure = inputs["exposure"].get("value")
        if exposure not in ("internal", "internet_facing"):
            raise ValueError("Unsupported or missing retained exposure.value")
        modifications = score["env_modifications"]
        if not isinstance(modifications, dict):
            raise ValueError("env_modifications must be a mapping")
        for key, value in modifications.items():
            if (
                key not in cvss31.ALLOWED
                or key in cvss31.BASE_METRICS
                or not isinstance(value, str)
                or value not in cvss31.ALLOWED[key]
            ):
                raise ValueError("Unsupported retained Environmental metric")

        steps = [
            _step(
                "Environmental score",
                env,
                "Retained CVSS Environmental score; its derivation is not replayed here.",
            ),
            _step(
                "Environmental modifiers",
                ", ".join(f"{key}={value}" for key, value in sorted(modifications.items()))
                or "none recorded",
                "Retained vector modifications; no additive role bonus.",
            ),
            _step(
                "EPSS percentile",
                percentile,
                "Relative ranking, not exploit probability. The EPSS probability is a separate "
                "feed value and is not used in this multiplier.",
            ),
            _step("Retained threat multiplier", retained_multiplier, "Stored score value."),
            _step("Retained risk", retained_risk, "Stored priority; this trace never changes it."),
        ]
        controls = inputs.get("control_applicability", {})
        if not isinstance(controls, dict):
            raise ValueError("control_applicability must be a mapping")
        for name, decision in sorted(controls.items()):
            if not isinstance(name, str) or not isinstance(decision, dict):
                raise ValueError("Malformed retained control decision")
            status, reason = decision.get("status"), decision.get("reason_code")
            if not isinstance(status, str) or not isinstance(reason, str):
                raise ValueError("Missing retained control status or reason_code")
            steps.append(
                _step(
                    f"Control: {name}",
                    status,
                    f"Retained decision: {reason}. "
                    + (
                        "Withheld: no score reduction is justified by this observation."
                        if status == "withheld"
                        else "An observed control signal does not prove mitigation."
                    ),
                )
            )

        if weights is None:
            return _result(
                "retained_only", "No policy weights supplied; arithmetic unverified.", steps, False
            )
        if not isinstance(weights, dict):
            raise ValueError("weights must be a mapping or None")
        matched = weights_hash(weights) == digest
        if not matched:
            return _result(
                "retained_only",
                "Supplied weights_hash does not match retained "
                "score.weights_hash; arithmetic unverified.",
                steps,
                False,
            )
        if weights.get("version", 1) != 1 or type(weights.get("version", 1)) is not int:
            raise ValueError("Unsupported policy version")
        threat = weights.get("threat")
        if not isinstance(threat, dict) or any(key not in threat for key in _THREAT):
            raise ValueError("Missing required threat policy fields")
        policy = {
            key: _number(threat[key], f"threat.{key}", 100 if key in _THREAT[3:] else 1)
            for key in _THREAT
        }
        if policy["base_multiplier"] + policy["epss_weight"] > 1:
            raise ValueError("Threat base_multiplier + epss_weight exceeds 1")
        if policy["kev_multiplier"] < policy["base_multiplier"]:
            raise ValueError("KEV multiplier minimum is below base_multiplier")
        computed, multiplier = risk(
            env, percentile, kev, None, weights, exposure == "internet_facing"
        )
        if multiplier != retained_multiplier:
            raise ValueError("Retained threat_multiplier disagrees with matching policy arithmetic")
        if computed != retained_risk:
            raise ValueError("Retained risk disagrees with matching policy arithmetic")

        environmental = weights.get("environmental", {})
        manual = inputs.get("manual", {})
        environment = manual.get("environment", {}) if isinstance(manual, dict) else {}
        if isinstance(environment, dict) and environment.get("value") == "test":
            # Describe the supplied mapping only when it actually declares this override.
            if isinstance(environmental, dict) and environmental.get("environment_test"):
                test_requirements = _requirements(environmental["environment_test"])
                role_feature = inputs.get("role", {})
                role = role_feature.get("value") if isinstance(role_feature, dict) else None
                roles = environmental.get("role_requirements", {})
                role_detail = ""
                if isinstance(roles, dict) and isinstance(role, str) and role in roles:
                    role_detail = f"Configured {role} role: {_requirements(roles[role])}. "
                detail = (
                    role_detail + f"Test environment overrides role requirements with "
                    f"{test_requirements} before manual criticality steps. "
                    "The retained final modifiers are shown above. There is no numeric role "
                    "bonus. Environmental derivation is not replayed."
                )
                steps.append(_step("Test environment override", "test", detail))

        base = env * 10
        raw_multiplier = (
            None
            if percentile is None
            else policy["base_multiplier"] + policy["epss_weight"] * percentile
        )
        steps.append(_step("Scale to priority", base, f"{env:g} × 10 = {base:g}."))
        steps.append(
            _step(
                "EPSS multiplier",
                raw_multiplier,
                "EPSS missing: no percentile multiplier is scored."
                if percentile is None
                else f"{policy['base_multiplier']:g} + {policy['epss_weight']:g} × "
                f"{percentile:g} = {raw_multiplier:g}.",
            )
        )
        if kev:
            steps.append(
                _step(
                    "KEV multiplier minimum",
                    multiplier,
                    f"max({raw_multiplier if raw_multiplier is not None else 0:g}, "
                    f"{policy['kev_multiplier']:g}) = {multiplier:g}.",
                )
            )
        multiplied = base if multiplier is None else base * multiplier
        steps.append(
            _step(
                "Threat adjusted priority",
                multiplied,
                "No multiplier applied because EPSS is missing and KEV is false."
                if multiplier is None
                else f"{base:g} × {multiplier:g} = {multiplied:g}.",
            )
        )
        boosted = multiplied + (policy["kev_boost"] if kev else 0)
        steps.append(
            _step(
                "KEV boost",
                boosted,
                f"{multiplied:g} + {policy['kev_boost']:g} = {boosted:g}."
                if kev
                else "KEV is false: no boost.",
            )
        )
        floored = boosted
        if kev and exposure == "internet_facing":
            floor = policy["kev_floor_internet_facing"]
            floored = max(boosted, floor)
            steps.append(
                _step(
                    "Internet-facing KEV floor",
                    floored,
                    f"max({boosted:g}, {floor:g}) = {floored:g}; "
                    + ("binding." if boosted < floor else "nonbinding."),
                )
            )
        else:
            steps.append(
                _step(
                    "Internet-facing KEV floor",
                    boosted,
                    "Not applicable: requires both KEV and internet-facing exposure.",
                )
            )
        capped = min(floored, 100.0)
        steps.append(
            _step(
                "Priority cap",
                capped,
                f"min({floored:g}, 100) = {capped:g}; "
                + ("binding." if floored > 100 else "nonbinding."),
            )
        )
        steps.append(_step("Final priority", computed, "Round capped priority to one decimal."))
        result = _result(
            "verified",
            "Matching policy reproduces retained priority arithmetic "
            "from env_score; Environmental derivation and feed facts are not verified.",
            steps,
            True,
        )
        result["computed_risk"] = computed
        return result
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as error:
        return _result("unavailable", str(error), [], matched)
