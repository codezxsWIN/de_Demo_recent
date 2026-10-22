"""Read-only interpretation of retained score facts; never calculate a priority."""

from typing import Any, Mapping

from vulnassess.errors import ConfigError
from vulnassess.schema import ScoreBreakdown

NO_CVE_INTELLIGENCE = (
    "No CVE association is recorded; EPSS and KEV are not applicable to this finding. "
    "CWE identifiers are classifications only; CWE definitions were not retrieved."
)


def threat_description(kev: bool, percentile: float | None) -> str:
    """Describe retained intelligence, not current compromise or absolute probability."""
    if type(kev) is not bool:
        raise ConfigError("retained KEV membership must be a boolean")
    if percentile is not None and (
        type(percentile) not in (int, float) or not 0 <= percentile <= 1
    ):
        raise ConfigError("retained EPSS percentile must be a finite number in [0, 1]")
    if kev:
        return "matched CVE listed in retained CISA KEV snapshot"
    if percentile is None:
        return "no exploitation data retained"
    ordinal = int(round(percentile * 100))
    suffix = (
        "th" if 10 <= ordinal % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(ordinal % 10, "th")
    )
    return f"EPSS relative ranking: {ordinal}{suffix} percentile (rounded)"


def missing_severity_basis(value: ScoreBreakdown | Mapping[str, Any]) -> bool:
    """Identify explicit unsupported historical priorities without rewriting them."""
    record = value.to_json() if isinstance(value, ScoreBreakdown) else value
    required = ("base_score", "env_score", "native_fallback")
    return (
        all(key in record and record[key] is None for key in required)
        and not record.get("base_vector")
        and not record.get("env_vector")
    )
