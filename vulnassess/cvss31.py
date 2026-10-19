"""CVSS v3.1 base and environmental scoring, implemented from the specification.

Pure arithmetic, no I/O and no third-party package.
"""

from math import floor

PREFIX = "CVSS:3.1"
BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
ORDER = (
    "AV",
    "AC",
    "PR",
    "UI",
    "S",
    "C",
    "I",
    "A",
    "E",
    "RL",
    "RC",
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MPR",
    "MUI",
    "MS",
    "MC",
    "MI",
    "MA",
)

AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_VALUES = {"L": 0.77, "H": 0.44}
UI_VALUES = {"N": 0.85, "R": 0.62}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
CIA_VALUES = {"H": 0.56, "L": 0.22, "N": 0.0}
REQUIREMENT_VALUES = {"H": 1.5, "M": 1.0, "L": 0.5, "X": 1.0}
E_VALUES = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
RL_VALUES = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
RC_VALUES = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}

ALLOWED = {
    "AV": set(AV_VALUES),
    "AC": set(AC_VALUES),
    "PR": set(PR_UNCHANGED),
    "UI": set(UI_VALUES),
    "S": {"U", "C"},
    "C": set(CIA_VALUES),
    "I": set(CIA_VALUES),
    "A": set(CIA_VALUES),
    "E": set(E_VALUES),
    "RL": set(RL_VALUES),
    "RC": set(RC_VALUES),
    "CR": set(REQUIREMENT_VALUES),
    "IR": set(REQUIREMENT_VALUES),
    "AR": set(REQUIREMENT_VALUES),
    "MAV": set(AV_VALUES) | {"X"},
    "MAC": set(AC_VALUES) | {"X"},
    "MPR": set(PR_UNCHANGED) | {"X"},
    "MUI": set(UI_VALUES) | {"X"},
    "MS": {"U", "C", "X"},
    "MC": set(CIA_VALUES) | {"X"},
    "MI": set(CIA_VALUES) | {"X"},
    "MA": set(CIA_VALUES) | {"X"},
}


def roundup(value: float) -> float:
    """The specification's round-half-up-to-one-decimal helper."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (floor(integer / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.x vector. A 4.0 vector is rejected: its arithmetic is different."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3."):
        raise ValueError(f"not a CVSS v3.x vector: {vector!r}")
    metrics: dict[str, str] = {}
    for token in vector.split("/")[1:]:
        if ":" not in token:
            raise ValueError(f"malformed metric {token!r} in {vector!r}")
        key, _, value = token.partition(":")
        if key not in ALLOWED:
            raise ValueError(f"unknown metric {key!r} in {vector!r}")
        if key in metrics:
            raise ValueError(f"duplicate metric {key!r} in {vector!r}")
        if value not in ALLOWED[key]:
            raise ValueError(f"invalid value {key}:{value} in {vector!r}")
        metrics[key] = value
    missing = [key for key in BASE_METRICS if key not in metrics]
    if missing:
        raise ValueError(f"missing base metric(s) {missing} in {vector!r}")
    return metrics


def to_vector(metrics: dict[str, str]) -> str:
    parts = [f"{key}:{metrics[key]}" for key in ORDER if metrics.get(key) not in (None, "X")]
    return "/".join([PREFIX, *parts])


def _modified(metrics: dict[str, str], modified_key: str, base_key: str) -> str:
    value = metrics.get(modified_key, "X")
    return metrics[base_key] if value == "X" else value


def base_score(metrics: dict[str, str]) -> float:
    scope_changed = metrics["S"] == "C"
    iss = 1 - (
        (1 - CIA_VALUES[metrics["C"]])
        * (1 - CIA_VALUES[metrics["I"]])
        * (1 - CIA_VALUES[metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    privileges = (PR_CHANGED if scope_changed else PR_UNCHANGED)[metrics["PR"]]
    exploitability = (
        8.22
        * AV_VALUES[metrics["AV"]]
        * AC_VALUES[metrics["AC"]]
        * privileges
        * UI_VALUES[metrics["UI"]]
    )
    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def environmental_score(metrics: dict[str, str]) -> float:
    modified_scope_changed = _modified(metrics, "MS", "S") == "C"
    confidentiality = CIA_VALUES[_modified(metrics, "MC", "C")]
    integrity = CIA_VALUES[_modified(metrics, "MI", "I")]
    availability = CIA_VALUES[_modified(metrics, "MA", "A")]
    miss = min(
        1
        - (
            (1 - REQUIREMENT_VALUES[metrics.get("CR", "X")] * confidentiality)
            * (1 - REQUIREMENT_VALUES[metrics.get("IR", "X")] * integrity)
            * (1 - REQUIREMENT_VALUES[metrics.get("AR", "X")] * availability)
        ),
        0.915,
    )
    if modified_scope_changed:
        modified_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
    else:
        modified_impact = 6.42 * miss
    privileges = (PR_CHANGED if modified_scope_changed else PR_UNCHANGED)[
        _modified(metrics, "MPR", "PR")
    ]
    modified_exploitability = (
        8.22
        * AV_VALUES[_modified(metrics, "MAV", "AV")]
        * AC_VALUES[_modified(metrics, "MAC", "AC")]
        * privileges
        * UI_VALUES[_modified(metrics, "MUI", "UI")]
    )
    if modified_impact <= 0:
        return 0.0
    temporal = (
        E_VALUES[metrics.get("E", "X")]
        * RL_VALUES[metrics.get("RL", "X")]
        * RC_VALUES[metrics.get("RC", "X")]
    )
    combined = modified_impact + modified_exploitability
    if modified_scope_changed:
        return roundup(roundup(min(1.08 * combined, 10)) * temporal)
    return roundup(roundup(min(combined, 10)) * temporal)


def score_vector(vector: str) -> tuple[float, float]:
    metrics = parse(vector)
    return base_score(metrics), environmental_score(metrics)
