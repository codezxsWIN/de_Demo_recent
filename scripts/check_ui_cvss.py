"""Build and verify the deterministic synthetic browser-CVSS regression fixture."""

import argparse
import json
import random
import shutil
import subprocess
import sys
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "synthetic" / "synthetic_cvss31_vectors.json"
CHECK = ROOT / "tests" / "synthetic" / "synthetic_cvss31_check.mjs"
PINNED = (
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:A",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L/MAV:A",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MS:C/MPR:H/E:F/RL:O/RC:R",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
)


def generate() -> None:
    sys.path.insert(0, str(ROOT))
    from vulnassess import cvss31, scoring
    from vulnassess.schema import ContextProfile, Feature
    from vulnassess.settings import Settings

    random_source = random.Random(20260913)
    vectors: list[str] = list(PINNED)
    while len(vectors) < 211:
        metrics = {
            key: random_source.choice(sorted(cvss31.ALLOWED[key])) for key in cvss31.BASE_METRICS
        }
        for key in cvss31.ORDER[8:]:
            if random_source.choice((True, False)):
                metrics[key] = random_source.choice(sorted(cvss31.ALLOWED[key]))
        vector = cvss31.to_vector(metrics)
        if vector not in vectors:
            vectors.append(vector)
    document = {
        "source": "synthetic pure arithmetic regression cases; not scanner or feed evidence",
        "seed": 20260913,
        "pinned": len(PINNED),
        "vectors": [
            {
                "vector": vector,
                "base": cvss31.score_vector(vector)[0],
                "environmental": cvss31.score_vector(vector)[1],
            }
            for vector in vectors
        ],
    }
    weights = Settings(ROOT / "config").weights
    profile = ContextProfile(
        host_ip="synthetic-arithmetic-only",
        role=Feature("unknown", 1.0, "manual", "synthetic arithmetic input"),
        exposure=Feature("internal", 1.0, "manual", "synthetic arithmetic input"),
        controls={"waf": Feature(False, 1.0, "manual", "synthetic arithmetic input")},
        manual={"criticality": Feature(4, 1.0, "manual", "synthetic arithmetic input")},
    )
    cases = []
    for role, exposure, environment, waf, kev, percentile in product(
        ("unknown", "web_frontend", "database"),
        ("internal", "internet_facing"),
        ("test", "prod"),
        (False, True),
        (False, True),
        (None, 0.2, 0.9987),
    ):
        changed = ContextProfile.from_json(profile.to_json())
        changed.role = Feature(role, 1.0, "manual", "synthetic arithmetic input")
        changed.exposure = Feature(exposure, 1.0, "manual", "synthetic arithmetic input")
        changed.controls["waf"] = Feature(waf, 1.0, "manual", "synthetic arithmetic input")
        changed.manual["environment"] = Feature(
            environment, 1.0, "manual", "synthetic arithmetic input"
        )
        vector, _ = scoring.environmental_vector(PINNED[0], changed, weights)
        base, environmental = cvss31.score_vector(vector)
        risk, multiplier = scoring.risk(
            environmental, percentile, kev, None, weights, exposure == "internet_facing"
        )
        cases.append(
            {
                "vector": PINNED[0],
                "profile": profile.to_json(),
                "changes": {
                    "role": role,
                    "exposure": exposure,
                    "environment": environment,
                    "waf": waf,
                    "kev": kev,
                    "epss": percentile,
                },
                "expected": {
                    "base": base,
                    "environmental": environmental,
                    "risk": risk,
                    "band": scoring.band(risk, weights),
                    "multiplier": multiplier,
                    "vector": vector,
                },
            }
        )
    document["sandbox_weights"] = weights
    document["sandbox_cases"] = cases
    FIXTURE.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"GENERATED: {FIXTURE.relative_to(ROOT).as_posix()}")


def verify_python() -> None:
    sys.path.insert(0, str(ROOT))
    from vulnassess import cvss31

    if not FIXTURE.is_file():
        raise FileNotFoundError(f"MISSING: {FIXTURE}")
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert len(document["vectors"]) == 211
    assert document["pinned"] == 11
    for row in document["vectors"]:
        assert cvss31.score_vector(row["vector"]) == (row["base"], row["environmental"]), row
    print("PYTHON CVSS: 211 of 211 match")


def verify_javascript() -> None:
    node = shutil.which("node")
    if node is None:
        raise FileNotFoundError("MISSING: node on PATH; no dependency is installed by this check")
    if not CHECK.is_file():
        raise FileNotFoundError(f"MISSING: {CHECK}")
    subprocess.run([node, str(CHECK), str(FIXTURE)], cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--generate", action="store_true", help="regenerate only the synthetic arithmetic fixture"
    )
    arguments = parser.parse_args()
    if arguments.generate:
        generate()
    verify_python()
    verify_javascript()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
