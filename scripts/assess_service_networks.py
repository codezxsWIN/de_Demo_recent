"""Assess the two running network-only labs and retain real scanner evidence.

Run with the optional lab Python environment. Start labs.service_networks first.
This command never starts or scans any target outside the two declared loopbacks.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from tempfile import mkstemp

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from labs.service_networks.catalog import ENVIRONMENTS  # noqa: E402
from vulnassess import live_assessment  # noqa: E402
from vulnassess.ui.server import UiApplication  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--provider",
        choices=("google", "groq", "groq_qwen", "openrouter", "ollama"),
        default="google",
    )
    parser.add_argument("--target", choices=tuple(ENVIRONMENTS))
    args = parser.parse_args()
    app = UiApplication(ROOT / "data/vulnassess.db", ROOT / "config", "scanme-2026-09-24")
    results = []
    for ip in [args.target] if args.target else ENVIRONMENTS:
        print(f"ASSESS {ip} — {ENVIRONMENTS[ip]['name']}", flush=True)
        check = app.target_check(ip)
        if check["status"] != "ready":
            raise SystemExit(f"Preflight refused: {check['reason']}")
        result = live_assessment.run(
            ip,
            check,
            ROOT / "config",
            provider=args.provider,
            database=ROOT / "data/vulnassess.db",
            on_progress=lambda stage, state, detail: print(
                f"  {stage}: {state} · {detail}", flush=True
            ),
        )
        directory = Path(result["evidence_directory"])
        payload = json.loads((directory / "case.json").read_text(encoding="utf-8"))
        labels = json.loads(
            (ROOT / "labs/service_networks/expected-policy-findings.json").read_text()
        )
        expected = (
            set(labels["targets"][ip])
            if payload.get("network_service_policy_sha256")
            else set(ENVIRONMENTS[ip]["checks"])
        )
        observed = {
            item["tool_native_id"]
            for item in payload["findings"]
            if item["tool"] == "service-network"
        }
        entry = {
            "ip": ip,
            "name": ENVIRONMENTS[ip]["name"],
            "scan_status": result["scan_status"],
            "expected_lab_checks": sorted(expected),
            "observed_lab_findings": sorted(observed),
            "missing_expected_conditions": sorted(expected - observed),
            "unexpected_conditions": sorted(observed - expected),
            "scored_findings": len(payload["scores"]),
            "unscored_findings": len(payload.get("unscored_findings", [])),
            "ai_status": result["ai_status"],
            "capture_id": directory.name,
            "report": f"http://127.0.0.1:8765/captures/{directory.name}/report",
            "coverage": payload["scanner_coverage"],
        }
        results.append(entry)
        print(json.dumps(entry), flush=True)
    output = ROOT / "data/service-networks"
    output.mkdir(parents=True, exist_ok=True)
    fd, path = mkstemp(prefix="verification-", suffix=".json", dir=output)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    print(f"Verification receipt: {path}", flush=True)
    return int(
        any(
            row["scan_status"] != "complete"
            or row["missing_expected_conditions"]
            or row["unexpected_conditions"]
            or row["unscored_findings"]
            or row["ai_status"] != "validated"
            for row in results
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
