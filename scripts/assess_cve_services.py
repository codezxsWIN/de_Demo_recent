"""Assess the two exact local CVE lab endpoints through the ordinary live pipeline.

Evaluation expectations are read only after scanning; never passed to detection.
"""

import json
import os
import sys
from pathlib import Path
from tempfile import mkstemp

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vulnassess import capture_history, live_assessment  # noqa: E402
from vulnassess.ui.server import UiApplication  # noqa: E402


def main():
    application = UiApplication(ROOT / "data/vulnassess.db", ROOT / "config", "scanme-2026-09-24")
    results = []
    for ip in ("127.0.0.4", "127.0.0.5"):
        check = application.target_check(ip)
        if check["status"] != "ready":
            raise RuntimeError("CVE lab preflight refused: " + check["reason"])
        print("ASSESS " + ip, flush=True)
        result = live_assessment.run(
            ip,
            check,
            ROOT / "config",
            provider="google",
            database=ROOT / "data/vulnassess.db",
            on_progress=lambda stage, state, detail: print(
                f"{stage}: {state}: {detail}", flush=True
            ),
        )
        directory = Path(result["evidence_directory"])
        record = capture_history.load(directory.parent, directory.name)
        payload = record["payload"]
        results.append(
            {
                "ip": ip,
                "capture_id": directory.name,
                "scan_status": result["scan_status"],
                "ai_status": result["ai_status"],
                "services": payload["hosts"][0]["services"],
                "candidate_cves": sorted(
                    {
                        cve
                        for item in payload["findings"]
                        if item["tool"] == "nvd-cpe"
                        for cve in item["cve_ids"]
                    }
                ),
                "enrichments": len(payload["enrichments"]),
                "scores": len(payload["scores"]),
                "unscored": len(payload["unscored_findings"]),
                "report": f"http://127.0.0.1:8765/captures/{directory.name}/report",
            }
        )
    ground_truth = json.loads((ROOT / "labs/cve_services/evaluation.json").read_text())
    reference = ground_truth["candidate_cve"]
    compared = {
        "reference_cve": reference,
        "reference_advisory": ground_truth["primary_advisory"],
        "affected_version_association_present": reference in results[0]["candidate_cves"],
        "reference_patched_version_association_absent": reference
        not in results[1]["candidate_cves"],
        "notice": "Evaluation ground truth was not provided to detection. The reference patch is not a claim that other CVEs are absent; exploitation was not tested.",
    }
    passed = (
        compared["affected_version_association_present"]
        and compared["reference_patched_version_association_absent"]
        and all(
            row["scan_status"] == "complete"
            and row["ai_status"] == "validated"
            and not row["unscored"]
            and row["candidate_cves"]
            for row in results
        )
    )
    receipt = {
        "status": "passed" if passed else "failed",
        "assessments": results,
        "evaluation": compared,
    }
    descriptor, path = mkstemp(
        prefix="cve-assessment-verification-", suffix=".json", dir=ROOT / "data/service-networks"
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
    print(json.dumps(receipt), flush=True)
    print("Receipt: " + path, flush=True)
    return int(not passed)


if __name__ == "__main__":
    raise SystemExit(main())
