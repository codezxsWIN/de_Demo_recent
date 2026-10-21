"""Re-analyze a verified capture without scanners or changing the original receipt."""

import argparse
import copy
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnassess import analyst, capture_history, live_assessment  # noqa: E402
from vulnassess.errors import ConfigError  # noqa: E402


def reanalyze(root, identity, provider, progress, *, cloud_sharing_authorized=False):
    if provider not in analyst.PROVIDERS:
        raise ConfigError("Unknown reanalysis provider")
    if provider != "ollama" and not cloud_sharing_authorized:
        raise ConfigError("Cloud reanalysis requires explicit authorization")
    root = Path(root).resolve()
    source = capture_history.load(root, identity)
    source_dir = root / identity
    manifest = json.loads((source_dir / "manifest.json").read_text(encoding="utf-8"))
    if len(manifest["files"]) >= 20 and "analysis-source.json" not in manifest["files"]:
        raise ConfigError("Reanalysis source reference exceeds the evidence file budget")
    directory = Path(tempfile.mkdtemp(prefix="assessment-", dir=root))
    # The strict reader has verified these exact files and names. Copy only the
    # manifest's evidence set, never local credentials or unrelated artifacts.
    for name in manifest["files"]:
        shutil.copyfile(source_dir / name, directory / name)
    reference = json.dumps(
        {
            "source_capture": identity,
            "source_snapshot_hash": source["snapshot_hash"],
            "source_intelligence_recorded_at": source.get("analysis_source", {}).get(
                "source_intelligence_recorded_at", source["intelligence_recorded_at"]
            ),
            "mode": "retained-evidence reanalysis; no scanner or feed refresh",
        },
        sort_keys=True,
    ).encode()
    (directory / "analysis-source.json").write_bytes(reference)
    manifest["files"]["analysis-source.json"] = hashlib.sha256(reference).hexdigest()
    if source["captured_at"] is not None:
        manifest["captured_at"] = source["captured_at"]
    else:
        manifest.pop("captured_at", None)
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    baseline = copy.deepcopy(source["result"])
    baseline.setdefault(
        "services",
        next(
            (
                host.get("services", [])
                for host in source["payload"]["hosts"]
                if host["ip"] == baseline["resolved_ip"]
            ),
            [],
        ),
    )
    baseline.update(analyst=None, ai_status="not_attempted", ai_attempts=[])
    baseline.pop("used_provider", None)
    baseline["selected_provider"] = provider
    baseline["assessment_summary"] = live_assessment.assessment_summary(
        baseline["target"], baseline["resolved_ip"], baseline["services"], source["payload"]
    )
    baseline["assessment_summary"].update(
        scan_status=baseline["scan_status"], ai_status="not_attempted", ai_attempts=[]
    )
    capture_history.save(
        directory,
        baseline,
        config_hash=source["configuration_hash"],
        captured_at_override=source["captured_at"],
    )
    outcome = analyst.analyze_optional(
        source["payload"],
        baseline["resolved_ip"],
        provider,
        progress,
        allow_fallback=False,
        cloud_sharing_authorized=cloud_sharing_authorized,
    )
    result = {**baseline, **outcome}
    result["assessment_summary"] = live_assessment.assessment_summary(
        baseline["target"],
        baseline["resolved_ip"],
        baseline["services"],
        source["payload"],
        outcome["analyst"],
    )
    result["assessment_summary"].update(
        scan_status=baseline["scan_status"],
        ai_status=outcome["ai_status"],
        ai_attempts=outcome["ai_attempts"],
    )
    capture_history.save(directory, result, final=True)
    return capture_history.load(root, directory.name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture")
    parser.add_argument("--root", default="data/live/raw")
    parser.add_argument("--provider", choices=analyst.PROVIDERS, default="ollama")
    parser.add_argument(
        "--allow-cloud",
        action="store_true",
        help="Authorize sending bounded evidence to the selected cloud provider",
    )
    args = parser.parse_args()
    if args.provider != "ollama" and not args.allow_cloud:
        parser.error("Cloud reanalysis requires explicit --allow-cloud")
    record = reanalyze(
        args.root,
        args.capture,
        args.provider,
        lambda stage, state, detail: print(f"{stage}: {state}: {detail}", flush=True),
        cloud_sharing_authorized=args.allow_cloud,
    )
    print(
        json.dumps(
            {
                "capture_id": record["capture_id"],
                "source": args.capture,
                "ai_status": record["result"]["ai_status"],
                "scanner_launched": False,
                "report": f"http://127.0.0.1:8765/captures/{record['capture_id']}/report",
            }
        )
    )
