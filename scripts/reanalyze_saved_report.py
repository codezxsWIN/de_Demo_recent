"""Re-analyze a verified capture without scanners or changing the original receipt."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnassess import analyst  # noqa: E402
from vulnassess.capture_reanalysis import reanalyze  # noqa: E402, F401

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
