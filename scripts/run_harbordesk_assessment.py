"""Run the existing assessment pipeline against the complete local fixture lab."""

import argparse
import json
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

from vulnassess.ui.server import UiApplication


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=["google", "groq", "ollama"], required=True)
    parser.add_argument(
        "--share-evidence",
        action="store_true",
        help="Explicitly allow bounded fictional lab evidence to the selected cloud provider",
    )
    args = parser.parse_args()
    if args.provider != "ollama" and not args.share_evidence:
        parser.error(
            "Cloud analysis requires --share-evidence. Only bounded fictional lab evidence is sent."
        )
    root = Path(__file__).resolve().parents[1]
    with build_opener(ProxyHandler({})).open(
        "http://127.0.0.1:8787/__lab__/health", timeout=5
    ) as response:
        health = json.load(response)
    if health.get("lab_id") != "harbordesk-local-v1" or health.get("network_lab") is not True:
        parser.error("Start python -m labs.harbordesk --network first. No scan started.")
    app = UiApplication(root / "data/vulnassess.db", root / "config")

    def progress(stage, state, detail):
        print(f"{stage}: {state}: {detail}", flush=True)

    result = app.live_report(
        "http://127.0.0.1:8787/",
        args.provider,
        progress,
        cloud_sharing_authorized=args.share_evidence,
    )
    print(
        json.dumps(
            {
                key: result.get(key)
                for key in (
                    "target",
                    "finding_count",
                    "scan_status",
                    "ai_status",
                    "evidence_directory",
                    "saved_assessment",
                )
            },
            indent=2,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
