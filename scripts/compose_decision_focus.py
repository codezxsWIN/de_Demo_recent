"""Select supported next verification decisions from a verified saved assessment."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnassess import analyst, capture_history, decision_focus  # noqa: E402
from vulnassess.errors import ConfigError, LLMUnavailable  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture")
    parser.add_argument("--root", default="data/live/raw")
    parser.add_argument("--provider", choices=analyst.PROVIDERS, default="ollama")
    parser.add_argument("--allow-cloud", action="store_true")
    args = parser.parse_args()
    if args.provider != "ollama" and not args.allow_cloud:
        parser.error(
            "Explicit --allow-cloud is required to share bounded evidence with a cloud provider"
        )
    root = Path(args.root).resolve()
    record = capture_history.load(root, args.capture)
    directory = root / record["capture_id"]
    destination = directory / "decision-focus.json"
    if destination.exists() or destination.is_symlink():
        raise ConfigError(
            "A decision focus already exists; source artifacts will not be overwritten"
        )
    document = decision_focus.compose(record, analyst.provider_client(args.provider))
    decision_focus.save_saved(directory, record, document)
    print(
        json.dumps(
            {
                "capture": record["capture_id"],
                "provider": args.provider,
                "model": document["model"],
                "status": "validated_focus_selection",
                "scanner_launched": False,
                "finding_priorities_changed": False,
                "report": f"http://127.0.0.1:8765/captures/{record['capture_id']}/report#decisions",
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (ConfigError, LLMUnavailable, OSError) as error:
        print(
            json.dumps(
                {
                    "status": "unavailable",
                    "detail": str(error),
                    "source_evidence_preserved": True,
                    "scanner_launched": False,
                }
            )
        )
        raise SystemExit(1)
