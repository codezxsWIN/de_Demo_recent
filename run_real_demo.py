"""Run the whole pipeline over the hand-built lab capture, enriched by the REAL feeds.

    python run_real_demo.py

Requires the real feed snapshots under data/feeds/ (gitignored). Fetch them first with
`python scripts/fetch_feeds.py` — or run `python run_demo.py` for the fully synthetic
pipeline that needs no downloads. The lab capture (examples/real_lab_nmap.xml) is
hand-built, not scanner output: the hosts are invented, but the CVE records, EPSS
scores and KEV listings it is enriched with are real.
"""

import sys
from pathlib import Path

from vulnassess.cli import main

ROOT = Path(__file__).resolve().parent
NMAP = ROOT / "examples" / "real_lab_nmap.xml"
FEEDS = ROOT / "data" / "feeds"


def run() -> int:
    if not (FEEDS / "kev.json").is_file():
        print(
            "MISSING data/feeds/ snapshots; fetch them first with:  python scripts/fetch_feeds.py",
            file=sys.stderr,
        )
        return 5
    return main(
        [
            "--config",
            str(ROOT / "config"),
            "--db",
            str(ROOT / "data" / "real-feeds.db"),
            "demo",
            "--target",
            f"172.28.0.12:{NMAP}",
            "--target",
            f"172.28.0.10:{NMAP}",
            "--feeds",
            str(FEEDS),
            "--out",
            str(ROOT / "reports" / "real-feeds-lab.html"),
        ]
    )


if __name__ == "__main__":
    sys.exit(run())
