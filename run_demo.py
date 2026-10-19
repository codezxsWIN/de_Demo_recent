"""Run the whole pipeline over the labelled synthetic inputs.

    python run_demo.py

The inputs are SYNTHETIC: they exercise the code, they are not evidence about real systems.
"""

import sys
from pathlib import Path

from vulnassess.cli import main

ROOT = Path(__file__).resolve().parent
SYNTHETIC = ROOT / "tests" / "synthetic"
NMAP = SYNTHETIC / "synthetic_nmap_two_machines.xml"
ZAP = SYNTHETIC / "synthetic_zap_dvwa.json"


def run() -> int:
    return main(
        [
            "--config",
            str(ROOT / "config"),
            "--db",
            str(ROOT / "data" / "vulnassess.db"),
            "demo",
            "--target",
            f"172.28.0.10:{NMAP}",
            "--target",
            f"172.28.0.12:{NMAP}",
            "--target",
            f"172.28.0.11:{NMAP}:{ZAP}",
            "--feeds",
            str(SYNTHETIC / "feeds"),
            "--truth",
            str(SYNTHETIC / "synthetic_groundtruth.yaml"),
            "--out",
            str(ROOT / "reports" / "demo.html"),
        ]
    )


if __name__ == "__main__":
    sys.exit(run())
