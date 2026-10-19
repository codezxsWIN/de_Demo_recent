"""Build a synthetic assessment and export the canonical VulnAssess workbench.

The simulation uses labelled synthetic scanner/feed/model inputs and is not evidence
of accuracy on real captures. It makes no network calls and needs no web server.
"""

import argparse
import io
import webbrowser
from contextlib import redirect_stdout
from pathlib import Path

from vulnassess.cli import main as run_cli
from vulnassess.ui.export import export_html
from vulnassess.ui.server import UiApplication

ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "data" / "visual-simulation.db"
OUTPUT = ROOT / "reports" / "visual-simulation.html"
RUN_ID = "visual-sim"
SYNTHETIC = ROOT / "tests" / "synthetic"


def _fresh_database() -> None:
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(DATABASE) + suffix)
        if path.exists():
            path.unlink()


def _run_data_pipeline() -> str:
    arguments = [
        "--config",
        str(ROOT / "config"),
        "--db",
        str(DATABASE),
        "demo",
        "--run-id",
        RUN_ID,
        "--target",
        f"172.28.0.10:{SYNTHETIC / 'synthetic_nmap_two_machines.xml'}",
        "--target",
        f"172.28.0.12:{SYNTHETIC / 'synthetic_nmap_two_machines.xml'}",
        "--target",
        (
            f"172.28.0.11:{SYNTHETIC / 'synthetic_nmap_two_machines.xml'}:"
            f"{SYNTHETIC / 'synthetic_zap_dvwa.json'}"
        ),
        "--feeds",
        str(SYNTHETIC / "feeds"),
        "--out",
        str(ROOT / "reports" / "visual-simulation-report.html"),
    ]
    output = io.StringIO()
    with redirect_stdout(output):
        code = run_cli(arguments)
    if code != 0:
        raise RuntimeError(f"data pipeline exited {code}: {output.getvalue()}")
    return output.getvalue()


def build() -> Path:
    _fresh_database()
    _run_data_pipeline()

    application = UiApplication(DATABASE, ROOT / "config", RUN_ID)
    return export_html(application, OUTPUT)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the canonical UI over synthetic inputs")
    parser.add_argument("--open", action="store_true", help="open the exported workbench")
    args = parser.parse_args()

    path = build()
    print("VULNASSESS UI SIMULATION")
    print("  evidence: NOT RUN; data kind: synthetic; real labelled captures are MISSING")
    print("  interface: canonical four-stage workbench (Evidence -> Context -> Risk -> Priorities)")
    print(f"  output: {path}")
    print(f"  open: {path.as_uri()}")
    if args.open:
        webbrowser.open(path.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
