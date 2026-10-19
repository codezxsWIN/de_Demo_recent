"""Capture the local UI with already-installed Microsoft Edge.

Only the ephemeral loopback viewer is navigated. The browser uses a disposable
profile, disables background services and blocks resolution of external names.
No package, browser, driver, font or image is downloaded by this script.
"""

import argparse
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "ui" / "screenshots"
CAPTURES = (
    ("phase-2-desktop.png", 1280, 900),
    ("phase-2-drawings.png", 1280, 1700),
    ("phase-2-mobile.png", 390, 1500),
)


def edge_path() -> Path | None:
    candidates = [
        shutil.which("msedge"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    return next((Path(value) for value in candidates if value and Path(value).is_file()), None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workbench",
        action="store_true",
        help="capture the current four-stage interface and its key states",
    )
    parser.add_argument(
        "--workflow",
        action="store_true",
        help="capture the independent workflow canvas without running a model",
    )
    parser.add_argument(
        "--project",
        action="store_true",
        help="capture the project introduction on desktop",
    )
    parser.add_argument("--run", help="existing assessment identifier")
    arguments = parser.parse_args()
    if sum((arguments.workflow, arguments.workbench, arguments.project)) > 1:
        parser.error("choose only one of --workflow, --workbench or --project")
    executable = edge_path()
    if executable is None:
        print("NOT RUN: screenshot capture; MISSING msedge executable")
        return 0
    sys.path.insert(0, str(ROOT))
    from vulnassess.ui.server import UiApplication, UiServer

    run_id = arguments.run or ("demo" if arguments.workflow or arguments.project else "verify")
    application = UiApplication(ROOT / "data" / "vulnassess.db", ROOT / "config", run_id)
    captures = [(filename, width, height, "") for filename, width, height in CAPTURES]
    page_path = "workflow" if arguments.workflow else ""
    if arguments.project:
        captures = [
            ("project-introduction.png", 1600, 1000, ""),
        ]
    if arguments.workflow:
        response = application.get("/api/run/" + run_id)
        if response.status != 200:
            raise RuntimeError(f"MISSING: run {run_id} for workflow captures")
        hosts = json.loads(response.body)["hosts"]
        selected = f"&host={hosts[0]['ip']}" if hosts else ""
        captures = [
            ("workflow-overview.png", 1600, 1000, ""),
            ("workflow-inspector.png", 1440, 1000, "#node=score" + selected),
            ("workflow-analyst.png", 1440, 1000, "#node=analyst" + selected),
            ("workflow-narrow.png", 500, 900, "#node=context" + selected),
        ]
    if arguments.workbench:
        response = application.get("/api/run/" + run_id)
        if response.status != 200:
            raise RuntimeError("MISSING: verify run for workbench captures")
        scores = json.loads(response.body)["scores"]
        if not scores:
            raise RuntimeError("MISSING: stored score for inspector capture")
        finding_id = scores[0]["finding_id"]
        captures = [
            (f"workbench-{stage}.png", 1280, 900, f"#stage-{stage}?theme=light")
            for stage in ("evidence", "context", "risk", "priorities")
        ] + [
            (
                "workbench-inspector.png",
                1280,
                900,
                f"#stage-priorities?theme=light&finding={finding_id}",
            ),
            ("workbench-tour.png", 1280, 900, "#stage-evidence?theme=light&tour=1"),
            ("workbench-dark.png", 1280, 900, "#stage-risk?theme=dark"),
            ("workbench-mobile.png", 500, 844, "#stage-evidence?theme=light"),
        ]
    server = UiServer(application, port=0)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    worker.start()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    try:
        for filename, width, height, fragment in captures:
            with TemporaryDirectory(prefix="doors-edge-", ignore_cleanup_errors=True) as profile:
                temporary = Path(profile) / filename
                command = [
                    str(executable),
                    "--headless",
                    "--disable-gpu",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-domain-reliability",
                    "--disable-sync",
                    "--disable-extensions",
                    "--metrics-recording-only",
                    "--run-all-compositor-stages-before-draw",
                    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                    "--force-device-scale-factor=1",
                    "--virtual-time-budget=1000",
                    f"--user-data-dir={profile}",
                    f"--screenshot={temporary}",
                    f"--window-size={width},{height}",
                    f"http://127.0.0.1:{server.server_port}/{page_path}{fragment}",
                ]
                try:
                    result = subprocess.run(command, capture_output=True, check=False, timeout=45)
                except (OSError, subprocess.TimeoutExpired) as error:
                    print(f"NOT RUN: {filename}; Edge capture failed ({type(error).__name__})")
                    continue
                if result.returncode != 0 or not temporary.is_file():
                    print(f"NOT RUN: {filename}; Edge exit {result.returncode}; PNG not captured")
                    continue
                image = temporary.read_bytes()
                if image[:8] != b"\x89PNG\r\n\x1a\n" or len(image) < 1000:
                    raise ValueError(f"invalid screenshot PNG: {temporary}")
                dimensions = struct.unpack(">II", image[16:24])
                if dimensions != (width, height):
                    raise ValueError(f"unexpected screenshot dimensions: {dimensions}")
                target = OUTPUT / filename
                shutil.copyfile(temporary, target)
                print(
                    f"CAPTURED: {target.relative_to(ROOT).as_posix()} ({width}x{height}; {len(image)} bytes)"
                )
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
    if worker.is_alive():
        raise RuntimeError("screenshot server did not stop")
    print("SCREENSHOT SERVER: stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
