"""Start the actual Office/IoT clients, packet observers and VulnAssess UI.

Run with the network-labs Python environment. No sample findings are inserted,
no external target is scanned, and no HarborDesk container is changed.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def run(arguments, *, timeout=120):
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError(f"Command failed: {result.stderr[-1200:]}")
    return result.stdout.strip()


def docker_binary():
    found = shutil.which("docker")
    fallback = (
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe"
    )
    if found:
        return found
    if os.name == "nt" and fallback.is_file():
        return str(fallback)
    raise RuntimeError("Docker CLI is missing. Install Docker Desktop and enable its Linux engine.")


def engine_ready(docker):
    try:
        return run([docker, "info", "--format", "{{.OSType}}"], timeout=5) == "linux"
    except (RuntimeError, subprocess.TimeoutExpired):
        return False


def read_url(path, port=8765):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=12) as response:
        if response.status != 200:
            raise RuntimeError("The local UI is not ready")
        return response.read(2 * 1024 * 1024)


def start_ui(directory):
    try:
        if b"Captured packets" in read_url("/network-live"):
            return {"reused": True}
    except (OSError, RuntimeError):
        pass
    # Refuse to mask an occupied old/unrelated listener with a second server.
    try:
        read_url("/")
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            "Port 8765 already serves another or older application; stop that listener first."
        ) from error
    except OSError:
        pass
    else:
        raise RuntimeError(
            "The existing UI lacks /network-live. Restart its Python process with the updated code."
        )
    from vulnassess.store import Store

    database = ROOT / "data/vulnassess.db"
    if not database.exists():
        # Only initialise the schema; never fill a fresh database with synthetic results.
        with Store(database):
            pass
    flags = (
        (
            subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.CREATE_NO_WINDOW
        )
        if os.name == "nt"
        else 0
    )
    with (
        (directory / "ui.stdout.log").open("ab") as output,
        (directory / "ui.stderr.log").open("ab") as errors,
    ):
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "vulnassess",
                "--db",
                str(database),
                "--config",
                str(ROOT / "config"),
                "ui",
                "--port",
                "8765",
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            creationflags=flags,
            start_new_session=os.name != "nt",
        )
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("UI startup failed; inspect data/network-live/ui.stderr.log")
        try:
            if b"Captured packets" in read_url("/network-live"):
                return {"reused": False, "pid": process.pid}
        except OSError:
            pass
        time.sleep(0.25)
    raise RuntimeError("UI readiness timed out; inspect its process and log before restarting.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build", action="store_true", help="Build the local lab image before starting"
    )
    args = parser.parse_args()
    from vulnassess.network_service_policy import load
    from vulnassess.settings import Settings

    settings = Settings(ROOT / "config")
    for ip in ("127.0.0.2", "127.0.0.3"):
        if (
            not settings.scope.contains(ip)
            or settings.scope.is_canary(ip)
            or load(settings.config_dir, settings.scope, ip) is None
        ):
            raise RuntimeError(
                "Both exact lab targets need current owner policy and scope authorisation"
            )
    docker = docker_binary()
    if not engine_ready(docker):
        if os.name != "nt":
            raise RuntimeError("Start the Docker Linux engine, then repeat this command")
        desktop = (
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/Docker Desktop.exe"
        )
        if not desktop.is_file():
            desktop = (
                Path(os.environ.get("ProgramFiles", "C:/Program Files"))
                / "Docker/Docker/Docker Desktop.exe"
            )
        if not desktop.is_file():
            raise RuntimeError("Docker Desktop is not installed at a recognised location")
        subprocess.Popen(
            [str(desktop)],
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 60
        while not engine_ready(docker):
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "Docker did not become ready. Inspect its startup error before retrying."
                )
            time.sleep(1)
    compose = [
        docker,
        "compose",
        "-f",
        str(ROOT / "labs/service_networks/compose.yaml"),
        "-f",
        str(ROOT / "labs/service_networks/live.compose.yaml"),
    ]
    if args.build:
        print("Building the lab image", flush=True)
        print(run([*compose, "build", "office"], timeout=600), flush=True)
    print("Starting the fixed local lab services, clients and independent observers", flush=True)
    print(
        "Startup uses the baseline lab configuration; runtime-only access changes may reset.",
        flush=True,
    )
    print(
        run(
            [
                *compose,
                "up",
                "-d",
                "--no-build",
                "--pull",
                "never",
                "--wait",
                "--wait-timeout",
                "90",
            ]
        ),
        flush=True,
    )
    directory = ROOT / "data/network-live"
    directory.mkdir(parents=True, exist_ok=True)
    ui = start_ui(directory)
    (directory / "startup.json").write_text(
        json.dumps({"ui": ui, "observed_at": time.time()}, indent=2), encoding="utf-8"
    )
    print("Office: http://127.0.0.1:8765/network-live#office", flush=True)
    print("IoT:    http://127.0.0.1:8765/network-live#iot", flush=True)
    print(
        "No assessment was fabricated or launched. Use Run check to collect fresh evidence.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
