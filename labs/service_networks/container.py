"""Run one environment in its own container/network namespace; no host mounts."""

import argparse
import asyncio
import json
import logging
import os
import signal
from datetime import UTC, datetime
from pathlib import Path


async def run(environment):
    from . import iot, office
    from .binding import validate

    validate("0.0.0.0", "container-only")
    root = Path("/runtime")
    ready = root / "ready.json"
    ready.unlink(missing_ok=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(name, stop.set)
    runtime = office if environment == "office" else iot
    profile = os.environ.get("VULNASSESS_LAB_ACCESS_PROFILE", "baseline")
    if profile not in {"baseline", "restricted"}:
        raise ValueError("Unknown fixed lab access profile")
    async with runtime.start(
        root / environment, bind_host="0.0.0.0", restrict_anonymous=profile == "restricted"
    ) as services:
        control = root / "control"
        control.mkdir(mode=0o700, exist_ok=True)
        access = control / "access.json"
        access.write_text(json.dumps(services), encoding="utf-8")
        access.chmod(0o600)
        # Publish topology only. Generated comparison credentials stay private
        # inside the container, outside the file share and outside stdout.
        receipt = {
            "environment": environment,
            "access_profile": profile,
            "started_at": datetime.now(UTC).isoformat(),
            "network_namespace": os.stat("/proc/self/ns/net").st_ino,
            "services": [
                {key: row[key] for key in ("port", "protocol", "protected") if key in row}
                for row in services
            ],
            "boundary": "Isolated container network namespace; shared WSL Linux kernel, not an independent OS or a VM security boundary.",
        }
        ready.write_text(json.dumps(receipt), encoding="utf-8")
        print(json.dumps(receipt), flush=True)
        try:
            await stop.wait()
        finally:
            ready.unlink(missing_ok=True)
            access.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment", choices=("office", "iot"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.ERROR)
    asyncio.run(run(args.environment))
