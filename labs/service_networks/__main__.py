"""Start both network-only environments: python -m labs.service_networks."""

import asyncio
import json
import logging
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from pathlib import Path

from .catalog import ENVIRONMENTS


async def main():
    from . import iot, office

    root = Path(__file__).resolve().parents[2] / "data" / "service-networks"
    root.mkdir(parents=True, exist_ok=True)
    async with AsyncExitStack() as stack:
        await stack.enter_async_context(office.start(root / "office"))
        await stack.enter_async_context(iot.start(root / "iot"))
        topology = {
            "started_at": datetime.now(UTC).isoformat(),
            "environments": ENVIRONMENTS,
            "isolation": "Separate loopback endpoints on one computer, not VMs or separate OS instances",
            "website_checks": False,
        }
        (root / "runtime.json").write_text(json.dumps(topology, indent=2), encoding="utf-8")
        print("Two real network-service environments are listening (loopback only):", flush=True)
        for ip, item in ENVIRONMENTS.items():
            print(
                f"{item['name']}: {ip} TCP {','.join(map(str, item['tcp']))}; UDP {','.join(map(str, item['udp'])) or 'none'}",
                flush=True,
            )
        print(
            "Enter either IP in VulnAssess > Run. No website URL required. Ctrl+C stops both.",
            flush=True,
        )
        try:
            await asyncio.Event().wait()
        finally:
            (root / "runtime.json").unlink(missing_ok=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
