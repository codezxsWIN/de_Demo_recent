"""Fixed-port socat relays from loopback publishing to one private lab backend.

No generic proxy, IP forwarding, shell execution or host mounts. Each listener
has a bounded child count and inactivity timeout. The service containers retain
their single internal network and cannot route through these application relays.
"""

import argparse
import asyncio
import json
import os
import signal
from contextlib import suppress
from pathlib import Path

ROUTES = {
    "office": ("172.30.41.2", (2121, 2122, 2222, 2223, 1445, 1446, 6379, *range(32200, 32210)), ()),
    "iot": ("172.30.42.2", (1883, 1884, 8883, 6379), (1161, 1162)),
}
REDIS_ROUTES = {"office": "172.30.41.4", "iot": "172.30.42.4"}


def command(environment, port, transport):
    ip, tcp, udp = ROUTES[environment]
    if transport not in ("tcp", "udp") or port not in (tcp if transport == "tcp" else udp):
        raise ValueError("Gateway accepts only the declared lab routes")
    if port == 6379:
        ip = REDIS_ROUTES[environment]
    # UDP-LISTEN owns the LISTEN option group (including max-children).
    # UDP-RECVFROM rejects max-children only after its first datagram arrives.
    listener = "TCP4-LISTEN" if transport == "tcp" else "UDP4-LISTEN"
    connector = "TCP4" if transport == "tcp" else "UDP4-SENDTO"
    return [
        "socat",
        "-T",
        "30" if transport == "tcp" else "3",
        f"{listener}:{port},bind=0.0.0.0,reuseaddr,fork,max-children=4",
        f"{connector}:{ip}:{port},connect-timeout=3"
        if transport == "tcp"
        else f"{connector}:{ip}:{port}",
    ]


async def run(environment):
    from .binding import validate

    validate("0.0.0.0", "container-only")
    ready = Path("/runtime/ready.json")
    ready.unlink(missing_ok=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(name, stop.set)
    processes, watchers = [], []
    _, tcp, udp = ROUTES[environment]
    try:
        for transport, ports in (("tcp", tcp), ("udp", udp)):
            for port in ports:
                processes.append(
                    await asyncio.create_subprocess_exec(
                        *command(environment, port, transport), start_new_session=True
                    )
                )
        # Let exec/listen errors surface before publishing readiness.
        await asyncio.sleep(0.2)
        if any(process.returncode is not None for process in processes):
            raise RuntimeError("A fixed-port gateway listener failed to start")
        receipt = {
            "environment": environment + "-gateway",
            "network_namespace": os.stat("/proc/self/ns/net").st_ino,
            "ip_forward": Path("/proc/sys/net/ipv4/ip_forward").read_text().strip(),
            "services": [{"port": p, "protocol": "tcp"} for p in tcp]
            + [{"port": p, "protocol": "snmp"} for p in udp],
        }
        if receipt["ip_forward"] != "0":
            raise RuntimeError("Gateway IP forwarding must be disabled")
        ready.write_text(json.dumps(receipt), encoding="utf-8")
        print(json.dumps(receipt), flush=True)
        watchers = [asyncio.create_task(process.wait()) for process in processes]
        stopped = asyncio.create_task(stop.wait())
        watchers.append(stopped)
        done, _ = await asyncio.wait(watchers, return_when=asyncio.FIRST_COMPLETED)
        if stopped not in done:
            raise RuntimeError("A fixed-port listener exited unexpectedly")
    finally:
        ready.unlink(missing_ok=True)
        for process in processes:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
        for process in processes:
            try:
                await asyncio.wait_for(process.wait(), 3)
            except TimeoutError:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
        for task in watchers:
            task.cancel()
        if watchers:
            await asyncio.gather(*watchers, return_exceptions=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment", choices=tuple(ROUTES))
    asyncio.run(run(parser.parse_args().environment))
