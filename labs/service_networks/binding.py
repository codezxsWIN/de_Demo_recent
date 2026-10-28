"""Keep the ordinary launcher loopback-only; explicit container entrypoint opts in."""

import os
from pathlib import Path


def validate(host: str, loopback: str) -> None:
    if host == loopback:
        return
    if (
        host == "0.0.0.0"
        and os.name == "posix"
        and Path("/.dockerenv").is_file()
        and os.environ.get("VULNASSESS_CONTAINER_LAB") == "1"
    ):
        return
    raise ValueError("Non-loopback lab binding requires the explicit Docker lab entrypoint")
