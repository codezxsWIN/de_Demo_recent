"""Non-scanning DNS lookup for lab-address preflight."""

import socket
from ipaddress import ip_address


def resolve_addresses(hostname: str, port: int) -> list[str]:
    return sorted(
        {
            str(ip_address(item[4][0]))
            for item in socket.getaddrinfo(
                hostname, port, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
        }
    )
