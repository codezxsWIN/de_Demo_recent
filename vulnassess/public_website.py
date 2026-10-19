"""Opt-in public website metadata check; transport is not run by the agent.

One root HEAD request, no redirects, cookies, body retention, scanners or scoring.
DNS is bounded and every answer is checked before connecting to a literal IP.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from ipaddress import IPv6Address, ip_address, ip_network
from threading import Event, Lock, Thread
from typing import Any, Callable
from urllib.parse import urlsplit

from vulnassess.errors import ConfigError, NeedsReview
from vulnassess.website_metadata import LIMIT, minimise

VERSION = "public_website.v1"
_DNS_LOCK = Lock()


def target(value: str) -> dict[str, Any]:
    """Validate a public web origin, discarding any non-root page path."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 2048
        or any(ord(char) <= 32 or ord(char) == 127 for char in value)
        or "\\" in value
    ):
        raise ConfigError("Website URL must be a bounded HTTP(S) address without whitespace")
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port or (443 if scheme == "https" else 80)
        if (
            scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or "?" in value
            or "#" in value
            or port != (443 if scheme == "https" else 80)
            or parsed.port == 0
            or "%" in host
        ):
            raise ValueError("unsupported URL")
        try:
            host = str(ip_address(host))
        except ValueError:
            if len(host) > 253 or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
                host,
            ):
                raise ValueError("invalid hostname") from None
    except (ValueError, UnicodeError) as error:
        raise ConfigError(
            "Website URL requires HTTP/80 or HTTPS/443, no credentials, query or fragment"
        ) from error
    authority = f"[{host}]" if ":" in host else host
    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "origin": f"{scheme}://{authority}/",
        "path_discarded": parsed.path not in {"", "/"},
    }


def _public(address: str, denied: Callable[[str], bool]) -> str:
    ip = ip_address(address)
    if (
        not ip.is_global
        or ip.is_multicast
        or ip.is_reserved
        or (isinstance(ip, IPv6Address) and ip not in ip_network("2000::/3"))
        or (isinstance(ip, IPv6Address) and (ip.ipv4_mapped or ip.sixtofour or ip.teredo))
        or denied(str(ip))
    ):
        raise ConfigError("Website destination is not an eligible public address or is a canary")
    return str(ip)


def _resolve(host: str, port: int) -> list[str]:
    """At most one resolver worker, including after a timeout; no retry queue."""
    try:
        return [str(ip_address(host))]
    except ValueError:
        pass
    if not _DNS_LOCK.acquire(blocking=False):
        raise ConfigError("Website DNS resolver is busy; retry later")
    ready = Event()
    result: dict[str, Any] = {}

    def lookup() -> None:
        try:
            rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            if not rows or len(rows) > 32:
                result["error"] = True
            else:
                result["addresses"] = sorted({str(ip_address(row[4][0])) for row in rows})
        except (OSError, ValueError):
            result["error"] = True
        finally:
            _DNS_LOCK.release()
            ready.set()

    worker = Thread(target=lookup, daemon=True, name="public-website-dns")
    try:
        worker.start()
    except RuntimeError as error:
        _DNS_LOCK.release()
        raise ConfigError("Website DNS worker could not start") from error
    if not ready.wait(3.0):
        raise ConfigError("Website DNS deadline exceeded; no HTTP request sent")
    if result.get("error") or not result.get("addresses"):
        raise ConfigError("Website DNS resolution failed or exceeded its answer budget")
    return result["addresses"]


def _head(connection: Any, host: str, deadline: float) -> dict[str, Any]:
    connection.settimeout(max(0.001, deadline - time.monotonic()))
    connection.sendall(
        f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: VulnAssess-Metadata/1\r\nConnection: close\r\n\r\n".encode(
            "ascii"
        )
    )
    raw = b""
    while b"\r\n\r\n" not in raw:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ConfigError("Website response deadline exceeded")
        connection.settimeout(remaining)
        chunk = connection.recv(min(1024, LIMIT + 1 - len(raw)))
        if not chunk:
            break
        raw += chunk
        if b"\r\n\r\n" in raw:
            raw = raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
        if len(raw) > LIMIT:
            raise ConfigError("Website response headers exceed the metadata budget")
    return json.loads(bytes.fromhex(minimise(raw)["raw_hex"]))


def check(value: str, denied: Callable[[str], bool]) -> dict[str, Any]:
    """Perform the explicitly requested check. Network transport is not run by the agent."""
    endpoint = target(value)
    started = time.monotonic()
    addresses = [_public(item, denied) for item in _resolve(endpoint["host"], endpoint["port"])]
    address = ip_address(addresses[0])
    deadline = started + 10.0
    authority = f"[{endpoint['host']}]" if ":" in endpoint["host"] else endpoint["host"]
    tls: dict[str, Any] = {
        "state": "not_checked",
        "reason": "HTTP origin selected"
        if endpoint["scheme"] == "http"
        else "TLS handshake not completed",
    }
    metadata = None
    failure = None
    http_attempted = False
    try:
        with socket.socket(
            socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM
        ) as connection:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.connect((str(address), endpoint["port"]))
            if endpoint["scheme"] == "https":
                connection.settimeout(max(0.001, deadline - time.monotonic()))
                with ssl.create_default_context().wrap_socket(
                    connection, server_hostname=endpoint["host"]
                ) as secured:
                    certificate = secured.getpeercert() or {}
                    expires = certificate.get("notAfter")
                    tls = {
                        "state": "validated",
                        "protocol": secured.version(),
                        "certificate_expires_at": (
                            datetime.fromtimestamp(
                                ssl.cert_time_to_seconds(expires), timezone.utc
                            ).isoformat()
                            if isinstance(expires, str)
                            else None
                        ),
                        "reason": "System trust store and submitted hostname validated",
                    }
                    http_attempted = True
                    metadata = _head(secured, authority, deadline)
            else:
                http_attempted = True
                metadata = _head(connection, authority, deadline)
        if time.monotonic() > deadline:
            raise ConfigError("Website check deadline exceeded")
    except ssl.SSLCertVerificationError:
        tls = {"state": "validation_failed", "reason": "Certificate trust or hostname check failed"}
        failure = "TLS validation failed; no HTTP request or insecure retry was sent"
    except (OSError, ValueError, ConfigError, NeedsReview):
        failure = "Website response unavailable, malformed or outside the time/size budget"
        metadata = None
    if metadata is not None:
        metadata = dict(metadata, format=VERSION)
    retained = {
        "schema_version": VERSION,
        "origin": endpoint["origin"],
        "resolved_addresses": addresses,
        "selected_address": str(address),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "path_discarded": endpoint["path_discarded"],
        "tls": tls,
        "metadata": metadata,
        "failure": failure,
    }
    observations = [
        f"DNS: {len(addresses)} public address(es) checked; selected {address}. Other addresses were not contacted.",
        f"Root HEAD response: HTTP {metadata['status']}." if metadata else failure,
        f"TLS: {tls['state']}. {tls['reason']}",
    ]
    if metadata:
        observations.extend(
            f"{name}: {state}. Review applicability; presence is not proof of an effective policy."
            for name, state in metadata["headers"].items()
        )
        observations.extend(
            [
                f"Cookie protection attributes (counts only): {json.dumps(metadata['cookies'], sort_keys=True)}",
                f"Redirect: {metadata['redirect']}. Destination not retained or followed.",
                "Authentication challenge: "
                + ("observed" if metadata["authentication_challenge_observed"] else "not observed")
                + ". Application authentication remains unknown.",
            ]
        )
    return {
        **retained,
        "state": "complete" if metadata else "incomplete",
        "retained_sha256": hashlib.sha256(
            json.dumps(retained, sort_keys=True).encode()
        ).hexdigest(),
        "evidence": [
            {"id": f"W{index}", "label": "observed", "text": text}
            for index, text in enumerate(observations, 1)
        ],
        "precautions": [
            "Use HTTPS and resolve certificate warnings; HTTP does not protect traffic in transit.",
            "Review security headers and sensitive-cookie protections on the actual application pages.",
            "Use the authorised deep assessment for vulnerability checks; this is metadata, not a safety verdict.",
        ],
        "coverage": {
            "executed": ["public destination validation"]
            + (["one pinned root HEAD attempt"] if http_attempted else [])
            + (["TLS certificate and hostname validation"] if tls["state"] == "validated" else []),
            "not_run": [
                "redirect following",
                "other pages",
                "port scan",
                "vulnerability probes",
                "AI",
            ],
            "limitations": [
                "One selected DNS address, one response, no retries; other CDN edges may differ.",
                "No page bodies, cookie names/values, redirect destinations or arbitrary headers retained.",
                "No CVE confirmation, NVD/EPSS/KEV enrichment, canonical score or safety guarantee.",
            ],
        },
    }
