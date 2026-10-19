"""Shared interpretation of scanner service labels; port conventions are not facts."""

from vulnassess.schema import Service

HTTP_NAMES = frozenset(
    f"{prefix}{name}{suffix}"
    for prefix in ("", "ssl/", "tls/")
    for name in ("http", "https")
    for suffix in ("", "-alt", "-proxy", "_alt", "_proxy")
)


def http_service_name(name: str | None) -> bool:
    return isinstance(name, str) and name.strip().lower() in HTTP_NAMES


def tls_service_name(name: str | None) -> bool:
    if not isinstance(name, str):
        return False
    normal = name.strip().lower()
    return normal.startswith(("ssl/", "tls/")) or (
        normal in HTTP_NAMES and normal.startswith("https")
    )


def is_http(service: Service) -> bool:
    """Only supported TCP HTTP classifications can justify a web-scanner step."""
    return service.protocol == "tcp" and http_service_name(service.name)


def uses_tls(service: Service) -> bool:
    return service.tls is True or tls_service_name(service.name)
