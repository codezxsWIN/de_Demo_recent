"""Keep pytest execution offline; integrations must inject their transports."""

import socket
from typing import NoReturn

import pytest


def _forbid_network(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("network forbidden in tests; inject a transport")


@pytest.fixture(autouse=True)
def offline_transport_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    for operation in ("connect", "connect_ex", "bind", "send", "sendall", "sendto"):
        monkeypatch.setattr(socket.socket, operation, _forbid_network)
    monkeypatch.setattr(socket, "create_connection", _forbid_network)
    monkeypatch.setattr(socket, "getaddrinfo", _forbid_network)
