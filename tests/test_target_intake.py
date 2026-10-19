"""Hostname preflight pins only authorised addresses for IPv4-only live scans."""

import socket
from pathlib import Path
from unittest.mock import patch

from vulnassess.ui.server import UiApplication

ROOT = Path(__file__).resolve().parents[1]


def test_scanme_dual_stack_dns_pins_approved_ipv4_without_authorising_ipv6():
    answers = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2600:3c01::f03c:91ff:fe18:bb2f", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("45.33.32.156", 0)),
    ]

    def fake_lookup(_host, _port, *, family, type):
        assert family == socket.AF_INET
        assert type == socket.SOCK_STREAM
        return [answer for answer in answers if answer[0] == family]

    app = UiApplication(ROOT / "data" / "vulnassess.db", ROOT / "config")
    with patch("vulnassess.target_intake.socket.getaddrinfo", side_effect=fake_lookup):
        check = app.target_check("scanme.nmap.org")

    assert check["status"] in {"needs-pinning", "needs-tools"}
    assert check["resolved_ips"] == ["45.33.32.156"]
    assert check["target"] == "45.33.32.156"


def test_hostname_with_unapproved_ipv4_still_fails_scope_check():
    answers = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("45.33.32.156", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
    ]
    app = UiApplication(ROOT / "data" / "vulnassess.db", ROOT / "config")
    with patch("vulnassess.target_intake.socket.getaddrinfo", return_value=answers):
        check = app.target_check("scanme.nmap.org")

    assert check["status"] == "blocked"
    assert "8.8.8.8" in check["resolved_ips"]


def test_target_check_preserves_explicit_web_endpoint_after_scope_pinning():
    app = UiApplication(ROOT / "data" / "vulnassess.db", ROOT / "config")
    with patch("vulnassess.ui.server.resolve_addresses", return_value=["172.28.0.10"]):
        check = app.target_check("https://pentest-ground.example:7001/console/login/LoginForm.jsp")

    assert check["status"] == "needs-pinning"
    assert check["target"] == "172.28.0.10"
    assert check["endpoint"] == {
        "scheme": "https",
        "host": "pentest-ground.example",
        "port": 7001,
        "path": "/console/login/LoginForm.jsp",
    }
