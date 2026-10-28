"""Independent real service, unpredictable port, public-policy and remediation proof."""

import ftplib
import ipaddress
import json
import os
import socket
import threading
from pathlib import Path

import pytest

from vulnassess import network_service_checks as checks
from vulnassess import network_service_policy as policy
from vulnassess.schema import Service
from vulnassess.settings import Scope

ORIGINAL_SOCKET = {
    name: getattr(socket.socket, name)
    for name in ("bind", "connect", "connect_ex", "send", "sendall", "sendto")
}
ORIGINAL_CONNECT = socket.create_connection
ORIGINAL_RESOLVE = socket.getaddrinfo


@pytest.fixture(autouse=True)
def offline_transport_guard(monkeypatch):
    def validate(address):
        assert ipaddress.ip_address(address[0]).is_loopback

    for name, original in ORIGINAL_SOCKET.items():

        def operation(sock, *args, _name=name, _original=original, **kwargs):
            if _name in {"bind", "connect", "connect_ex"}:
                validate(args[0])
            if _name == "sendto":
                validate(args[-1])
            return _original(sock, *args, **kwargs)

        monkeypatch.setattr(socket.socket, name, operation)

    def connect(address, *args, **kwargs):
        validate(address)
        return ORIGINAL_CONNECT(address, *args, **kwargs)

    def resolve(host, *args, **kwargs):
        assert ipaddress.ip_address(host).is_loopback
        return ORIGINAL_RESOLVE(host, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)


@pytest.mark.skipif(
    os.environ.get("VULNASSESS_NETWORK_LABS") != "1",
    reason="Explicit loopback runtime opt-in required",
)
def test_public_access_policy_violation_then_real_remediation_and_legitimate_access(tmp_path):
    pytest.importorskip("pyftpdlib")
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.ioloop import IOLoop
    from pyftpdlib.servers import FTPServer

    data = tmp_path / "independent-files"
    data.mkdir()
    (data / "unrelated-name.txt").write_bytes(
        b"Not a lab marker; this file must never be retrieved"
    )
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(str(data), perm="elr")
    authorizer.add_user("owner", "IndependentlyConfigured-Secret", str(data), perm="elr")
    reads = []

    class Handler(FTPHandler):
        auth_failed_timeout = 0

        def ftp_RETR(self, file):
            reads.append(file)
            return super().ftp_RETR(file)

    Handler.authorizer = authorizer
    loop = IOLoop()
    server = FTPServer(("127.0.0.1", 0), Handler, ioloop=loop)
    port = server.socket.getsockname()[1]
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"timeout": 0.05, "handle_exit": False}, daemon=True
    )
    thread.start()
    scope = Scope({"allowed_cidrs": ["127.0.0.1/32"]}, Path("independent-scope.yaml"))

    def assess(name, require_auth):
        directory = tmp_path / name
        directory.mkdir()
        (directory / policy.FILENAME).write_text(
            json.dumps(
                {
                    "version": 1,
                    "targets": {
                        "127.0.0.1": [
                            {
                                "port": port,
                                "transport": "tcp",
                                "service": "ftp",
                                "require_auth": require_auth,
                            }
                        ]
                    },
                }
            )
        )
        selected = policy.load(directory, scope, "127.0.0.1")
        findings, services, coverage = checks.run(
            scope, "127.0.0.1", selected, [Service(port, "tcp", name="ftp")], directory
        )
        assert coverage.startswith("complete:")
        assert services[0].port == port
        return findings

    try:
        assert assess("public-intended", False) == []
        before = assess("private-policy-before", True)
        assert len(before) == 1
        assert before[0].port == port
        # This is actual protocol evidence from an independently configured service,
        # not the lab's fixed ports or expected-condition file. Counterfactual
        # context below tests formula sensitivity, not real production exposure.
        from dataclasses import replace

        from vulnassess import scoring
        from vulnassess.schema import ContextProfile, Feature
        from vulnassess.settings import Settings

        weights = Settings(Path(__file__).resolve().parents[1] / "config").weights
        profile = ContextProfile(
            host_ip="127.0.0.1",
            role=Feature("unknown", 0.2, "rule", "none observed"),
            exposure=Feature("internal", 1, "rule", "Independent loopback service"),
            manual={
                "environment": Feature("test", 1, "manual", "Independent local test environment")
            },
        )
        local_score = scoring.score(before[0], None, profile, (), weights)
        counterfactual = replace(
            profile,
            exposure=Feature(
                "internet_facing", 1, "manual", "COUNTERFACTUAL external vantage; not scanned"
            ),
            manual={
                "environment": Feature(
                    "prod", 1, "manual", "COUNTERFACTUAL production tag; not observed"
                )
            },
        )
        comparison = scoring.score(before[0], None, counterfactual, (), weights)
        assert local_score.inputs["native_triage"]["category"] == "login"
        assert local_score.risk == 30 and comparison.risk == 55
        authorizer.remove_user("anonymous")
        assert assess("private-policy-after", True) == []
        with ftplib.FTP(timeout=3) as legitimate:
            legitimate.connect("127.0.0.1", port)
            assert legitimate.login("owner", "IndependentlyConfigured-Secret").startswith("230")
            assert legitimate.pwd() == "/"
        assert reads == []
    finally:
        server.close_all()
        thread.join(timeout=3)
        loop.close()
        assert not thread.is_alive()
