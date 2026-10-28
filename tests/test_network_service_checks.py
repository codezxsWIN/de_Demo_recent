import json
from pathlib import Path

import pytest

from vulnassess import network_service_checks as checks
from vulnassess import network_service_policy as policy
from vulnassess.errors import ConfigError, ScopeError
from vulnassess.schema import Service
from vulnassess.settings import Scope


def scoped(ip="192.0.2.77"):
    return Scope({"allowed_cidrs": [ip + "/32"]}, Path("synthetic-scope.yaml"))


def write_policy(root, entry, ip="192.0.2.77"):
    (root / policy.FILENAME).write_text(json.dumps({"version": 1, "targets": {ip: [entry]}}))
    return policy.load(root, scoped(ip), ip)


def test_unfamiliar_target_and_nonstandard_port_are_supported(tmp_path, monkeypatch):
    selected = write_policy(
        tmp_path, {"service": "ftp", "transport": "tcp", "port": 49171, "require_auth": True}
    )
    calls = []

    def exchange(ip, entry):
        calls.append((ip, entry["port"]))
        return {"protocol_confirmed": True, "anonymous_accepted": True, "response": "230 Accepted"}

    monkeypatch.setitem(checks.TRANSPORTS, "ftp", exchange)
    findings, services, coverage = checks.run(
        scoped(), "192.0.2.77", selected, [Service(49171, "tcp", name="ftp")], tmp_path
    )
    assert calls == [("192.0.2.77", 49171)]
    assert len(findings) == 1
    assert services[0].port == 49171
    assert coverage.startswith("complete:")
    assert "proof_file" not in findings[0].evidence
    assert json.loads(findings[0].evidence)["policy_sha256"] == selected["policy_sha256"]
    assert not findings[0].cve_ids


@pytest.mark.parametrize("require_auth", [False, None])
def test_public_or_unspecified_access_policy_never_becomes_auth_vulnerability(require_auth):
    entry = {"service": "ftp"}
    if require_auth is not None:
        entry["require_auth"] = require_auth
    assert checks.violations(entry, {"protocol_confirmed": True, "anonymous_accepted": True}) == []


def test_successful_valid_credential_is_not_automatically_a_default_credential_flaw():
    assert (
        checks.violations(
            {"require_auth": True}, {"protocol_confirmed": True, "test_credential_accepted": True}
        )
        == []
    )
    assert checks.violations(
        {"reject_test_credential": True},
        {"protocol_confirmed": True, "test_credential_accepted": True},
    )


def test_no_protocol_confirmation_means_no_finding():
    assert (
        checks.violations(
            {"require_auth": True}, {"protocol_confirmed": False, "anonymous_accepted": True}
        )
        == []
    )


def test_closed_tcp_endpoint_is_not_probed(tmp_path, monkeypatch):
    selected = write_policy(
        tmp_path, {"service": "ftp", "transport": "tcp", "port": 49171, "require_auth": True}
    )
    monkeypatch.setitem(
        checks.TRANSPORTS, "ftp", lambda *_: pytest.fail("Undiscovered endpoint connected")
    )
    findings, services, coverage = checks.run(scoped(), "192.0.2.77", selected, [], tmp_path)
    assert findings == services == []
    assert coverage.startswith("partial: 0 owner-authorised endpoint checks attempted; 1 skipped")
    receipt = json.loads((tmp_path / "network-service-observations.json").read_text())
    assert receipt["observations"][0]["status"] == "not_discovered_open"


def test_mixed_endpoint_coverage_counts_attempted_and_skipped(tmp_path, monkeypatch):
    selected = write_policy(tmp_path, {"service": "ftp", "transport": "tcp", "port": 49171})
    selected["endpoints"].append({"service": "ftp", "transport": "tcp", "port": 49172})
    calls = []
    monkeypatch.setitem(checks.TRANSPORTS, "ftp", lambda ip, entry: calls.append(entry["port"]) or {"protocol_confirmed": True})
    _, _, coverage = checks.run(scoped(), "192.0.2.77", selected, [Service(49171, "tcp")], tmp_path)
    assert calls == [49171]
    assert coverage.startswith("partial: 1 owner-authorised endpoint checks attempted; 1 skipped")


def test_scope_revocation_precedes_protocol_calls(tmp_path, monkeypatch):
    selected = write_policy(tmp_path, {"service": "ftp", "transport": "tcp", "port": 49171})
    monkeypatch.setitem(
        checks.TRANSPORTS, "ftp", lambda *_: pytest.fail("Revoked target connected")
    )
    with pytest.raises(ScopeError):
        checks.run(scoped("192.0.2.88"), "192.0.2.77", selected, [], tmp_path)


def test_snmp_silence_stays_inconclusive_without_open_port_or_vulnerability(tmp_path, monkeypatch):
    selected = write_policy(
        tmp_path, {"service": "snmp", "transport": "udp", "port": 49172, "require_auth": True}
    )
    monkeypatch.setitem(
        checks.TRANSPORTS, "snmp", lambda *_: {"protocol_confirmed": False, "inconclusive": True}
    )
    findings, services, coverage = checks.run(scoped(), "192.0.2.77", selected, [], tmp_path)
    assert not findings and not services
    assert coverage.startswith("partial:")


def test_remediation_and_public_policy_change_do_not_need_answer_markers(tmp_path, monkeypatch):
    entry = {"service": "ftp", "transport": "tcp", "port": 49171, "require_auth": True}
    selected = write_policy(tmp_path, entry)
    for index, accepted in enumerate((True, False)):
        directory = tmp_path / str(index)
        directory.mkdir()
        monkeypatch.setitem(
            checks.TRANSPORTS,
            "ftp",
            lambda *_, accepted=accepted: {
                "protocol_confirmed": True,
                "anonymous_accepted": accepted,
            },
        )
        findings, _, _ = checks.run(
            scoped(), "192.0.2.77", selected, [Service(49171, "tcp")], directory
        )
        assert len(findings) == int(accepted)


@pytest.mark.parametrize(
    "entry",
    [
        {"service": "ftp", "transport": "tcp", "port": True},
        {"service": [], "transport": "tcp", "port": 21},
        {"service": "ftp", "transport": "tcp", "port": 21, "require_auth": "yes"},
        {"service": "mqtt", "transport": "tcp", "port": 1883, "publish_topic": "#"},
        {
            "service": "ssh",
            "transport": "tcp",
            "port": 22,
            "credential": {"username": "x", "password": "y"},
        },
        {"service": "ftp", "transport": "tcp", "port": 21, "require_signing": True},
    ],
)
def test_invalid_policy_is_rejected_before_network(tmp_path, entry):
    with pytest.raises(ConfigError):
        write_policy(tmp_path, entry)


def test_ftp_checks_login_without_reading_files(monkeypatch):
    class FTP:
        def __init__(self, **_):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def connect(self, ip, port):
            return "220 Independently configured FTP"

        def login(self, *_):
            return "230 Public area accepted"

        def retrbinary(self, *_):
            pytest.fail("No file retrieval was authorised")

    monkeypatch.setattr(checks.ftplib, "FTP", FTP)
    proof = checks._ftp("192.0.2.77", {"port": 49171})
    assert proof["anonymous_accepted"] is True
    assert proof["files_read"] is False


def test_detector_does_not_import_lab_catalog_or_match_training_payloads():
    source = Path(checks.__file__).read_text()
    for forbidden in (
        "labs.service_networks",
        "network-proof.txt",
        "127.0.0.2",
        "127.0.0.3",
        "matches_training_file",
    ):
        assert forbidden not in source


@pytest.mark.parametrize("matching_nonce", [True, False])
def test_mqtt_matches_acknowledgement_and_own_nonce_amid_interleaved_messages(
    monkeypatch, matching_nonce
):
    from types import SimpleNamespace

    marker = b"fresh-owned-nonce"
    topic = b"owner/assessment"
    expected = len(topic).to_bytes(2, "big") + topic + marker
    other = b"\x00\x05otherunrelated-reading"
    packets = iter(
        [
            (0x20, b"\x00\x00"),
            (0x31, other),
            (0x90, b"\x00\x01\x00"),
            (0x31, other),
            (0x30, expected if matching_nonce else expected + b"wrong"),
            (0xD0, b""),
        ]
    )

    class Wire:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def settimeout(self, value):
            assert 0 < value <= checks.TIMEOUT

    monkeypatch.setattr(checks.socket, "create_connection", lambda *_args, **_kwargs: Wire())
    monkeypatch.setattr(checks, "uuid4", lambda: SimpleNamespace(hex=marker.decode()))
    monkeypatch.setattr(checks, "_packet", lambda _: next(packets))
    sent = []
    monkeypatch.setattr(checks, "_send", lambda _, header, payload: sent.append((header, payload)))
    result = checks._mqtt("192.0.2.77", {"port": 49171, "publish_topic": topic.decode()})
    assert result["anonymous_accepted"] is True
    assert result["message_exchange_confirmed"] is matching_nonce
    assert (0x30, expected) in sent


def test_smb_negotiate_and_session_are_not_confused_with_file_access(monkeypatch):
    import sys
    from types import SimpleNamespace

    class Denied(Exception):
        def getErrorCode(self):
            return 0xC0000022

    class SMB:
        def __init__(self, *_args, **_kwargs):
            pass

        def isSigningRequired(self):
            return False

        def getDialect(self):
            return 514

        def login(self, *_):
            pass

        def getFile(self, *_):
            raise Denied()

        def close(self):
            pass

    monkeypatch.setitem(
        sys.modules,
        "impacket.smbconnection",
        SimpleNamespace(SMBConnection=SMB, SessionError=Denied),
    )
    entry = {
        "port": 49171,
        "share": "OWNER",
        "read_path": "arbitrary-file.txt",
        "require_auth": True,
        "require_signing": True,
    }
    proof = checks._smb("192.0.2.77", entry)
    assert proof["anonymous_session_accepted"] is True
    assert proof["anonymous_accepted"] is False
    assert [row[0] for row in checks.violations(entry, proof)] == ["signing"]


def test_generic_policy_reaches_live_capture_scores_and_retained_replay(tmp_path, monkeypatch):
    import shutil
    import subprocess

    from vulnassess import analyst, live_assessment
    from vulnassess.ui.server import _replay_evidence

    root = Path(__file__).resolve().parents[1]
    configuration = tmp_path / "config"
    shutil.copytree(root / "config", configuration)
    write_policy(
        configuration,
        {"service": "ftp", "transport": "tcp", "port": 49171, "require_auth": True},
        ip="127.0.0.1",
    )
    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "nmap")

    def scan(command, **_):
        assert command[-1] == "127.0.0.1"
        assert command[command.index("-p") + 1] == "49171"
        Path(command[command.index("-oX") + 1]).write_text(
            '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="49171"><state state="open"/>'
            '<service name="ftp" product="Independent FTP" version="1.2.3"/></port></ports></host></nmaprun>'
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(live_assessment.subprocess, "run", scan)
    monkeypatch.setitem(
        checks.TRANSPORTS,
        "ftp",
        lambda *_: {"protocol_confirmed": True, "anonymous_accepted": True},
    )
    monkeypatch.setattr(analyst, "configuration_detail", lambda _: "Test-only unavailable analyst")
    monkeypatch.setattr(
        analyst,
        "analyze_optional",
        lambda *_a, **_k: {"analyst": None, "ai_status": "unavailable", "ai_attempts": []},
    )
    result = live_assessment.run(
        "127.0.0.1",
        {"status": "ready", "resolved_ips": ["127.0.0.1"]},
        configuration,
        provider="google",
        on_progress=lambda *_: None,
    )
    payload = json.loads((Path(result["evidence_directory"]) / "case.json").read_text())
    assert len(payload["findings"]) == len(payload["scores"]) == 1
    assert payload["network_service_policy_sha256"]
    assert payload["hosts"][0]["services"][0]["product"] == "Independent FTP"
    assert payload["hosts"][0]["services"][0]["version"] == "1.2.3"
    assert payload["scanner_coverage"]["nikto"].startswith("not run")
    _, status, _ = _replay_evidence({**result, "payload": payload}, "127.0.0.1", lambda *_: None)
    assert status == "complete"
