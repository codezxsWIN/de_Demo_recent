import json
import shutil
import subprocess
from ipaddress import ip_address
from pathlib import Path

import pytest

from labs.service_networks.catalog import ENVIRONMENTS
from vulnassess import analyst, live_assessment
from vulnassess import service_network_probe as probe
from vulnassess.errors import ScopeError
from vulnassess.schema import Finding, Provenance
from vulnassess.settings import Settings

ROOT = Path(__file__).resolve().parents[1]


def settings():
    return Settings(ROOT / "config")


def proof(observed=True):
    return observed, {"access": "read", "signing_required": False}, True, {"access": "denied"}


def stub_protocols(monkeypatch, observed=True):
    for name in ("_ftp", "_smb", "_ssh", "_mqtt", "_snmp", "_certificate"):
        monkeypatch.setattr(probe, name, lambda _, value=observed: proof(value))


def test_two_declared_network_environments_have_distinct_loopback_targets():
    assert set(ENVIRONMENTS) == {"127.0.0.2", "127.0.0.3"}
    assert all(ip_address(ip).is_loopback for ip in ENVIRONMENTS)
    assert set(ENVIRONMENTS["127.0.0.2"]["tcp"].values()) == {"ftp", "ssh", "microsoft-ds", "redis"}
    assert ENVIRONMENTS["127.0.0.3"]["udp"] == {1161: "snmp", 1162: "snmp"}
    scope = settings().scope
    assert all(scope.contains(ip) for ip in ENVIRONMENTS)
    # CVE version-comparison endpoints are separately authorised; they do not
    # become Office/IoT protocol-fixture targets.
    assert scope.contains("127.0.0.4") and scope.contains("127.0.0.5")
    assert not scope.contains("127.0.0.6")


@pytest.mark.parametrize(
    "ip,endpoint",
    [
        ("127.0.0.1", None),
        ("192.0.2.2", None),
        ("127.0.0.4", None),
        ("127.0.0.2", {"host": "127.0.0.2", "port": 2121}),
    ],
)
def test_no_protocol_check_runs_outside_exact_lab_scope(tmp_path, monkeypatch, ip, endpoint):
    monkeypatch.setattr(probe, "_ftp", lambda _: pytest.fail("Out-of-scope socket check"))
    with pytest.raises(ScopeError):
        probe.run(settings().scope, ip, endpoint, tmp_path)
    assert not list(tmp_path.iterdir())


def test_declared_services_alone_never_produce_findings(tmp_path, monkeypatch):
    stub_protocols(monkeypatch, False)
    monkeypatch.setattr(probe, "_smb", lambda _: (False, {"signing_required": True}, True, {}))
    findings, _, coverage = probe.run(settings().scope, "127.0.0.2", None, tmp_path)
    assert findings == []
    assert "0 observed conditions" in coverage


@pytest.mark.parametrize("ip,expected", [("127.0.0.2", 4), ("127.0.0.3", 3)])
def test_observations_have_target_bound_provenance_and_no_invented_cves(
    tmp_path, monkeypatch, ip, expected
):
    stub_protocols(monkeypatch)
    findings, _, coverage = probe.run(settings().scope, ip, None, tmp_path)
    assert coverage.startswith("complete:")
    assert len(findings) == expected
    receipt = json.loads((tmp_path / "service-network-checks.json").read_text())
    for finding in findings:
        assert finding.host_ip == ip
        assert not finding.cve_ids
        assert finding.tool == "service-network"
        assert "SQL" not in finding.title
        row = receipt["checks"][finding.provenance.record_index]
        assert row["observed"] is True
        assert row["id"] == finding.tool_native_id
        assert probe.guidance(finding.to_json())["verify"]


def test_protocol_failure_is_partial_not_a_clean_result(tmp_path, monkeypatch):
    stub_protocols(monkeypatch)
    monkeypatch.setattr(
        probe, "_smb", lambda _: (_ for _ in ()).throw(RuntimeError("Synthetic protocol failure"))
    )
    findings, _, coverage = probe.run(settings().scope, "127.0.0.2", None, tmp_path)
    assert coverage.startswith("partial:")
    assert {finding.tool_native_id for finding in findings} == {
        "ftp-anonymous",
        "ssh-default-credential",
    }
    rows = json.loads((tmp_path / "service-network-checks.json").read_text())["checks"]
    assert next(row for row in rows if row["id"] == "smb-signing")["status"] == "error"


def test_failed_comparison_remains_visible(tmp_path, monkeypatch):
    stub_protocols(monkeypatch)
    monkeypatch.setattr(
        probe, "_mqtt", lambda _: (True, {"publish_received": True}, False, {"access": "connected"})
    )
    findings, _, coverage = probe.run(settings().scope, "127.0.0.3", None, tmp_path)
    assert len(findings) == 3
    assert coverage.startswith("partial:")


@pytest.mark.parametrize(
    "kind,primary",
    [
        ("_ftp_read", {"matches_training_file": True}),
        ("_smb_read", {"matches_training_file": True, "signing_required": False}),
        ("_mqtt_exchange", {"publish_received": True}),
    ],
)
def test_comparison_outage_preserves_primary_network_proof(monkeypatch, kind, primary):
    def reader(_ip, port, **_):
        if port in {2122, 1446, 1884}:
            raise ConnectionRefusedError("Synthetic comparison outage")
        return primary

    monkeypatch.setattr(probe, kind, reader)
    function = {"_ftp_read": probe._ftp, "_smb_read": probe._smb, "_mqtt_exchange": probe._mqtt}[
        kind
    ]
    observed, received, passed, comparison = function("127.0.0.2")
    assert observed is True
    assert received == primary
    assert passed is False
    assert comparison["access"] == "error"


def test_silent_snmp_port_never_becomes_confirmed_service(tmp_path, monkeypatch):
    stub_protocols(monkeypatch)
    monkeypatch.setattr(probe, "_snmp", lambda _: (False, {"access": "no response"}, True, {}))
    findings, services, coverage = probe.run(settings().scope, "127.0.0.3", None, tmp_path)
    assert coverage.startswith("partial:")
    assert all(service.port != 1161 for service in services)
    assert all(finding.tool_native_id != "snmp-public" for finding in findings)


def test_ssh_probe_cannot_consult_user_config_keys_or_proxy(monkeypatch):
    import sys
    from types import SimpleNamespace

    class Denied(Exception):
        pass

    def connect(ip, port, **options):
        assert options["config"] is None
        assert options["client_keys"] is None
        assert options["agent_path"] is None
        assert options["tunnel"] is None
        assert options["proxy_command"] is None
        assert options["public_key_auth"] is False
        raise Denied()

    monkeypatch.setitem(
        sys.modules, "asyncssh", SimpleNamespace(connect=connect, PermissionDenied=Denied)
    )
    # The fake connector rejects synchronously before the coroutine can suspend;
    # exercising this branch needs no event-loop socketpair under the offline guard.
    coroutine = probe._ssh_login("127.0.0.2", 2222)
    with pytest.raises(StopIteration) as completed:
        coroutine.send(None)
    assert completed.value.value["access"] == "denied"


@pytest.mark.parametrize("ip", ENVIRONMENTS)
def test_live_pipeline_uses_exact_ports_skips_web_and_ranks_protocol_findings(
    tmp_path, monkeypatch, ip
):
    config = tmp_path / "config"
    shutil.copytree(ROOT / "config", config)
    # This regression exercises the retained legacy fixture adapter, not the new policy runner.
    (config / "network-services.json").unlink(missing_ok=True)
    stub_protocols(monkeypatch)
    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: "nmap")

    def scanner(command, **_):
        assert command[-1] == ip
        assert "--top-ports" not in command
        assert command[command.index("-p") + 1] == ",".join(
            map(str, sorted(ENVIRONMENTS[ip]["tcp"]))
        )
        Path(command[command.index("-oX") + 1]).write_text(
            f'<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="1883"><state state="open"/>'
            '<service name="mqtt"/></port></ports></host></nmaprun>'
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(live_assessment.subprocess, "run", scanner)
    monkeypatch.setattr(analyst, "configuration_detail", lambda _: "Synthetic test configuration")
    received = []

    def analyze(payload, *_args, **_kwargs):
        received.append(payload)
        return {"analyst": None, "ai_status": "unavailable", "ai_attempts": []}

    monkeypatch.setattr(analyst, "analyze_optional", analyze)
    result = live_assessment.run(
        ip,
        {"status": "ready", "resolved_ips": [ip]},
        config,
        provider="google",
        on_progress=lambda *_: None,
    )
    payload = received[0]
    assert result["scan_status"] == "complete"
    assert len(payload["findings"]) == len(ENVIRONMENTS[ip]["checks"])
    assert len(payload["scores"]) == len(payload["findings"])
    assert payload["scanner_coverage"]["nikto"].startswith("not run")
    assert payload["scanner_coverage"]["service-network"].startswith("complete:")
    assert result["saved_assessment"]["status"] == "saved"
    assert all(not item["cve_ids"] for item in payload["findings"])
    from vulnassess.ui.server import _replay_evidence

    source = {**result, "payload": payload}
    _, status, _ = _replay_evidence(source, ip, lambda *_: None)
    assert status == "complete"
    payload["scanner_coverage"]["nmap"] = "exact lab TCP ports 1,2,3"
    _, status, _ = _replay_evidence(source, ip, lambda *_: None)
    assert status == "partial", "Unrecognised port coverage cannot become a completed retained scan"


def test_report_and_findings_use_network_specific_guidance():
    from vulnassess.ui.assessment_report import _finding_guidance
    from vulnassess.ui.vulnerability_findings import guidance

    finding = Finding.make(
        host_ip="127.0.0.2",
        port=2121,
        protocol="tcp",
        tool="service-network",
        tool_native_id="ftp-anonymous",
        title="Anonymous FTP permits file access",
        description="Observed anonymous file read",
        evidence="230 Login successful",
        provenance=Provenance("service-network", "proof.json", 0, "test"),
    ).to_json()
    assert "SFTP" in _finding_guidance(finding)[3]
    assert "SQL injection" in guidance(finding)["scenario"]
