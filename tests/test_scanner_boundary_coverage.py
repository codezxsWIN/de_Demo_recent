"""Scanner installation and execution contracts; subprocesses are always test doubles."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_assessment_snapshot import SETTINGS
from vulnassess import orchestrator, runner
from vulnassess.errors import AdapterError, ConfigError
from vulnassess.readers import nessus_xml, nikto_json, zap_json


@pytest.fixture(autouse=True)
def no_scanners(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", Mock(side_effect=AssertionError("real scanner forbidden"))
    )
    monkeypatch.setattr(orchestrator.shutil, "which", Mock(return_value=None))
    for name in (
        "VULNASSESS_NIKTO_BIN",
        "VULNASSESS_NIKTO_SCRIPT",
        "VULNASSESS_PERL_BIN",
        "VULNASSESS_PERL_LIB",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("suffix", [".pl", ".exe"])
def test_explicit_nikto_file_resolution(tmp_path, monkeypatch, suffix):
    script = tmp_path / f"nikto{suffix}"
    script.touch()
    monkeypatch.setenv("VULNASSESS_NIKTO_BIN", str(script))
    monkeypatch.setenv("VULNASSESS_PERL_BIN", "synthetic-perl")
    expected = ("synthetic-perl", str(script)) if suffix == ".pl" else (str(script),)
    assert orchestrator.scanner_argv("nikto") == expected
    assert orchestrator._nikto_cwd(expected) == (str(tmp_path) if suffix == ".pl" else None)


def test_explicit_script_uses_fallback_perl_and_vendor_module(tmp_path, monkeypatch):
    script = tmp_path / "program/nikto.pl"
    script.parent.mkdir()
    script.touch()
    perl = tmp_path / "perl.exe"
    perl.touch()
    library = tmp_path / "vendor/lib/XML/Writer.pm"
    library.parent.mkdir(parents=True)
    library.touch()
    monkeypatch.setattr(orchestrator, "PERL_DEFAULT", perl)
    monkeypatch.setenv("VULNASSESS_NIKTO_BIN", str(script))
    assert orchestrator.scanner_argv("nikto") == (
        str(perl),
        "-I",
        str(library.parent.parent),
        str(script),
    )


def test_missing_explicit_binary_does_not_use_unrelated_install(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNASSESS_NIKTO_BIN", str(tmp_path / "missing"))
    assert orchestrator.scanner_argv("nikto") is None
    with pytest.raises(ConfigError, match="unknown locally executable"):
        orchestrator.scanner_argv("arbitrary")


@pytest.mark.parametrize(
    "result,status",
    [
        (OSError("blocked"), "dependency-error"),
        (subprocess.TimeoutExpired("perl", 10), "dependency-error"),
        (
            SimpleNamespace(returncode=1, stdout="", stderr="XML::Writer missing"),
            "dependency-error",
        ),
        (SimpleNamespace(returncode=0, stdout="Nikto", stderr=""), "available"),
    ],
)
def test_nikto_preflight_status_does_not_claim_failed_install_is_ready(
    tmp_path, monkeypatch, result, status
):
    script = tmp_path / "nikto.pl"
    script.touch()
    monkeypatch.setattr(orchestrator, "scanner_argv", Mock(return_value=("perl", str(script))))
    run = Mock(side_effect=result) if isinstance(result, Exception) else Mock(return_value=result)
    monkeypatch.setattr(subprocess, "run", run)
    assert orchestrator.scanner_status("nikto")["status"] == status
    assert run.call_args.args[0] == ["perl", str(script), "-Version"]
    assert run.call_args.kwargs["timeout"] == 10


def test_nmap_absent_status_is_unavailable(monkeypatch):
    monkeypatch.setattr(orchestrator, "scanner_argv", Mock(return_value=None))
    assert orchestrator.scanner_status("nmap")["status"] == "unavailable"


@pytest.mark.parametrize(
    "returncode,writes,expect_error", [(0, True, False), (1, True, False), (1, False, True)]
)
def test_legacy_runner_execution_outcome(tmp_path, monkeypatch, returncode, writes, expect_error):
    monkeypatch.setattr(runner, "missing_binaries", Mock(return_value=[]))

    def execute(argv, **kwargs):
        assert kwargs == {"capture_output": True, "text": True, "timeout": 7, "check": False}
        assert argv[-1] == "172.28.0.10"
        if writes:
            Path(argv[argv.index("-oX") + 1]).write_text("<nmaprun/>")
        return SimpleNamespace(returncode=returncode)

    run = Mock(side_effect=execute)
    monkeypatch.setattr(subprocess, "run", run)
    if expect_error:
        with pytest.raises(AdapterError, match="wrote no output"):
            runner.run_scan(SETTINGS, "172.28.0.10", ["nmap"], tmp_path, execute=True, timeout=7)
    else:
        result = runner.run_scan(
            SETTINGS, "172.28.0.10", ["nmap"], tmp_path, execute=True, timeout=7
        )
        assert result["executed"] and result["exit_codes"] == {"nmap": returncode}
    run.assert_called_once()


@pytest.mark.parametrize(
    "xml,reason",
    [
        ("<broken", "valid report XML"),
        ("<NessusClientData_v2><Report/></NessusClientData_v2>", "no ReportHost"),
        (
            '<NessusClientData_v2><Report><ReportHost name="name.invalid"/></Report></NessusClientData_v2>',
            "verified host-ip",
        ),
        (
            '<NessusClientData_v2><Report><ReportHost name="192.0.2.1"><HostProperties><tag name="host-ip">bad</tag></HostProperties></ReportHost></Report></NessusClientData_v2>',
            "verified host-ip",
        ),
    ],
)
def test_nessus_rejects_unverified_host_documents(tmp_path, xml, reason):
    path = tmp_path / "test.nessus"
    path.write_text(xml)
    with pytest.raises(AdapterError, match=reason):
        nessus_xml.parse_nessus_xml(path, "synthetic")


@pytest.mark.parametrize(
    "attributes,reason",
    [
        ('severity="invalid"', "severity"),
        ('severity="3"', "pluginID"),
        ('severity="3" pluginID="123" port="bad"', "port"),
        ('severity="3" pluginID="123" port="65536"', "port"),
    ],
)
def test_nessus_bad_items_are_not_partial_findings(tmp_path, attributes, reason):
    path = tmp_path / "test.nessus"
    path.write_text(
        f'<NessusClientData_v2><Report><ReportHost name="192.0.2.1"><ReportItem {attributes}/></ReportHost></Report></NessusClientData_v2>'
    )
    with pytest.raises(AdapterError, match=reason):
        nessus_xml.parse_nessus_xml(path, "synthetic")


@pytest.mark.parametrize(
    "payload,reason",
    [
        (None, "vulnerabilities"),
        ({"vulnerabilities": []}, "neither"),
        ({"ip": "192.0.2.1", "vulnerabilities": [None]}, "non-object"),
    ],
)
def test_nikto_bad_records_fail_closed(tmp_path, payload, reason):
    path = tmp_path / "nikto.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(AdapterError, match=reason):
        nikto_json.parse_nikto_json(path, "synthetic")


def test_nikto_invalid_port_uses_documented_http_default(tmp_path):
    path = tmp_path / "nikto.json"
    path.write_text(
        json.dumps(
            {
                "ip": "192.0.2.1",
                "port": "bad",
                "vulnerabilities": [{"id": "123", "msg": "synthetic"}],
            }
        )
    )
    findings = nikto_json.parse_nikto_json(path, "synthetic")
    assert len(findings) == 1 and findings[0].port == 80
    assert findings[0].native_severity is None


@pytest.mark.parametrize(
    "payload,reason",
    [({}, "top-level"), ({"site": [None]}, "non-object"), ({"site": [{}]}, "neither")],
)
def test_zap_bad_documents_fail_closed(tmp_path, payload, reason):
    path = tmp_path / "zap.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(AdapterError, match=reason):
        zap_json.parse_zap_json(path, "synthetic")


def test_zap_host_and_port_fallbacks_do_not_invent_severity(tmp_path):
    assert zap_json._host_from({"@name": "https://192.0.2.1/"}) == "192.0.2.1"
    assert zap_json._port_of("https://192.0.2.1/", {}) == 443
    assert zap_json._port_of("http://192.0.2.1/", {}) == 80
    assert zap_json._port_of("/relative", {"@port": "bad"}) == 80
    assert zap_json._port_of("/relative", {"@port": 8080}) == 8080
