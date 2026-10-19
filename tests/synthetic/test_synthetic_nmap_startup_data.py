"""Synthetic startup failures, not installed-scanner or live-network verification."""

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vulnassess import live_assessment as live
from vulnassess.errors import ConfigError

ROOT = Path(__file__).resolve().parents[2]


def test_windows_executable_alone_is_not_ready(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "os", SimpleNamespace(name="nt", environ={}))
    binary = tmp_path / "nmap.exe"
    binary.touch()
    error = live._nmap_data_error(str(binary))
    assert all(name in error for name in ("nmap-protocols", "nmap-services", "nmap-service-probes"))
    assert "version check is not scan readiness" in error
    for name in ("nmap-protocols", "nmap-services", "nmap-service-probes"):
        (tmp_path / name).write_text("SYNTHETIC test data, not scanner provisioning")
    assert live._nmap_data_error(str(binary)) is None
    (tmp_path / "nmap-services").write_text("")
    assert "nmap-services" in live._nmap_data_error(str(binary))


def test_nmapdir_override_and_nonwindows(tmp_path, monkeypatch):
    override = tmp_path / "missing-override"
    monkeypatch.setattr(live, "os", SimpleNamespace(name="nt", environ={"NMAPDIR": str(override)}))
    assert str(override) in live._nmap_data_error("nmap.exe")
    monkeypatch.setattr(live, "os", SimpleNamespace(name="posix", environ={}))
    assert live._nmap_data_error("nmap") is None


def test_successful_version_does_not_hide_missing_data(monkeypatch):
    monkeypatch.setattr(live.shutil, "which", lambda _: "synthetic-nmap")
    monkeypatch.setattr(
        live.subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 0))
    )
    monkeypatch.setattr(live, "_nmap_data_error", lambda _: "MISSING nmap-protocols")
    assert live.nmap_probe() == (None, "MISSING nmap-protocols")


def test_actual_error_shape_retains_xml_cause_and_bounds_controls(tmp_path):
    capture = tmp_path / "synthetic_nmap_error.xml"
    capture.write_text(
        '<nmaprun><runstats><finished exit="error" errormsg="Unable to open /etc/protocols&#13;&#10; for reading"/></runstats></nmaprun>'
    )
    completed = subprocess.CompletedProcess([], 1, "", "")
    assert (
        live._nmap_failure_detail(completed, capture) == "Unable to open /etc/protocols for reading"
    )
    completed.stderr = "SYNTHETIC\x00\r\n" + "x" * 1000
    detail = live._nmap_failure_detail(completed, capture)
    assert len(detail) <= 500 and "\x00" not in detail and "\n" not in detail


@pytest.mark.parametrize("text", ["broken", '<!DOCTYPE x [<!ENTITY a "unsafe">]><nmaprun/>'])
def test_bad_diagnostic_xml_not_trusted(tmp_path, text):
    capture = tmp_path / "synthetic_bad_nmap.xml"
    capture.write_text(text)
    assert "invalid" in live._nmap_failure_detail(
        subprocess.CompletedProcess([], 1, "", ""), capture
    )


@pytest.mark.parametrize("failure", ["exit", "timeout", "os"])
def test_startup_failure_emits_scanner_error_and_never_calls_ai(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(live, "nmap_binary", lambda: "synthetic-nmap")
    monkeypatch.setattr(live, "mkdtemp", lambda **kwargs: str(tmp_path))
    events = []
    analyst = Mock(side_effect=AssertionError("No analysis without scan evidence"))
    monkeypatch.setattr(live.analyst, "analyze_target", analyst)
    if failure == "exit":
        (tmp_path / "nmap.xml").write_text(
            '<nmaprun><runstats><finished errormsg="Unable to open /etc/protocols"/></runstats></nmaprun>'
        )
        launch = Mock(return_value=subprocess.CompletedProcess([], 1, "", ""))
    else:
        error = subprocess.TimeoutExpired([], 180) if failure == "timeout" else OSError("runtime")
        launch = Mock(side_effect=error)
    monkeypatch.setattr(live.subprocess, "run", launch)
    with pytest.raises(ConfigError):
        live.run(
            "scanme.nmap.org",
            {"status": "ready", "resolved_ips": ["45.33.32.156"]},
            ROOT / "config",
            provider="ollama",
            on_progress=lambda *event: events.append(event),
        )
    assert events[-1][0:2] == ("scanner", "error")
    if failure == "exit":
        assert "/etc/protocols" in events[-1][2]
    analyst.assert_not_called()


def test_skipped_endpoint_does_not_mask_failed_or_completed_nmap():
    module = (ROOT / "vulnassess/ui/static/workflow-data.js").as_uri()
    script = f"""
import assert from 'node:assert/strict';
import {{nodeExecutionEntry, finishFailedExecution}} from {json.dumps(module)};
const stages = new Map([['scanner', {{state:'error',detail:'missing protocols'}}], ['endpoint_scan', {{state:'skipped',detail:'not run'}}]]);
assert.equal(nodeExecutionEntry(stages, ['scanner','endpoint_scan']).state, 'error');
const terminal = finishFailedExecution(new Map([['scanner', stages.get('scanner')]]), ['scanner','endpoint_scan','report'], 'stopped');
assert.equal([...terminal.values()].filter(x => x.state === 'error').length, 1);
stages.set('scanner', {{state:'complete'}});
assert.equal(nodeExecutionEntry(stages, ['scanner','endpoint_scan']).state, 'complete');
assert.equal(nodeExecutionEntry(new Map(), ['scanner']), undefined);
"""
    node = shutil.which("node")
    assert node is not None, "MISSING node for offline UI regression"
    completed = subprocess.run(
        [node, "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
