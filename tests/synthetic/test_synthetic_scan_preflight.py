"""Local discovery/preflight checks cannot launch an unauthorized scanner."""

import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_all import SETTINGS
from vulnassess import live_assessment
from vulnassess.errors import ConfigError


@pytest.mark.parametrize(
    "provider,check,message",
    [
        ("unknown", {"status": "ready", "resolved_ips": ["127.0.0.1"]}, "Unknown analyst"),
        (
            "ollama",
            {"status": "blocked", "resolved_ips": ["127.0.0.1"], "reason": "synthetic denial"},
            "synthetic denial",
        ),
        ("ollama", {"status": "ready", "resolved_ips": []}, "one authorised address"),
        (
            "ollama",
            {"status": "ready", "resolved_ips": ["127.0.0.1", "172.28.0.10"]},
            "one authorised address",
        ),
    ],
)
def test_invalid_run_preflight_never_discovers_or_launches_scanners(
    monkeypatch, provider, check, message
):
    discover = Mock(side_effect=AssertionError("scanner discovery forbidden"))
    launch = Mock(side_effect=AssertionError("scanner launch forbidden"))
    monkeypatch.setattr(live_assessment, "nmap_binary", discover)
    monkeypatch.setattr(live_assessment.subprocess, "run", launch)
    with pytest.raises(ConfigError, match=message):
        live_assessment.run(
            "synthetic", check, SETTINGS.config_dir, provider=provider, on_progress=Mock()
        )
    discover.assert_not_called()
    launch.assert_not_called()


def test_missing_nmap_reports_configuration_error_without_launch(monkeypatch):
    monkeypatch.setattr(live_assessment, "nmap_binary", lambda: None)
    launch = Mock(side_effect=AssertionError("scanner launch forbidden"))
    monkeypatch.setattr(live_assessment.subprocess, "run", launch)
    with pytest.raises(ConfigError, match="Nmap is not installed"):
        live_assessment.run(
            "127.0.0.1",
            {"status": "ready", "resolved_ips": ["127.0.0.1"]},
            SETTINGS.config_dir,
            provider="ollama",
            on_progress=Mock(),
        )
    launch.assert_not_called()


@pytest.mark.parametrize("endpoint", [[], "http://synthetic.invalid", 1])
def test_nonobject_endpoint_metadata_is_rejected(endpoint):
    with pytest.raises(ConfigError, match="endpoint metadata is invalid"):
        live_assessment._validated_endpoint({"endpoint": endpoint})


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_literal_endpoint_addresses_preserve_pinning(host):
    endpoint = {"host": host, "port": 8080, "scheme": "http", "path": "/synthetic"}
    assert live_assessment._validated_endpoint({"endpoint": endpoint}) == endpoint


def test_nonwindows_discovery_does_not_consult_registry(monkeypatch):
    monkeypatch.setattr(live_assessment, "os", SimpleNamespace(name="posix"))
    assert live_assessment._registered_nmap_binary() is None


def test_windows_without_registry_module_reports_no_registered_install(monkeypatch):
    monkeypatch.setattr(live_assessment, "os", SimpleNamespace(name="nt"))
    monkeypatch.setitem(sys.modules, "winreg", None)
    assert live_assessment._registered_nmap_binary() is None


def test_registry_discovery_tries_second_view_after_inaccessible_first(tmp_path, monkeypatch):
    binary = tmp_path / "nmap.exe"
    binary.touch()
    registry = SimpleNamespace(
        KEY_WOW64_32KEY=32,
        KEY_WOW64_64KEY=64,
        KEY_READ=1,
        HKEY_LOCAL_MACHINE=2,
        OpenKey=Mock(
            side_effect=[PermissionError("synthetic first view"), nullcontext("synthetic-key")]
        ),
        QueryValueEx=Mock(return_value=(str(tmp_path), 1)),
    )
    monkeypatch.setattr(live_assessment, "os", SimpleNamespace(name="nt"))
    monkeypatch.setitem(sys.modules, "winreg", registry)
    assert live_assessment._registered_nmap_binary() == str(binary)
    assert registry.OpenKey.call_count == 2


def test_missing_nmap_install_has_actionable_message_and_never_executes(monkeypatch):
    monkeypatch.delenv("VULNASSESS_NMAP_BIN", raising=False)
    monkeypatch.setattr(live_assessment.shutil, "which", lambda _: None)
    monkeypatch.setattr(live_assessment, "_registered_nmap_binary", lambda: None)
    launch = Mock(side_effect=AssertionError("no executable to launch"))
    monkeypatch.setattr(live_assessment.subprocess, "run", launch)
    binary, detail = live_assessment.nmap_probe()
    assert binary is None
    assert "VULNASSESS_NMAP_BIN" in detail and "server PATH" in detail
    launch.assert_not_called()
