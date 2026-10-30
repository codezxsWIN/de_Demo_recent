"""Configuration-only discovery and workflow selection regression checks."""

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vulnassess.errors import ConfigError
from vulnassess.ui import server


@pytest.mark.parametrize(
    "configured,recommended",
    [
        ({"google"}, "google"),
        ({"google", "groq", "groq_qwen", "openrouter"}, "google"),
        ({"groq", "groq_qwen", "openrouter"}, "groq"),
        ({"groq_qwen", "openrouter"}, "groq_qwen"),
        ({"openrouter"}, "openrouter"),
        (set(), "ollama"),
    ],
)
def test_configuration_recommendation_does_not_probe_or_expose_keys(
    monkeypatch, configured, recommended
):
    clients = {
        provider: SimpleNamespace(
            key="PRIVATE-secret" if provider in configured else "  ",
            available=Mock(side_effect=AssertionError("Must not probe availability")),
        )
        for provider in ("google", "groq", "groq_qwen", "openrouter")
    }
    factory = Mock(side_effect=clients.__getitem__)
    monkeypatch.setattr(server.analyst, "provider_client", factory)
    app = object.__new__(server.UiApplication)
    response = app.get("/api/analyst-providers")
    assert response.status == 200
    result = json.loads(response.body)
    assert result["recommended"] == recommended
    assert result["providers"] == [
        {"id": provider, "configured": provider in configured} for provider in clients
    ]
    assert "PRIVATE" not in response.body.decode()
    assert "availability" in result["detail"]
    assert all(set(item) == {"id", "configured"} for item in result["providers"])
    assert factory.call_count == 4
    for client in clients.values():
        client.available.assert_not_called()


@pytest.mark.parametrize("error", [ConfigError("PRIVATE"), OSError("PRIVATE"), UnicodeError("PRIVATE")])
def test_unreadable_credentials_are_unknown_and_do_not_break_discovery(monkeypatch, error):
    def client(provider):
        if provider == "google":
            raise error
        return SimpleNamespace(key="secret" if provider == "groq" else "")

    monkeypatch.setattr(server.analyst, "provider_client", client)
    app = object.__new__(server.UiApplication)
    response = app.get("/api/analyst-providers")
    result = json.loads(response.body)
    assert response.status == 200
    assert result["providers"][0] == {"id": "google", "configured": None}
    assert result["recommended"] == "groq"
    assert "PRIVATE" not in response.body.decode()


def test_workflow_provider_selection_consent_and_attempt_details():
    node = shutil.which("node")
    assert node, "Node is required for workflow regression checks"
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [node, "tests/synthetic/analyst_provider_check.mjs"],
        cwd=root, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
