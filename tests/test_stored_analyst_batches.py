"""Stored UI requests must review the whole target, not stop after one batch."""

import copy
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from vulnassess import analyst
from vulnassess.errors import NeedsReview
from vulnassess.ui import server


@pytest.fixture
def stored_app(monkeypatch):
    ip = "192.0.2.10"
    payload = {
        "run": {"run_id": "SYNTHETIC-retained"},
        "hosts": [{"ip": ip, "services": [{"port": 22}]}],
        "findings": [
            {"id": f"SYNTHETIC-{i}", "host_ip": ip, "port": 22, "protocol": "tcp"} for i in range(6)
        ],
        "scores": [],
        "enrichments": [],
    }

    @contextmanager
    def read_only(_database):
        yield SimpleNamespace(run=lambda _run: copy.deepcopy(payload))

    monkeypatch.setattr(server, "open_read_store", read_only)
    app = object.__new__(server.UiApplication)
    app.database = "SYNTHETIC-no-file-opened"
    app.evidence_requests = SimpleNamespace(evidence=lambda *_: [])
    app.analyst_model = "SYNTHETIC-custom-local-model"
    app.ollama_host = "http://127.0.0.1:11435"
    return app, payload, ip


@pytest.mark.parametrize("provider", ["ollama", "google"])
def test_every_stored_finding_reaches_the_ui_result_with_its_batch_scope(
    stored_app, monkeypatch, provider
):
    app, payload, ip = stored_app
    original = copy.deepcopy(payload)
    calls = []

    def one_at_a_time(current, host, **options):
        assert host == ip and options["provider"] == provider
        assert options["model"] == app.analyst_model and options["ollama_host"] == app.ollama_host
        identity = current["findings"][0]["id"]
        calls.append(identity)
        return {"finding_coverage": {"included_ids": [identity]}, "canonical_scores_changed": False}

    monkeypatch.setattr(analyst, "analyze_target", one_at_a_time)
    result = app.analyst_report("SYNTHETIC-retained", ip, provider=provider)
    assert len(calls) == 6 and set(calls) == {row["id"] for row in payload["findings"]}
    assert result["batch_coverage"]["findings_included"] == 6
    assert result["batch_coverage"]["findings_omitted"] == 0
    assert result["run_id"] == "SYNTHETIC-retained" and payload == original


def test_failed_later_batch_cannot_be_shown_as_a_complete_stored_assessment(
    stored_app, monkeypatch
):
    app, payload, ip = stored_app
    calls = []

    def fails_second(current, *_args, **_kwargs):
        calls.append(current["findings"][0]["id"])
        if len(calls) > 1:
            raise NeedsReview("SYNTHETIC later batch rejected")
        return {"finding_coverage": {"included_ids": [calls[0]]}}

    monkeypatch.setattr(analyst, "analyze_target", fails_second)
    with pytest.raises(NeedsReview, match="later batch"):
        app.analyst_report("SYNTHETIC-retained", ip, provider="google")
    assert len(calls) == 2 and len(payload["findings"]) == 6
