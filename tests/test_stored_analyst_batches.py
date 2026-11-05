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


