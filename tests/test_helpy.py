"""Extractive assistance must never turn model-written facts into report evidence."""

import copy
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_assessment_report import setup_report
from tests.test_ui import request
from vulnassess import capture_history, helpy
from vulnassess.errors import ConfigError, LLMUnavailable
from vulnassess.ui import assessment_report


def test_offline_voice_transcript_and_highlight_contract():
    node = shutil.which("node")
    assert node, "Node is required for the Helpy browser contract"
    completed = subprocess.run(
        [node, "tests/synthetic/helpy_check.mjs"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def record_at(tmp_path):
    app, directory = setup_report(tmp_path)
    return app, capture_history.load(directory.parent, directory.name)


def client(output):
    return SimpleNamespace(
        model="SYNTHETIC selector", generate_structured=lambda *a, **k: copy.deepcopy(output)
    )


def test_selected_text_is_server_owned_not_model_written(tmp_path):
    _, record = record_at(tmp_path)
    result = helpy.answer(
        record,
        "What matters?",
        client({"status": "supported", "references": ["B1:executive", "B1:context"]}),
    )
    assert result["capture_id"] == record["capture_id"]
    assert result["excerpts"][0]["text"] == "SYNTHETIC observed loopback service."
    assert result["excerpts"][0]["citations"] == ["E1"]
    assert result["excerpts"][0]["batch"] == 1


@pytest.mark.parametrize(
    "output",
    [
        {"status": "supported", "references": ["invented"]},
        {"status": "supported", "references": []},
        {"status": "supported", "references": ["R:limits", "R:limits"]},
        {"status": "supported", "references": [None]},
        {"status": "supported", "references": ["R:limits"], "answer": "Fabricated safe verdict"},
        {"status": "safe", "references": ["R:limits"]},
    ],
)
def test_rejects_unbound_or_model_written_output(tmp_path, output):
    _, record = record_at(tmp_path)
    with pytest.raises(LLMUnavailable):
        helpy.answer(record, "Explain", client(output))


def test_rejected_analysis_never_enters_assistance(tmp_path):
    _, record = record_at(tmp_path)
    record["result"]["analyst"]["analysis"]["summary"] = "HIDDEN fabrication"
    record["result"]["analyst"]["analysis"]["claims"][0]["quotes"][0]["text"] = (
        "Fabricated evidence quote"
    )
    assert not any(ref.startswith("B") for ref in helpy.sources(record))
    assert "HIDDEN" not in str(helpy.sources(record))


def test_unknown_answer_does_not_promote_observations(tmp_path):
    _, record = record_at(tmp_path)
    result = helpy.answer(
        record,
        "Am I compromised?",
        client({"status": "not_established", "references": ["B1:executive", "R:limits"]}),
    )
    assert [item["reference"] for item in result["excerpts"]] == ["R:limits"]
    assert "does not establish" in result["message"]


@pytest.mark.parametrize("question", ["", " " * 8, "a" * 601, None])
def test_question_budget(tmp_path, question):
    _, record = record_at(tmp_path)
    with pytest.raises(ConfigError):
        helpy.answer(record, question, client({}))


def test_cloud_consent_required_before_provider_or_capture_load(tmp_path, monkeypatch):
    app, record = record_at(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("Provider must not be contacted")

    monkeypatch.setattr("vulnassess.analyst.provider_client", forbidden)
    with pytest.raises(ConfigError):
        app.helpy_answer(
            {
                "capture_id": record["capture_id"],
                "question": "Explain",
                "provider": "google",
                "share_evidence": False,
            }
        )


def test_assistance_lock_released_on_failure(tmp_path, monkeypatch):
    app, record = record_at(tmp_path)

    def fail(*args, **kwargs):
        raise ConfigError("SYNTHETIC unavailable")

    monkeypatch.setattr("vulnassess.analyst.provider_client", fail)
    with pytest.raises(ConfigError):
        app.helpy_answer(
            {
                "capture_id": record["capture_id"],
                "question": "Explain",
                "provider": "ollama",
                "share_evidence": False,
            }
        )
    assert app._helpy_lock.acquire(blocking=False)
    app._helpy_lock.release()


def test_live_panel_not_embedded_in_inert_download(tmp_path):
    _, record = record_at(tmp_path)
    live = assessment_report.render(record)
    assert 'id="helpy-panel"' in live
    assert "/static/helpy.js" in live
    assert 'data-claim-ref="B1:executive"' in live
    download = assessment_report.render(record, standalone=True)
    assert 'id="helpy-panel"' not in download
    assert "<script" not in download


def test_http_helpy_requires_explicit_same_origin_action(tmp_path, monkeypatch):
    app, _ = record_at(tmp_path)
    monkeypatch.setattr(app, "helpy_answer", lambda body: {"status": "supported"})
    body = b"{}"
    base = "Content-Type: application/json\r\nContent-Length: 2\r\n"
    assert request(app, "/api/helpy", "POST", extra_headers=base, body=body)[0] == 403
    valid = base + "Origin: http://127.0.0.1:8765\r\nX-VulnAssess-Action: helpy\r\n"
    status, _, output = request(app, "/api/helpy", "POST", extra_headers=valid, body=body)
    assert status == 200
    assert json.loads(output) == {"status": "supported"}
    assert (
        request(
            app, "/api/helpy", "POST", extra_headers=valid + "Content-Length: 2\r\n", body=body
        )[0]
        == 409
    )


def test_http_provider_failure_does_not_expose_credentials(tmp_path, monkeypatch):
    app, _ = record_at(tmp_path)

    def fail(body):
        raise ConfigError("SYNTHETIC-private-key-do-not-disclose")

    monkeypatch.setattr(app, "helpy_answer", fail)
    headers = "Content-Type: application/json\r\nContent-Length: 2\r\nOrigin: http://127.0.0.1:8765\r\nX-VulnAssess-Action: helpy\r\n"
    status, _, output = request(app, "/api/helpy", "POST", extra_headers=headers, body=b"{}")
    assert status == 409
    assert b"private-key" not in output
