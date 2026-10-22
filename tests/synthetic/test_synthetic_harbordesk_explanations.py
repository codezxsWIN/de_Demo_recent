"""Pure-logic explanation API and offline browser-contract checks."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from labs.harbordesk import app
from tests.synthetic.test_synthetic_harbordesk_impact import Client
from tests.test_harbordesk_lab import request
from vulnassess.harbordesk_guidance import guidance

ROOT = Path(__file__).resolve().parents[2]


def test_every_case_reuses_complete_reviewed_guidance_without_changing_the_catalog() -> None:
    source = app.ROOT / "ground-truth.json"
    original = source.read_bytes()
    raw = json.loads(original)
    status, _, body = request("/__lab__/ground-truth")
    catalog = json.loads(body)
    assert status == 200 and len(catalog["cases"]) == len(raw["cases"]) == 23
    for case, original_case in zip(catalog["cases"], raw["cases"], strict=True):
        explanation = case.pop("explanation")
        assert case == original_case
        assert explanation == guidance({"tool": "harbordesk", "tool_native_id": case["id"]})
        for key in ("category", "meaning", "scenario", "impact", "source"):
            assert isinstance(explanation[key], str) and explanation[key].strip()
        for key in ("patch", "verify", "prerequisites"):
            assert explanation[key] and all(isinstance(item, str) for item in explanation[key])
        assert "No vendor CVE" in explanation["source"]
        assert "risk" not in explanation and "observed_intentional_weakness" not in explanation
    assert source.read_bytes() == original


def test_missing_reviewed_explanation_is_an_explicit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app, "reviewed_guidance", lambda _finding: None)
    status, _, body = request("/__lab__/ground-truth")
    data = json.loads(body)
    assert status == 500 and data["fixture"] is True
    assert "Missing reviewed explanation for HD-01" in data["error"]
    assert "vulnassess/harbordesk_guidance.py" in data["error"]
    assert "cases" not in data


def test_explanation_reads_do_not_change_active_training_state() -> None:
    client = Client()
    client.server.workspace.update_profile("demo", {"role": "admin"})
    client.server.workspace.update_order(2002, 777)
    before_profile = client.server.workspace.profile("demo")
    before_order = client.server.workspace.order(2002)
    status, data = client.api("/__lab__/ground-truth")
    assert status == 200 and len(data["cases"]) == 23
    assert client.server.workspace.profile("demo") == before_profile
    assert client.server.workspace.order(2002) == before_order
    assert client.server.secure_workspace.profile("demo")["role"] == "customer"


def test_dialog_and_shortcuts_preserve_the_existing_training_controls() -> None:
    status, _, body = request("/")
    assert status == 200
    assert b'id="case-explanation"' in body
    assert b'aria-labelledby="explanation-title"' in body
    assert b'id="explanation-close"' in body
    for identity in ("HD-17", "HD-18", "HD-19", "HD-23", "HD-24"):
        assert f'data-explain-case="{identity}"'.encode() in body
    for identity in ("role-form", "order-write-form", "export-fixtures", "network-cases"):
        assert f'id="{identity}"'.encode() in body


def test_offline_explanation_browser_contract() -> None:
    node = shutil.which("node")
    assert node is not None, "MISSING: Node.js executable 'node'"
    script = ROOT / "tests" / "synthetic" / "synthetic_harbordesk_explanations_check.mjs"
    guard = ROOT / "scripts" / "offline_pyright_guard.cjs"
    assert script.is_file(), f"MISSING: {script}"
    assert guard.is_file(), f"MISSING: {guard}"
    result = subprocess.run(
        [node, "--require", str(guard), str(script)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
        env={**os.environ, "NODE_OPTIONS": ""},
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "9 explanation interaction checks passed" in result.stdout
