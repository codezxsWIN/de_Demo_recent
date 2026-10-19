"""Synthetic filesystem/HTML recovery checks; no real scanner or provider evidence."""

import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from tests.test_capture_history import capture
from vulnassess import capture_history, live_assessment
from vulnassess.errors import ConfigError
from vulnassess.saved_cve_case import load_saved_cve_case
from vulnassess.settings import Settings
from vulnassess.store import Store
from vulnassess.ui.server import UiApplication

ROOT = Path(__file__).resolve().parents[2]


def synthetic_capture(root, identity="assessment-synthetic-legacy", change=None):
    directory = root / identity
    directory.mkdir(parents=True)
    payload = {
        "hosts": [{"ip": "127.0.0.1", "services": [{"port": 22, "name": "SYNTHETIC"}]}],
        "findings": [
            {
                "id": "synthetic-finding",
                "host_ip": "127.0.0.1",
                "title": "SYNTHETIC retained finding",
                "cve_ids": [],
            }
        ],
        "scores": [
            {
                "finding_id": "synthetic-finding",
                "host_ip": "127.0.0.1",
                "risk": 80,
                "band": "Critical",
            }
        ],
        "context": [{"host_ip": "127.0.0.1"}],
        "enrichments": [],
    }
    if change:
        change(payload)
    raw = json.dumps(payload).encode()
    (directory / "case.json").write_bytes(raw)
    manifest = {
        "target": "http://synthetic.example:6379/",
        "resolved_ip": "127.0.0.1",
        "files": {"case.json": hashlib.sha256(raw).hexdigest()},
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def bytes_under(root):
    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


@pytest.fixture
def synthetic_app(tmp_path, monkeypatch):
    config = tmp_path / "config"
    shutil.copytree(ROOT / "config", config)
    database = tmp_path / "synthetic_history.db"
    with Store(database):
        pass
    monkeypatch.delenv("VULNASS_DATABASE_URL", raising=False)

    def forbidden(*args, **kwargs):
        raise AssertionError("History reads must not execute a scanner, publisher or model")

    monkeypatch.setattr(live_assessment.subprocess, "run", forbidden)
    monkeypatch.setattr(live_assessment.analyst, "analyze_optional", forbidden)
    monkeypatch.setattr(live_assessment.intel_online, "sync_cves", forbidden)
    return UiApplication(database, config), tmp_path / "data/live/raw"


def test_two_undated_captures_are_individually_viewable_but_not_automatically_selected(
    synthetic_app,
):
    app, root = synthetic_app
    directories = [synthetic_capture(root, f"assessment-synthetic-{n}") for n in (1, 2)]
    before = bytes_under(root)
    index = app.get("/captures")
    assert index.status == 200
    assert b"Legacy evidence" in index.body
    for directory in directories:
        assert directory.name.encode() in index.body
        response = app.get("/captures/" + directory.name)
        assert response.status == 200
        for label in (
            b"Legacy evidence",
            b"Collection time unknown",
            b"Collection status unknown",
            b"AI status unknown",
            b"SYNTHETIC retained finding",
            b"not revalidated",
        ):
            assert label in response.body
        assert b"Collection completed" not in response.body
        assert b"validated output" not in response.body
        assert app.get("/api/captures/" + directory.name).status == 409
    assert json.loads(app.get("/api/captures").body)["total"] == 0
    with pytest.raises(ConfigError, match="unknown chronology"):
        load_saved_cve_case(root, "http://synthetic.example:6379/", Settings(app.config_dir).scope)
    restarted = UiApplication(app.database, app.config_dir)
    assert (
        restarted.get("/captures/" + directories[0].name).body
        == app.get("/captures/" + directories[0].name).body
    )
    assert restarted.scan_plans._plans == restarted.evidence_requests._records == {}
    assert restarted._recent_live_cases == restarted._last_live_scan == {}
    assert bytes_under(root) == before


@pytest.mark.parametrize("filename", ["review-evidence.json", "review-final.json"])
def test_present_but_corrupt_receipt_never_falls_back_to_legacy_html(synthetic_app, filename):
    app, root = synthetic_app
    directory = synthetic_capture(root)
    (directory / filename).write_text("{}", encoding="utf-8")
    assert app.get("/captures/" + directory.name).status == 409
    assert b"Needs review" in app.get("/captures").body


def test_dangling_receipt_symlink_never_falls_back(synthetic_app, monkeypatch):
    app, root = synthetic_app
    directory = synthetic_capture(root)
    original = Path.is_symlink
    monkeypatch.setattr(
        Path, "is_symlink", lambda path: path == directory / "review-final.json" or original(path)
    )
    assert app.get("/captures/" + directory.name).status == 409


@pytest.mark.parametrize(
    "collection", ["hosts", "findings", "scores", "context", "enrichments", "rationales"]
)
def test_malformed_present_collection_is_controlled_failure(synthetic_app, collection):
    app, root = synthetic_app
    directory = synthetic_capture(root, change=lambda payload: payload.update({collection: None}))
    response = app.get("/captures/" + directory.name)
    assert response.status == 409
    assert b"Traceback" not in response.body


@pytest.mark.parametrize("owner", ["hosts", "findings", "context", "scores"])
def test_legacy_owners_must_match_the_manifest(synthetic_app, owner):
    app, root = synthetic_app

    def change(payload):
        payload[owner][0]["ip" if owner == "hosts" else "host_ip"] = "192.0.2.99"

    directory = synthetic_capture(root, change=change)
    assert app.get("/captures/" + directory.name).status == 409


def test_unowned_score_is_not_rendered_as_a_retained_finding(synthetic_app):
    app, root = synthetic_app
    directory = synthetic_capture(
        root, change=lambda payload: payload["scores"][0].update(finding_id="synthetic foreign")
    )
    assert app.get("/captures/" + directory.name).status == 409


def test_legacy_content_is_escaped_and_not_backfilled(synthetic_app):
    app, root = synthetic_app
    directory = synthetic_capture(
        root,
        change=lambda payload: payload["findings"][0].update(title="<script>SYNTHETIC</script>"),
    )
    before = bytes_under(root)
    response = app.get("/captures/" + directory.name)
    assert response.status == 200
    assert b"&lt;script&gt;SYNTHETIC&lt;/script&gt;" in response.body
    assert b"<script>" not in response.body
    assert b"Configuration receipt not recorded" in response.body
    assert b"Intelligence receipt not recorded" in response.body
    assert b"local consistency" in response.body
    assert b"authenticity" in response.body
    assert bytes_under(root) == before


def test_tampered_case_is_rejected(synthetic_app):
    app, root = synthetic_app
    directory = synthetic_capture(root)
    (directory / "case.json").write_text("{}", encoding="utf-8")
    assert app.get("/captures/" + directory.name).status == 409


@pytest.mark.parametrize("value", [True, 1.0, 2])
def test_receipt_schema_requires_an_actual_supported_integer(tmp_path, value):
    directory, result = capture(tmp_path)
    capture_history.save(directory, result, config_hash="synthetic configuration")
    path = directory / "review-evidence.json"
    record = json.loads(path.read_text())
    record["schema_version"] = value
    record["snapshot_hash"] = capture_history._hash(
        {key: item for key, item in record.items() if key != "snapshot_hash"}
    )
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ConfigError, match="schema"):
        capture_history.load(tmp_path, directory.name)


def test_private_legacy_listing_paginates_without_claiming_chronology(tmp_path):
    for number in range(21):
        synthetic_capture(tmp_path, f"assessment-synthetic-{number:02d}")
    before = bytes_under(tmp_path)
    first, second = (capture_history._listing_for_review(tmp_path, page) for page in (1, 2))
    assert len(first["captures"]) == 20 and len(second["captures"]) == 1
    assert first["total"] == second["total"] == 21
    assert all(
        item["status"] == "legacy" and item["captured_at"] is None for item in first["captures"]
    )
    assert first["captures"][0]["capture_id"] == "assessment-synthetic-20"
    assert bytes_under(tmp_path) == before


@pytest.mark.parametrize("part", ["case.json", "manifest.json", "directory"])
def test_legacy_symlink_boundaries_remain_closed(synthetic_app, monkeypatch, part):
    app, root = synthetic_app
    directory = synthetic_capture(root)
    target = directory if part == "directory" else directory / part
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == target or original(path))
    assert app.get("/captures/" + directory.name).status == 409


def test_manifest_cannot_read_outside_the_capture(synthetic_app):
    app, root = synthetic_app
    directory = synthetic_capture(root)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"]["../synthetic_secret.json"] = "0" * 64
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert app.get("/captures/" + directory.name).status == 409


@pytest.mark.parametrize("kind", ["malformed", "deep"])
def test_invalid_json_is_a_controlled_review_failure(synthetic_app, kind):
    app, root = synthetic_app
    directory = synthetic_capture(root)
    depth = max(10_000, sys.getrecursionlimit() + 20)
    assert depth < 1_000_000, "Synthetic decoder stress must stay within the capture byte budget"
    raw = (
        b'{"synthetic":'
        if kind == "malformed"
        else b'{"synthetic":' + b"[" * depth + b"0" + b"]" * depth + b"}"
    )
    (directory / "case.json").write_bytes(raw)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"]["case.json"] = hashlib.sha256(raw).hexdigest()
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    response = app.get("/captures/" + directory.name)
    assert response.status == 409
    assert b"Saved assessment JSON is malformed" in response.body


def test_case_byte_budget_is_enforced_before_decoding(synthetic_app, monkeypatch):
    app, root = synthetic_app
    directory = synthetic_capture(root)
    budget = (directory / "manifest.json").stat().st_size
    assert (directory / "case.json").stat().st_size > budget
    monkeypatch.setattr(capture_history, "MAX_BYTES", budget)
    assert app.get("/captures/" + directory.name).status == 409


def test_manifest_file_count_is_bounded(synthetic_app):
    app, root = synthetic_app
    directory = synthetic_capture(root)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"].update({f"synthetic-part-{n}.json": "0" * 64 for n in range(20)})
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert app.get("/captures/" + directory.name).status == 409


def test_aggregate_read_budget_is_enforced_with_small_in_memory_buffers(synthetic_app, monkeypatch):
    app, root = synthetic_app
    directory = synthetic_capture(root)
    manifest = json.loads((directory / "manifest.json").read_text())
    names = [f"synthetic-part-{n}.json" for n in range(9)]
    manifest["files"].update({name: hashlib.sha256(b"{}").hexdigest() for name in names})
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    class SyntheticLarge(bytes):
        def __len__(self):
            return 8 * 1024 * 1024

    original = capture_history._bytes
    monkeypatch.setattr(
        capture_history,
        "_bytes",
        lambda path, name: SyntheticLarge(b"{}") if name in names else original(path, name),
    )
    assert app.get("/captures/" + directory.name).status == 409


def test_missing_sections_stay_unrecorded_and_declared_time_is_not_refreshed(synthetic_app):
    app, root = synthetic_app

    def change(payload):
        for key in ("scores", "context", "enrichments"):
            del payload[key]

    directory = synthetic_capture(root, change=change)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["captured_at"] = "2020-01-01T00:00:00+00:00"
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    before = bytes_under(root)
    response = app.get("/captures/" + directory.name)
    assert response.status == 200
    assert b"2020-01-01" in response.body and b"declared in manifest" in response.body
    assert b"Stored priority values</dt><dd>Not recorded" in response.body
    assert b"AI status unknown" in response.body
    assert bytes_under(root) == before


@pytest.mark.parametrize("collection", ["hosts", "findings", "scores"])
def test_receipt_payload_collection_corruption_does_not_escape_as_type_error(tmp_path, collection):
    directory, result = capture(tmp_path)
    capture_history.save(directory, result, config_hash="synthetic configuration")
    payload = json.loads((directory / "case.json").read_text())
    payload[collection] = None
    raw = json.dumps(payload).encode()
    (directory / "case.json").write_bytes(raw)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"]["case.json"] = hashlib.sha256(raw).hexdigest()
    manifest_raw = json.dumps(manifest).encode()
    (directory / "manifest.json").write_bytes(manifest_raw)
    record = json.loads((directory / "review-evidence.json").read_text())
    record["manifest_hash"] = hashlib.sha256(manifest_raw).hexdigest()
    record["evidence_hash"] = capture_history._hash(payload)
    record["snapshot_hash"] = capture_history._hash(
        {key: item for key, item in record.items() if key != "snapshot_hash"}
    )
    (directory / "review-evidence.json").write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ConfigError, match="list of objects"):
        capture_history.load(tmp_path, directory.name)
