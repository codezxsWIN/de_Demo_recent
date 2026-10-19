"""Synthetic replay discovery must isolate candidates without bypassing verification."""

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnassess.errors import ConfigError
from vulnassess.saved_cve_case import load_saved_cve_case

TARGET = "http://synthetic.example:6379/"
ADDRESS = "192.0.2.10"
CANARY = "192.0.2.99"
SCOPE = SimpleNamespace(
    contains=lambda ip: ip in (ADDRESS, CANARY), is_canary=lambda ip: ip == CANARY
)


def write_capture(root, name, timestamp, *, target=TARGET, payload=None, recorded_at=None):
    directory = root / name
    directory.mkdir()
    if payload is None:
        payload = {
            "hosts": [{"ip": ADDRESS, "services": []}],
            "findings": [
                {
                    "id": "synthetic-capture-finding",
                    "host_ip": ADDRESS,
                    "cve_ids": ["CVE-2022-0543"],
                }
            ],
        }
    content = json.dumps(payload).encode("utf-8")
    (directory / "case.json").write_bytes(content)
    manifest = {
        "target": target,
        "resolved_ip": ADDRESS,
        "files": {"case.json": hashlib.sha256(content).hexdigest()},
    }
    if recorded_at is not None:
        manifest["captured_at"] = recorded_at
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    os.utime(manifest_path, (timestamp, timestamp))
    os.utime(directory, (timestamp, timestamp))
    return directory


def deny_manifest_read(monkeypatch, path):
    original = Path.open

    def open_file(candidate, *args, **kwargs):
        if candidate == path:
            raise PermissionError("synthetic discovery read failure")
        return original(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_file)


@pytest.mark.parametrize("failure", ["json", "encoding", "shape", "permission"])
def test_unreadable_newer_manifest_does_not_block_independent_matching_capture(
    tmp_path, monkeypatch, failure
):
    valid = write_capture(tmp_path, "assessment-synthetic-older", 1700000000)
    rejected = write_capture(
        tmp_path, "assessment-synthetic-unrelated", 1700000100, target="synthetic-unrelated"
    )
    path = rejected / "manifest.json"
    if failure != "permission":
        invalid_manifests = {
            "json": b'{"target":"synthetic-unrelated",',
            "encoding": b"\xff",
            "shape": b"[]",
        }
        path.write_bytes(invalid_manifests[failure])
    before = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}

    with monkeypatch.context() as guard:
        if failure == "permission":
            deny_manifest_read(guard, path)
        result = load_saved_cve_case(tmp_path, TARGET, SCOPE)

    assert result["target"] == TARGET
    assert result["resolved_ip"] == ADDRESS
    assert result["evidence_directory"] == str(valid)
    assert result["historical_capture"] is True
    assert result["payload"]["findings"][0]["cve_ids"] == ["CVE-2022-0543"]
    diagnostics = result["discovery_diagnostics"]
    assert len(diagnostics) == 1
    assert diagnostics[0]["evidence_directory"] == str(rejected)
    assert "unreadable or malformed" in diagnostics[0]["reason"]
    assert {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()} == before


def test_parseable_unrelated_manifest_does_not_need_matching_evidence_validation(tmp_path):
    valid = write_capture(tmp_path, "assessment-synthetic-older", 1700000000)
    unrelated = write_capture(
        tmp_path, "assessment-synthetic-unrelated", 1700000100, target="synthetic-unrelated"
    )
    (unrelated / "manifest.json").write_text(
        json.dumps({"target": "synthetic-unrelated", "files": None}), encoding="utf-8"
    )

    result = load_saved_cve_case(tmp_path, TARGET, SCOPE)

    assert result["evidence_directory"] == str(valid)


@pytest.mark.parametrize(
    "failure,message",
    [
        ("scope", "outside the current authorized scope"),
        ("canary", "outside the current authorized scope"),
        ("hash", "hash mismatch"),
        ("missing-case", "unreadable or malformed"),
        ("missing-address", "unreadable or malformed"),
        ("files-shape", "Invalid saved capture manifest"),
        ("evidence-json", "unreadable or malformed"),
        ("evidence-encoding", "unreadable or malformed"),
        ("evidence-shape", "unreadable or malformed"),
        ("finding-shape", "unreadable or malformed"),
        ("empty-hosts", "unreadable or malformed"),
        ("cve-shape", "unreadable or malformed"),
        ("different-host", "contains a different target"),
    ],
)
def test_identified_matching_capture_failure_refuses_older_valid_fallback(
    tmp_path, failure, message
):
    write_capture(
        tmp_path, "assessment-synthetic-older", 1700000000, recorded_at="2020-01-01T00:00:00Z"
    )
    invalid = write_capture(
        tmp_path, "assessment-synthetic-matching", 1700000100, recorded_at="2021-01-01T00:00:00Z"
    )
    manifest_path = invalid / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    case_path = invalid / "case.json"
    if failure in ("scope", "canary"):
        manifest["resolved_ip"] = "192.0.2.11" if failure == "scope" else CANARY
    elif failure == "missing-address":
        del manifest["resolved_ip"]
    elif failure == "files-shape":
        manifest["files"] = ["case.json"]
    elif failure == "missing-case":
        case_path.unlink()
    else:
        payload = json.loads(case_path.read_text(encoding="utf-8"))
        if failure == "different-host":
            payload["hosts"][0]["ip"] = "192.0.2.11"
        elif failure == "empty-hosts":
            payload["hosts"] = []
        elif failure == "finding-shape":
            payload["findings"] = [7]
        elif failure == "cve-shape":
            payload["findings"][0]["cve_ids"] = "CVE-2022-0543"
        content = {
            "evidence-json": b"{",
            "evidence-encoding": b"\xff",
            "evidence-shape": b"[]",
            "hash": b"{}",
        }.get(failure, json.dumps(payload).encode("utf-8"))
        case_path.write_bytes(content)
        if failure != "hash":
            manifest["files"]["case.json"] = hashlib.sha256(content).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_saved_cve_case(tmp_path, TARGET, SCOPE)


@pytest.mark.parametrize("failure", ["json", "permission"])
def test_all_unreadable_candidates_return_explicit_discovery_failure(
    tmp_path, monkeypatch, failure
):
    names = ["assessment-synthetic-first", "assessment-synthetic-second"]
    for timestamp, name in enumerate(names, start=1700000000):
        directory = write_capture(tmp_path, name, timestamp)
        path = directory / "manifest.json"
        if failure == "json":
            path.write_text("{", encoding="utf-8")
    if failure == "permission":
        original = Path.open

        def open_file(path, *args, **kwargs):
            if path.name == "manifest.json":
                raise PermissionError("synthetic discovery read failure")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", open_file)

    with pytest.raises(ConfigError, match="No verified saved CVE capture") as caught:
        load_saved_cve_case(tmp_path, TARGET, SCOPE)

    assert "unreadable or malformed" in str(caught.value)
    assert all(name in str(caught.value) for name in names)


@pytest.mark.parametrize("candidate", ["empty", "unrelated", "without-cves"])
def test_no_matching_verified_cve_capture_returns_explicit_failure(tmp_path, candidate):
    if candidate == "unrelated":
        write_capture(tmp_path, "assessment-synthetic-other", 1700000000, target="unrelated")
    elif candidate == "without-cves":
        write_capture(
            tmp_path,
            "assessment-synthetic-no-cves",
            1700000000,
            payload={"hosts": [{"ip": ADDRESS}], "findings": []},
        )

    with pytest.raises(
        ConfigError, match="No verified saved CVE capture exists for this exact target"
    ):
        load_saved_cve_case(tmp_path, TARGET, SCOPE)
