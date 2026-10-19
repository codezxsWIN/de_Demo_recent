"""A replay remains scope-gated and rejects malformed captures before use."""

import hashlib
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_saved_cve_case import load, saved
from vulnassess.errors import ConfigError
from vulnassess.saved_cve_case import refresh_saved_case


@pytest.mark.parametrize(
    "mode,message",
    [
        ("missing-manifest", "No verified saved CVE"),
        ("wrong-target", "No verified saved CVE"),
        ("empty-files", "Invalid saved capture manifest"),
        ("bad-filename", "Invalid saved evidence filename"),
        ("different-host", "contains a different target"),
        ("no-cves", "No verified saved CVE"),
        ("bad-json", "unreadable or malformed"),
        ("large-file", "replay budget"),
    ],
)
def test_saved_capture_replay_rejects_invalid_inputs(tmp_path, mode, message):
    directory = saved(tmp_path)
    path = directory / "manifest.json"
    manifest = json.loads(path.read_text())
    if mode == "missing-manifest":
        path.unlink()
    elif mode == "wrong-target":
        manifest["target"] = "different"
    elif mode == "empty-files":
        manifest["files"] = {}
    elif mode == "bad-filename":
        manifest["files"]["../case.json"] = "x"
    elif mode in ("different-host", "no-cves"):
        payload = json.loads((directory / "case.json").read_text())
        if mode == "different-host":
            payload["hosts"][0]["ip"] = "192.0.2.99"
        else:
            payload["findings"] = []
        raw = json.dumps(payload).encode()
        (directory / "case.json").write_bytes(raw)
        manifest["files"]["case.json"] = hashlib.sha256(raw).hexdigest()
    elif mode == "large-file":
        (directory / "case.json").write_bytes(b"x" * (8 * 1024 * 1024 + 1))
    if mode != "missing-manifest":
        path.write_text("{" if mode == "bad-json" else json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load(tmp_path)


def test_refresh_rechecks_scope_before_accessing_payload_or_publishers(tmp_path):
    settings = SimpleNamespace(scope=SimpleNamespace(contains=lambda _: False))
    progress = Mock()
    with pytest.raises(ConfigError, match="outside the current authorized scope"):
        refresh_saved_case({}, "192.0.2.99", settings, tmp_path / "unused.db", progress)
    progress.assert_not_called()
    assert not (tmp_path / "intel-cache.db").exists()
