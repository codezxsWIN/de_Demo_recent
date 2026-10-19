"""Offline export fails explicitly when source assets or destination are invalid."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vulnassess.errors import ConfigError
from vulnassess.ui import export


@pytest.fixture
def application(tmp_path):
    return SimpleNamespace(
        run_id="synthetic",
        config_dir=tmp_path / "config",
        get=Mock(
            return_value=SimpleNamespace(
                status=200,
                body=b'<html><head></head><body><script id="assessment-data" type="application/json">{}</script></body></html>',
            )
        ),
        cvss_fixture=lambda: {},
    )


@pytest.mark.parametrize(
    "mode,message",
    [
        ("no-run", "requires --run"),
        ("extension", ".html output path"),
        ("config", "must not overwrite"),
        ("http-error", "cannot read run"),
        ("missing-bootstrap", "missing the assessment-data"),
    ],
)
def test_export_preconditions_leave_destination_untouched(tmp_path, application, mode, message):
    destination = tmp_path / "report.html"
    if mode == "no-run":
        application.run_id = None
    elif mode == "extension":
        destination = tmp_path / "report.txt"
    elif mode == "config":
        destination = application.config_dir / "report.html"
    elif mode == "http-error":
        application.get.return_value.status = 404
    else:
        application.get.return_value.body = b"<html></html>"
    with pytest.raises(ConfigError, match=message):
        export.export_html(application, destination)
    assert not destination.exists()


@pytest.mark.parametrize(
    "mode,message",
    [
        ("missing-style", "MISSING: UI asset"),
        ("bad-style", "cannot read UI asset"),
        ("missing-artwork", "MISSING: UI artwork"),
        ("bad-artwork", "cannot read UI artwork"),
        ("bad-font", "cannot read UI font"),
        ("missing-import", "known local cobe-globe.js"),
        ("bad-vendor", "known local Cobe module exports"),
        ("write-denied", "cannot write UI export"),
    ],
)
def test_asset_failures_are_not_export_success(tmp_path, application, monkeypatch, mode, message):
    destination = tmp_path / "report.html"
    original_file = Path.is_file
    original_read = Path.read_text
    original_bytes = Path.read_bytes
    original_write = Path.write_text

    def is_file(path):
        if (mode == "missing-style" and path.name == "tokens.css") or (
            mode == "missing-artwork" and path.name == "project-horizon.png"
        ):
            return False
        return original_file(path)

    def read_text(path, *args, **kwargs):
        if mode == "bad-style" and path.name == "tokens.css":
            raise PermissionError("synthetic")
        if mode == "missing-import" and path.name == "app.js":
            return ""
        if mode == "bad-vendor" and path.name == "cobe.js":
            return "// no exports"
        return original_read(path, *args, **kwargs)

    def read_bytes(path):
        if (mode == "bad-artwork" and path.name == "project-horizon.png") or (
            mode == "bad-font" and path.suffix == ".woff2"
        ):
            raise PermissionError("synthetic")
        return original_bytes(path)

    def write_text(path, *args, **kwargs):
        if mode == "write-denied" and path == destination:
            raise PermissionError("synthetic")
        return original_write(path, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", is_file)
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(Path, "write_text", write_text)
    with pytest.raises(ConfigError, match=message):
        export.export_html(application, destination)
    assert not destination.exists()
