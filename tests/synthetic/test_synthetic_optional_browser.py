"""Optional browser tooling must not become a core gate dependency."""

import argparse
import sys
from types import ModuleType
from unittest.mock import Mock

import pytest

from scripts import verify_capture_history_ui as smoke


@pytest.mark.parametrize("missing", ["playwright", "playwright.sync_api"])
def test_missing_optional_browser_is_explicit_and_fail_closed(monkeypatch, capsys, missing):
    importer = Mock(side_effect=ModuleNotFoundError("synthetic missing package", name=missing))
    monkeypatch.setattr(smoke, "import_module", importer)
    with pytest.raises(SystemExit) as result:
        smoke.load_browser_api(argparse.ArgumentParser())
    assert result.value.code == 2
    assert "MISSING optional browser prerequisite: playwright.sync_api" in capsys.readouterr().err
    importer.assert_called_once_with("playwright.sync_api")


def test_broken_transitive_import_is_not_disguised_as_missing_playwright(monkeypatch):
    error = ModuleNotFoundError("synthetic broken installation", name="other_dependency")
    monkeypatch.setattr(smoke, "import_module", Mock(side_effect=error))
    with pytest.raises(ModuleNotFoundError) as result:
        smoke.load_browser_api(argparse.ArgumentParser())
    assert result.value is error


def test_existing_optional_browser_api_is_returned_without_launch(monkeypatch):
    api = ModuleType("synthetic_browser_api")
    importer = Mock(return_value=api)
    monkeypatch.setattr(smoke, "import_module", importer)
    assert smoke.load_browser_api(argparse.ArgumentParser()) is api
    importer.assert_called_once_with("playwright.sync_api")


@pytest.mark.parametrize(
    ("arguments", "exit_code"),
    [(["--help"], 0), (["https://example.com", "synthetic-output"], 2)],
)
def test_help_and_invalid_origin_never_load_browser(monkeypatch, arguments, exit_code):
    importer = Mock(side_effect=AssertionError("browser must not be loaded"))
    monkeypatch.setattr(smoke, "import_module", importer)
    monkeypatch.setattr(sys, "argv", ["verify_capture_history_ui.py", *arguments])
    with pytest.raises(SystemExit) as result:
        smoke.main()
    assert result.value.code == exit_code
    importer.assert_not_called()
