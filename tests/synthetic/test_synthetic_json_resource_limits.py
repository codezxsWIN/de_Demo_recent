"""Synthetic local JSON boundaries for stage 7 and reproducible artifacts."""

import json
from pathlib import Path
from typing import Any, BinaryIO
from unittest.mock import MagicMock, Mock

import pytest

from vulnassess import audit
from vulnassess.errors import ConfigError


@pytest.mark.parametrize("change", ["grow", "replace"])
@pytest.mark.parametrize("padding", [b" ", b"\xff"], ids=["json-whitespace", "invalid-utf8"])
def test_actual_bytes_are_bounded_after_path_size_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str, padding: bytes
) -> None:
    cap = 16
    path = tmp_path / "synthetic_racing.json"
    replacement = tmp_path / "synthetic_replacement.json"
    path.write_bytes(b"{}")
    replacement.write_bytes(b"{}" + padding * 64)
    assert path.is_file() and replacement.is_file()
    assert path.stat().st_size < cap
    original_open = Path.open
    streams: list[BinaryIO] = []
    readers: list[MagicMock] = []
    loads = Mock(wraps=json.loads)

    def racing_open(candidate: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if candidate != path or mode != "rb":
            return original_open(candidate, mode, *args, **kwargs)
        # Mutation happens after the loader's size check, just before its open.
        if change == "grow":
            with original_open(path, "ab") as output:
                output.write(padding * 64)
        else:
            replacement.replace(path)
        stream = original_open(candidate, mode, *args, **kwargs)
        reader = MagicMock(wraps=stream)
        reader.__enter__.return_value = reader
        reader.__exit__.side_effect = stream.__exit__
        streams.append(stream)
        readers.append(reader)
        return reader

    with monkeypatch.context() as boundary:
        boundary.setattr(Path, "open", racing_open)
        boundary.setattr(audit.json, "loads", loads)
        with pytest.raises(ConfigError) as caught:
            audit.load_json_payload(path, "synthetic JSON", max_bytes=cap)

    assert str(caught.value) == f"synthetic JSON {path} exceeds {cap} bytes"
    assert len(readers) == 1
    readers[0].read.assert_called_once_with(cap + 1)
    assert streams[0].closed
    loads.assert_not_called()


@pytest.mark.parametrize("number", ["1e1000", "-1e1000", "NaN", "Infinity", "-Infinity"])
@pytest.mark.parametrize(
    "template",
    ["NUMBER", "[0,NUMBER,null]", '{"value":NUMBER}', '{"metadata":{"unknown":[{"x":NUMBER}]}}'],
    ids=["root", "array", "object", "uninterpreted-metadata"],
)
def test_nonfinite_numbers_are_rejected_everywhere(
    tmp_path: Path, number: str, template: str
) -> None:
    path = tmp_path / "synthetic_nonfinite.json"
    path.write_text(template.replace("NUMBER", number), encoding="utf-8")
    assert path.is_file()

    with pytest.raises(ConfigError) as caught:
        audit.load_json_payload(path, "synthetic JSON")

    assert str(caught.value).startswith(f"invalid synthetic JSON {path}: non-finite number ")


@pytest.mark.parametrize(
    "content",
    [
        b"1.7976931348623157e308",
        b"-1.7976931348623157e308",
        b"[1e-1000,-0.0,true,false,null]",
        b'{"metadata":{"unknown":[{"large":' + b"9" * 320 + b',"text":"1e1000"}]}}',
        '\ufeff{"metadata":{"unknown":["\u03bb",1.25]}}'.encode("utf-8"),
    ],
    ids=["largest-finite", "negative-finite", "array", "unknown-metadata", "utf8-bom"],
)
@pytest.mark.parametrize("spare_bytes", [0, 1])
def test_finite_payloads_and_unknown_metadata_survive_byte_boundary(
    tmp_path: Path, content: bytes, spare_bytes: int
) -> None:
    path = tmp_path / "synthetic_finite.json"
    path.write_bytes(content)
    assert path.is_file()
    expected = json.loads(content.decode("utf-8-sig"))

    payload = audit.load_json_payload(path, "synthetic JSON", max_bytes=len(content) + spare_bytes)

    assert payload == expected
    assert json.dumps(payload, allow_nan=False) == json.dumps(expected, allow_nan=False)


def test_known_oversize_is_rejected_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "synthetic_known_oversize.json"
    path.write_bytes(b"{} ")
    assert path.is_file()
    forbidden = Mock(side_effect=AssertionError("known oversized JSON must not be opened"))

    with monkeypatch.context() as boundary:
        boundary.setattr(Path, "open", forbidden)
        with pytest.raises(ConfigError) as caught:
            audit.load_json_payload(path, "synthetic JSON", max_bytes=2)

    assert str(caught.value) == f"synthetic JSON {path} exceeds 2 bytes"
    forbidden.assert_not_called()


@pytest.mark.parametrize("operation", ["open", "read"])
def test_descriptor_errors_remain_path_labelled_config_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    path = tmp_path / "synthetic_unreadable.json"
    path.write_bytes(b"{}")
    assert path.is_file()
    stream = MagicMock()
    stream.__enter__.return_value = stream
    denied = PermissionError("synthetic denied")
    opener = Mock(side_effect=denied) if operation == "open" else Mock(return_value=stream)
    stream.read.side_effect = denied

    with monkeypatch.context() as boundary:
        boundary.setattr(Path, "open", opener)
        with pytest.raises(ConfigError) as caught:
            audit.load_json_payload(path, "synthetic JSON", max_bytes=16)

    assert str(caught.value) == f"invalid synthetic JSON {path}: synthetic denied"
    assert caught.value.__cause__ is denied
    if operation == "read":
        stream.__exit__.assert_called_once()
