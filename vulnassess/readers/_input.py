"""Shared defensive capture loading for untrusted scanner files."""

import json
from pathlib import Path
from typing import Any
from xml.parsers import expat

from vulnassess.errors import AdapterError

MAX_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 128
MAX_NODES = 200_000


def read_capture(path: str | Path, tool: str) -> tuple[Path, bytes]:
    path = Path(path)
    rendered = str(path)
    if rendered.startswith("\\\\") or rendered.startswith("//"):
        raise AdapterError(f"{tool}: network-share capture paths are forbidden: {path}")
    if not path.is_file():
        raise AdapterError(f"{tool}: MISSING scan file {path}")
    try:
        size = path.stat().st_size
        if size > MAX_CAPTURE_BYTES:
            raise AdapterError(
                f"{tool}: capture {path} is {size} bytes; maximum is {MAX_CAPTURE_BYTES}"
            )
        with path.open("rb") as handle:
            content = handle.read(MAX_CAPTURE_BYTES + 1)
        if len(content) > MAX_CAPTURE_BYTES:
            raise AdapterError(
                f"{tool}: capture {path} exceeds size limit; maximum is {MAX_CAPTURE_BYTES}"
            )
    except AdapterError:
        raise
    except OSError as error:
        raise AdapterError(f"{tool}: {path} is unreadable ({error})") from error
    if not content:
        raise AdapterError(f"{tool}: capture {path} is empty")
    return path, content


def reject_xml_declarations(content: bytes, path: Path, tool: str) -> None:
    """Inspect decoded XML declarations before ElementTree can expand an entity.

    Expat recognizes XML encodings itself; byte regexes miss UTF-16 declarations.
    Bare Nmap DOCTYPEs remain supported, but external subsets are never loaded.
    """
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    nodes = depth = 0

    def reject_subset(_name: str, _system: str | None, _public: str | None, internal: int) -> None:
        if internal:
            raise AdapterError(
                f"{tool}: DTD internal subsets are forbidden; entity declarations are forbidden in {path}"
            )

    parser.StartDoctypeDeclHandler = reject_subset

    def start_element(_name: str, _attributes: dict[str, str]) -> None:
        nonlocal nodes, depth
        nodes += 1
        depth += 1
        if nodes > MAX_NODES:
            raise AdapterError(f"{tool}: XML in {path} exceeds {MAX_NODES} elements")
        if depth > MAX_DEPTH:
            raise AdapterError(f"{tool}: XML in {path} exceeds depth {MAX_DEPTH}")

    def end_element(_name: str) -> None:
        nonlocal depth
        depth -= 1

    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    try:
        parser.Parse(content, True)
    except (expat.ExpatError, LookupError, ValueError) as error:
        description = "not valid report XML" if tool == "nessus" else "not parsable XML"
        raise AdapterError(f"{tool}: {path} is {description} ({error})") from error


def validate_tree(root: Any, path: Path, tool: str) -> None:
    nodes = 0
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise AdapterError(f"{tool}: XML in {path} exceeds {MAX_NODES} elements")
        if depth > MAX_DEPTH:
            raise AdapterError(f"{tool}: XML in {path} exceeds depth {MAX_DEPTH}")
        stack.extend((child, depth + 1) for child in list(node))


def load_json_capture(path: str | Path, tool: str) -> tuple[Path, Any]:
    path, content = read_capture(path, tool)

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AdapterError(f"{tool}: duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise AdapterError(f"{tool}: non-finite JSON value {value!r} in {path}")

    try:
        payload = json.loads(
            content.decode("utf-8-sig"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except AdapterError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise AdapterError(f"{tool}: {path} is not valid bounded UTF-8 JSON ({error})") from error
    validate_json_shape(payload, path, tool)
    return path, payload


def validate_json_shape(payload: Any, path: Path, tool: str) -> None:
    nodes = 0
    stack = [(payload, 1)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise AdapterError(f"{tool}: JSON in {path} exceeds {MAX_NODES} values")
        if depth > MAX_DEPTH:
            raise AdapterError(f"{tool}: JSON in {path} exceeds depth {MAX_DEPTH}")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
