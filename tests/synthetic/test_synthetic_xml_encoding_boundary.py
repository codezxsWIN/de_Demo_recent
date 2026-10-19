"""Encoding-independent rejection of synthetic XML declarations before tree parsing."""

from types import SimpleNamespace
from unittest.mock import Mock
from xml.etree import ElementTree as ET

import pytest

from vulnassess.errors import AdapterError
from vulnassess.readers import _input, nessus_xml, nmap_xml, parse_nessus_xml, parse_nmap_xml


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize(
    "reader,root", [(parse_nmap_xml, "nmaprun"), (parse_nessus_xml, "NessusClientData_v2")]
)
def test_encoded_entities_are_rejected_before_tree_construction(
    tmp_path, monkeypatch, encoding, reader, root
):
    declaration = "UTF-8" if encoding == "utf-8" else "UTF-16"
    document = (
        f'<?xml version="1.0" encoding="{declaration}"?>'
        f'<!DOCTYPE {root} [<!ENTITY banner "synthetic-expanded">]>'
        f"<{root}>&banner;</{root}>"
    )
    path = tmp_path / "synthetic_encoded_entity.xml"
    path.write_bytes(document.encode(encoding))
    build_tree = Mock(side_effect=AssertionError("untrusted declarations reached tree parser"))
    monkeypatch.setattr("xml.etree.ElementTree.fromstring", build_tree)

    with pytest.raises(AdapterError, match="forbidden"):
        reader(path, "synthetic")

    build_tree.assert_not_called()


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
def test_encoded_internal_subset_without_entities_is_rejected(tmp_path, encoding):
    document = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE nmaprun [<!NOTATION x SYSTEM "synthetic">]><nmaprun/>'
    path = tmp_path / "synthetic_encoded_subset.xml"
    path.write_bytes(document.encode(encoding))

    with pytest.raises(AdapterError, match="DTD internal subsets are forbidden"):
        parse_nmap_xml(path, "synthetic")


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
def test_benign_encoded_nmap_preserves_observed_text(tmp_path, encoding):
    declaration = "UTF-8" if encoding == "utf-8" else "UTF-16"
    document = (
        f'<?xml version="1.0" encoding="{declaration}"?><!DOCTYPE nmaprun>'
        '<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="synthetic café"/></port></ports></host></nmaprun>'
    )
    path = tmp_path / "synthetic_benign_encoded.xml"
    path.write_bytes(document.encode(encoding))

    hosts, findings = parse_nmap_xml(path, "synthetic")

    assert hosts[0].services[0].product == "synthetic café"
    assert findings == []


def test_capture_growth_after_stat_cannot_cross_read_limit(tmp_path, monkeypatch):
    path = tmp_path / "synthetic_growing.json"
    path.write_bytes(b"x" * 17)
    monkeypatch.setattr(_input, "MAX_CAPTURE_BYTES", 16)
    real_stat = path.stat()
    monkeypatch.setattr(
        type(path),
        "stat",
        lambda *_args, **_kwargs: SimpleNamespace(st_mode=real_stat.st_mode, st_size=1),
    )

    with pytest.raises(AdapterError, match="maximum is 16"):
        _input.read_capture(path, "nikto")


@pytest.mark.parametrize(
    "document,setting,limit",
    [
        ("<nmaprun><host/><host/></nmaprun>", "MAX_NODES", 2),
        ("<nmaprun><host><ports/></host></nmaprun>", "MAX_DEPTH", 2),
    ],
)
def test_xml_complexity_is_rejected_before_tree_allocation(
    tmp_path, monkeypatch, document, setting, limit
):
    path = tmp_path / "synthetic_complex.xml"
    path.write_text(document, encoding="utf-8")
    monkeypatch.setattr(_input, setting, limit)
    build_tree = Mock(side_effect=AssertionError("oversized XML reached tree construction"))
    monkeypatch.setattr("xml.etree.ElementTree.fromstring", build_tree)

    with pytest.raises(AdapterError, match="exceeds"):
        parse_nmap_xml(path, "synthetic")

    build_tree.assert_not_called()


def test_unsupported_xml_encoding_has_a_bounded_adapter_error(tmp_path):
    path = tmp_path / "synthetic_unknown_encoding.xml"
    path.write_bytes(b'<?xml version="1.0" encoding="unrecognised-encoding"?><nmaprun/>')

    with pytest.raises(AdapterError, match="XML"):
        parse_nmap_xml(path, "synthetic")


def test_external_doctype_identifier_is_not_fetched(tmp_path):
    path = tmp_path / "synthetic_external_identifier.xml"
    path.write_text(
        '<!DOCTYPE nmaprun SYSTEM "https://synthetic.invalid/nmap.dtd"><nmaprun/>', encoding="utf-8"
    )

    assert parse_nmap_xml(path, "synthetic") == ([], [])


@pytest.mark.parametrize(
    "parser,document,reason",
    [
        (nmap_xml.parse_nmap_xml, "<nmaprun/>", "not parsable XML"),
        (
            nessus_xml.parse_nessus_xml,
            '<NessusClientData_v2><Report><ReportHost name="192.0.2.1"/></Report></NessusClientData_v2>',
            "not valid report XML",
        ),
    ],
)
def test_xml_tree_parser_failure_is_normalized_to_adapter_error(
    tmp_path, monkeypatch, parser, document, reason
):
    path = tmp_path / "synthetic_tree_parser_failure.xml"
    path.write_text(document, encoding="utf-8")
    monkeypatch.setattr(
        ET, "fromstring", Mock(side_effect=ET.ParseError("synthetic parser refusal"))
    )

    with pytest.raises(AdapterError, match=reason):
        parser(path, "synthetic")
