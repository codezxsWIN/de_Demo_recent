"""Adversarial scanner-input boundary tests."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess.errors import AdapterError
from vulnassess.readers import _input, parse_nikto_json, parse_nmap_xml, parse_zap_json


class TestReaderSecurity(unittest.TestCase):
    def test_network_share_is_rejected_before_file_access(self):
        with self.assertRaises(AdapterError) as caught:
            _input.read_capture(r"\\server\share\synthetic_nmap.xml", "nmap")

        self.assertIn("network-share", str(caught.exception))

    def test_capture_size_limit_is_enforced_before_reading(self):
        original = _input.MAX_CAPTURE_BYTES
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic_oversized.json"
            path.write_bytes(b"x" * 17)
            _input.MAX_CAPTURE_BYTES = 16
            try:
                with self.assertRaises(AdapterError) as caught:
                    _input.read_capture(path, "zap")
            finally:
                _input.MAX_CAPTURE_BYTES = original

        self.assertIn("maximum is 16", str(caught.exception))

    def test_xml_entity_declarations_are_forbidden(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic_entity.xml"
            path.write_text(
                '<!DOCTYPE nmaprun [<!ENTITY x "expanded">]><nmaprun>&x;</nmaprun>',
                encoding="utf-8",
            )

            with self.assertRaises(AdapterError) as caught:
                parse_nmap_xml(path, "synthetic")

        self.assertIn("entity declarations are forbidden", str(caught.exception))

    def test_doctype_internal_subsets_are_forbidden_even_without_entities(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic_subset.xml"
            path.write_text(
                '<!DOCTYPE nmaprun [<!NOTATION x SYSTEM "y">]><nmaprun/>',
                encoding="utf-8",
            )

            with self.assertRaises(AdapterError) as caught:
                parse_nmap_xml(path, "synthetic")

        self.assertIn("DTD internal subsets are forbidden", str(caught.exception))

    def test_real_nmap_doctype_header_is_accepted(self):
        """Real Nmap writes a bare <!DOCTYPE nmaprun>; the reader must not reject it."""
        with TemporaryDirectory() as directory:
            path = Path(directory) / "real_header.xml"
            path.write_text(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                "<!DOCTYPE nmaprun>\n"
                '<nmaprun scanner="nmap" start="1"><host>'
                '<status state="up"/><address addr="172.28.0.12" addrtype="ipv4"/>'
                "</host></nmaprun>",
                encoding="utf-8",
            )
            parse_nmap_xml(path, "synthetic")

    def test_excessive_xml_depth_is_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic_deep.xml"
            depth = _input.MAX_DEPTH + 1
            path.write_text(
                '<nmaprun scanner="nmap" start="1">'
                + "<node>" * depth
                + "</node>" * depth
                + "</nmaprun>",
                encoding="utf-8",
            )

            with self.assertRaises(AdapterError) as caught:
                parse_nmap_xml(path, "synthetic")

        self.assertIn("exceeds depth", str(caught.exception))

    def test_duplicate_json_keys_are_rejected_for_every_json_reader(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic_duplicate.json"
            path.write_text('{"site": [], "site": []}', encoding="utf-8")

            for reader in (parse_zap_json, parse_nikto_json):
                with (
                    self.subTest(reader=reader.__name__),
                    self.assertRaises(AdapterError) as caught,
                ):
                    reader(path, "synthetic")
                self.assertIn("duplicate JSON key", str(caught.exception))

    def test_non_finite_json_values_are_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic_nan.json"
            path.write_text('{"site": [], "score": NaN}', encoding="utf-8")

            with self.assertRaises(AdapterError) as caught:
                parse_zap_json(path, "synthetic")

        self.assertIn("non-finite JSON value", str(caught.exception))

    def test_excessive_json_depth_is_rejected(self):
        payload = {"leaf": True}
        for _ in range(_input.MAX_DEPTH + 1):
            payload = {"nested": payload}
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic_deep.json"
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(AdapterError) as caught:
                _input.load_json_capture(path, "zap")

        self.assertIn("exceeds depth", str(caught.exception))

    def test_empty_capture_is_not_an_empty_success(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic_empty.xml"
            path.write_bytes(b"")

            with self.assertRaises(AdapterError) as caught:
                parse_nmap_xml(path, "synthetic")

        self.assertIn("empty", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
