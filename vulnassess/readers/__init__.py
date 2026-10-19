"""Scanner output readers. Each turns one tool's file into canonical records."""

from vulnassess.readers.nessus_xml import parse_nessus_xml
from vulnassess.readers.nikto_json import parse_nikto_json
from vulnassess.readers.nmap_xml import parse_nmap_xml
from vulnassess.readers.zap_json import parse_zap_json

READERS = {
    "nmap": parse_nmap_xml,
    "nikto": parse_nikto_json,
    "nessus": parse_nessus_xml,
    "zap": parse_zap_json,
}

__all__ = ["READERS", "parse_nmap_xml", "parse_nikto_json", "parse_nessus_xml", "parse_zap_json"]
