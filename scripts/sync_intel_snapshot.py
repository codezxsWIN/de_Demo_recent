"""Download and validate four public vulnerability-intelligence snapshots.
Intended for the GitHub Actions snapshot workflow. Python standard library only.
"""
import csv
import gzip
import io
import json
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

OUT = Path("intel_snapshots")
OUT.mkdir(parents=True, exist_ok=True)

def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "VulnAssess-public-intel-snapshot/1.0"})
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read()

kev = json.loads(fetch("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"))
assert kev["count"] == len(kev["vulnerabilities"]) and kev["count"] > 1000
(OUT / "cisa_kev_catalog.json").write_text(json.dumps(kev, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

nvd = json.loads(fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0543"))
assert nvd["totalResults"] == 1 and nvd["vulnerabilities"][0]["cve"]["id"] == "CVE-2022-0543"
(OUT / "nvd_CVE-2022-0543.json").write_text(json.dumps(nvd, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

epss_bytes = gzip.decompress(fetch("https://epss.empiricalsecurity.com/epss_scores-2026-10-22.csv.gz"))
epss_text = epss_bytes.decode("utf-8-sig")
lines = [line for line in epss_text.splitlines() if not line.startswith("#")]
reader = csv.DictReader(io.StringIO("\n".join(lines)))
assert {"cve", "epss", "percentile"}.issubset(reader.fieldnames or [])
assert sum(1 for _ in reader) > 300000
(OUT / "epss_scores-2026-10-22.csv").write_bytes(epss_bytes)

archive = zipfile.ZipFile(io.BytesIO(fetch("https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip")))
xml_members = [name for name in archive.namelist() if name.lower().endswith(".xml")]
assert len(xml_members) == 1, xml_members
xml_bytes = archive.read(xml_members[0])
root = ET.fromstring(xml_bytes)
assert root.attrib.get("Version") == "4.20"
(OUT / "cwec_v4.20.xml").write_bytes(xml_bytes)
print("All four validated:", [p.name for p in OUT.iterdir()])
