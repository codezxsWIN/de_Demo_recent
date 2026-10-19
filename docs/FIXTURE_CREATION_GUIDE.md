# VulnAssess Fixture Creation & Testing Guide

Quick reference for creating and testing scan data fixtures for the vulnassess project.

---

## QUICK START: Creating a Minimal Fixture

### 1. Create Nmap XML Fixture

**File:** `tests/fixtures/nmap/example.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1757116800" version="7.94">
  <host starttime="1757116800" endtime="1757116860">
    <status state="up" reason="arp-response"/>
    <address addr="172.28.0.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="target.lab" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="7.4" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.49" method="probed" conf="10">
          <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
        </service>
        <script id="vulners" output="CVE-1999-9001 9.8 https://vulners.com/cve/CVE-1999-9001"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.15 - Ubuntu 22.04" accuracy="96"/>
    </os>
  </host>
  <runstats>
    <finished time="1757116860" exit="success" elapsed="60.00"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
```

**Expected parser output:**
- 1 Host: 172.28.0.10 with 2 services (SSH, HTTP)
- 1 Finding: CVE-1999-9001 on port 80

---

### 2. Create ZAP JSON Fixture

**File:** `tests/fixtures/zap/example.json`

```json
{
  "@programName": "ZAP",
  "@version": "2.15.0",
  "@generated": "Fri, 5 Sep 2026 00:00:00",
  "site": [
    {
      "@name": "http://172.28.0.11",
      "@host": "172.28.0.11",
      "@port": "80",
      "@ssl": "false",
      "alerts": [
        {
          "pluginid": "10020",
          "alertRef": "10020-1",
          "alert": "Missing Anti-clickjacking Header",
          "name": "Missing Anti-clickjacking Header",
          "riskcode": "2",
          "confidence": "2",
          "riskdesc": "Medium (Medium)",
          "desc": "<p>The response does not protect against ClickJacking attacks.</p>",
          "solution": "<p>Send a Content-Security-Policy frame-ancestors directive.</p>",
          "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options</p>",
          "cweid": "1021",
          "wascid": "15",
          "instances": [
            {
              "uri": "http://172.28.0.11/",
              "method": "GET",
              "param": "x-frame-options",
              "evidence": ""
            }
          ]
        }
      ]
    }
  ]
}
```

**Expected parser output:**
- 1 Finding: Missing X-Frame-Options on HTTP GET /
- Severity: Medium, Confidence: Medium
- CWE-1021

---

### 3. Create Nikto JSON Fixture

**File:** `tests/fixtures/nikto/example.json`

```json
{
  "host": "172.28.0.11",
  "ip": "172.28.0.11",
  "port": "80",
  "banner": "Apache/2.4.49 (Ubuntu)",
  "vulnerabilities": [
    {
      "id": "999957",
      "method": "GET",
      "url": "/",
      "msg": "The anti-clickjacking X-Frame-Options header is not present.",
      "references": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    }
  ]
}
```

**Expected parser output:**
- 1 Finding: X-Frame-Options header not present
- No severity/confidence (Nikto has none)
- No CVE (unless in msg/references)

---

## Adding Provenance Record

After creating fixture files, update the README.md:

**File:** `tests/fixtures/nmap/README.md`

```markdown
# Real Nmap captures

## example.xml

- Capture date/time (UTC): 2026-01-06T00:00:00Z
- Captured by: Test Engineer
- Target: 172.28.0.10 (target.lab)
- Tool and version: Nmap 7.94
- Command: `nmap -sV -O --script vulners -oX tests/fixtures/nmap/example.xml 172.28.0.10`
- Exit code and completion state: 0 (success)
- Vantage: Local lab network
- Scope/configuration reference: config/scope.yaml (in-scope lab targets)
- Raw artifact SHA-256: `<sha256sum of file>`
- Network fence and canary evidence: Lab firewall rules block external; 172.28.0.250 unreachable
- Coverage limits: TCP port-specific scan; no UDP; no aggressive OS detection
- Redactions/transformations: None
- Original artifact location: N/A

| File | Capture date | Command | Target | Tool version | Captured by |
| --- | --- | --- | --- | --- | --- |
| example.xml | 2026-01-06 | `nmap -sV -O --script vulners -oX ...` | 172.28.0.10 | 7.94 | Test Engineer |
```

---

## Test Structure

### Unit Test (Synthetic Data)

```python
# tests/test_parse_nmap.py
import pytest
from pathlib import Path
from vulnassess.readers import parse_nmap_xml


@pytest.fixture
def minimal_nmap_xml(tmp_path: Path) -> Path:
    """Synthetic minimal Nmap XML for unit testing."""
    path = tmp_path / "minimal.xml"
    path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" start="1757116800" version="7.94">
  <host starttime="1757116800" endtime="1757116860">
    <status state="up" reason="arp-response"/>
    <address addr="172.28.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
    </ports>
  </host>
  <runstats><finished time="1757116860" exit="success"/></runstats>
</nmaprun>
""",
        encoding="utf-8",
    )
    return path


def test_parse_minimal_nmap(minimal_nmap_xml: Path) -> None:
    """Test parsing minimal Nmap XML with one service."""
    hosts, findings = parse_nmap_xml(minimal_nmap_xml, "unit-test")

    assert len(hosts) == 1
    host = hosts[0]
    assert host.ip == "172.28.0.10"
    assert len(host.services) == 1
    assert host.services[0].port == 22
    assert host.services[0].name == "ssh"

    assert len(findings) == 0  # No CVEs found (no vulners script)
```

### Integration Test (Real Fixture)

```python
# tests/test_nmap_real_capture.py
import pytest
from pathlib import Path
from vulnassess.readers import parse_nmap_xml

needs_fixture = pytest.mark.needs_fixture


@needs_fixture(
    "tests/fixtures/nmap/example.xml",
    "tests/fixtures/nmap/README.md",
)
def test_parse_real_nmap_capture() -> None:
    """Test parsing real Nmap capture with provenance verification."""
    path = Path("tests/fixtures/nmap/example.xml")
    hosts, findings = parse_nmap_xml(path, "integration-test")

    # Verify host extraction
    assert len(hosts) >= 1, "Real capture must have at least one up host"
    assert all(host.ip for host in hosts), "Every host must have IP"

    # Verify finding extraction
    for finding in findings:
        assert finding.evidence, "Every finding must have verbatim evidence"
        assert len(finding.evidence) <= 2048, "Evidence must be <= 2048 chars"
        assert finding.tool == "nmap"
        assert finding.provenance.run_id == "integration-test"
        assert finding.provenance.raw_path == str(path)

    # Verify against golden snapshot
    snapshot_path = Path("tests/golden/nmap/example.json")
    if snapshot_path.exists():
        import json

        expected = json.loads(snapshot_path.read_text())
        actual = {
            "hosts": [h.to_json() for h in hosts],
            "findings": [f.to_json() for f in findings],
        }
        assert actual == expected
```

---

## Common Patterns

### Handling Multiple Findings in Nmap

```xml
<!-- Multiple script outputs with different CVEs -->
<port protocol="tcp" portid="80">
  <state state="open" reason="syn-ack"/>
  <service name="http" product="Apache httpd" version="2.4.49"/>
  <script id="vulners" output="
    cpe:/a:apache:http_server:2.4.49:
      CVE-1999-9001 9.8 https://vulners.com/cve/CVE-1999-9001
      CVE-1999-9002 8.5 https://vulners.com/cve/CVE-1999-9002
  "/>
</port>
```
**Result:** 2 findings (one per CVE)

### Handling Multiple Instances in ZAP

```json
{
  "pluginid": "10020",
  "name": "Missing Header",
  "riskcode": "2",
  "confidence": "2",
  "cweid": "1021",
  "instances": [
    {"uri": "http://172.28.0.11/", "param": "x-frame-options"},
    {"uri": "http://172.28.0.11/index.php", "param": "x-frame-options"},
    {"uri": "http://172.28.0.11/contact.php", "param": "x-frame-options"}
  ]
}
```
**Result:** 3 findings (one per instance)

### CVE Extraction in Nikto

```json
{
  "id": "600523",
  "url": "/",
  "msg": "Apache/2.4.49 appears vulnerable to CVE-1999-9001 and CVE-1999-9002.",
  "references": "https://httpd.apache.org/security/ CVE-1999-9001 CVE-1999-9002"
}
```
**Result:** Finding with `cve_ids=("CVE-1999-9001", "CVE-1999-9002")`

---

## Validation Checklist

### Before Committing Nmap Fixture

- [ ] File is valid XML (can parse with `xml.etree.ElementTree`)
- [ ] Root element is `<nmaprun>`
- [ ] Contains at least one `<host>` with `status[@state]="up"`
- [ ] Contains at least one IPv4 `<address>`
- [ ] `start` and version attributes present
- [ ] No DOCTYPE or ENTITY declarations
- [ ] File size < 16 MB
- [ ] Updated `tests/fixtures/nmap/README.md` with provenance row
- [ ] Raw file SHA-256 calculated and recorded
- [ ] No credentials, session tokens, or production identifiers
- [ ] Captured with written authorization for the target
- [ ] Target is in scope (config/scope.yaml)

### Before Committing ZAP Fixture

- [ ] File is valid JSON
- [ ] Root is object with `"site"` array
- [ ] Each site has `"@name"` or `"@host"` (parseable to IP)
- [ ] Each alert has required fields: `pluginid`, `name`, `riskcode`, `confidence`
- [ ] `cweid` values are valid (or empty, "-1", "0")
- [ ] `instances` array properly formatted (or omitted)
- [ ] No duplicate JSON keys
- [ ] File size < 16 MB
- [ ] Updated `tests/fixtures/zap/README.md` with provenance row
- [ ] No credentials, session tokens, or cookies in `instances[].uri`
- [ ] Captured with written authorization
- [ ] Target is in scope and HTTP endpoints verified

### Before Committing Nikto Fixture

- [ ] File is valid JSON
- [ ] Contains `"vulnerabilities"` array
- [ ] Has `"ip"` or `"host"` field
- [ ] Each vulnerability has `"msg"` and `"id"` or `"OSVDB"`
- [ ] No duplicate JSON keys
- [ ] File size < 16 MB
- [ ] Updated `tests/fixtures/nikto/README.md` with provenance row
- [ ] Target is in scope with written authorization

---

## Running Fixture Tests

### Run All Tests (Skip Missing Fixtures)

```bash
pytest tests/ -v
# Tests marked with @needs_fixture skip if files missing
# Tests with malformed files still fail normally
```

### Run Only Fixture Tests

```bash
pytest tests/test_nmap_real_capture.py -v
pytest tests/test_zap_real_capture.py -v
pytest tests/test_nikto_real_capture.py -v
```

### Run Synthetic Tests Only

```bash
pytest tests/test_assessment_snapshot.py -v
pytest tests/test_experiments.py -v
# These use synthetic_*.xml and synthetic_*.json from tests/synthetic/
```

### Update Golden Snapshots

After parser changes, regenerate golden files:

```bash
# Regenerate single golden file
python -m pytest tests/test_nmap_real_capture.py::test_parse_real_nmap_capture \
  --snapshot-update

# Or manually:
python -c """
from pathlib import Path
from vulnassess.readers import parse_nmap_xml
import json

path = Path('tests/fixtures/nmap/example.xml')
hosts, findings = parse_nmap_xml(path, 'snapshot-gen')
snapshot = {
    'hosts': [h.to_json() for h in hosts],
    'findings': [f.to_json() for f in findings],
}
Path('tests/golden/nmap/example.json').write_text(json.dumps(snapshot, indent=2))
"""
```

---

## File Size Troubleshooting

### Check Actual File Sizes

```bash
# PowerShell
Get-Item tests/fixtures/nmap/*.xml | Select-Object Name, @{l="Size MB";e={$_.Length / 1MB}}

# Linux/macOS
du -h tests/fixtures/nmap/*.xml
```

### Compress Large Real Captures

```bash
# For private archive (never commit compressed to repo)
gzip -c tests/fixtures/nmap/large.xml > large.xml.gz

# Decompress before running tests
gunzip -c large.xml.gz > tests/fixtures/nmap/large.xml
```

### Split Very Large Captures

If a single target produces massive output:
1. Run Nmap on smaller port subset
2. Create separate fixtures per target
3. Document port limitation in README.md

---

## Schema Validation

### Quick Validation Script

```python
# validate_fixture.py
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def validate_nmap(path: Path) -> bool:
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        assert root.tag == "nmaprun"
        assert any(
            h.find("status") is not None and h.find("status").get("state") == "up"
            for h in root.findall("host")
        )
        print(f"✓ Valid Nmap XML: {path}")
        return True
    except Exception as e:
        print(f"✗ Invalid Nmap XML: {path}\n  {e}")
        return False


def validate_zap(path: Path) -> bool:
    try:
        data = json.loads(path.read_text())
        assert isinstance(data, dict)
        assert "site" in data and isinstance(data["site"], list)
        assert len(data["site"]) > 0
        assert all("@name" in s or "@host" in s for s in data["site"])
        print(f"✓ Valid ZAP JSON: {path}")
        return True
    except Exception as e:
        print(f"✗ Invalid ZAP JSON: {path}\n  {e}")
        return False


def validate_nikto(path: Path) -> bool:
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            reports = data
        else:
            reports = [data]
        assert any("vulnerabilities" in r for r in reports)
        assert all("ip" in r or "host" in r for r in reports if "vulnerabilities" in r)
        print(f"✓ Valid Nikto JSON: {path}")
        return True
    except Exception as e:
        print(f"✗ Invalid Nikto JSON: {path}\n  {e}")
        return False


# Run validation
for xml in Path("tests/fixtures/nmap").glob("*.xml"):
    validate_nmap(xml)

for json_file in Path("tests/fixtures/zap").glob("*.json"):
    validate_zap(json_file)

for json_file in Path("tests/fixtures/nikto").glob("*.json"):
    validate_nikto(json_file)
```

---

## Reference Fixtures

### Pre-built Synthetic Examples

Located in `tests/synthetic/`:
- `synthetic_nmap_two_machines.xml` - Two hosts with CVEs and OS detection
- `synthetic_nmap_ssh_only.xml` - Minimal (one host, SSH port only)
- `synthetic_zap_dvwa.json` - DVWA target with multiple alerts
- `synthetic_nikto_dvwa.json` - DVWA with three findings (including CVE)

**Use these as templates** for creating new fixtures.

### Golden Snapshots

Located in `tests/golden/`:
- `tests/golden/nmap/*.json` - Expected parser output for Nmap captures
- `tests/golden/zap/*.json` - Expected parser output for ZAP reports

Generate after validating capture authenticity.

---

## FAQ

**Q: Can I use synthetic data in tests/fixtures/?**
A: No. `tests/fixtures/` is reserved for human-captured real scans with provenance. Synthetic data goes in `tests/synthetic/`.

**Q: What if I make a typo in the fixture?**
A: If the file is malformed, the parser raises `AdapterError` and the test fails normally (not skipped). Fix the fixture before re-running.

**Q: Can I commit a production scan output?**
A: No. Fixtures must come from an explicitly authorized lab target with written approval. Record the authorization and scope reference in README.md.

**Q: How do I handle credentials in captured output?**
A: Never commit credentials, tokens, or session cookies. If the capture contains them, redact before committing and document the redaction in README.md provenance record.

**Q: Should I commit .xml.gz or only .xml?**
A: Commit only decompressed `.xml` and `.json` files. Compressed versions are for private archive use.

**Q: How large can a fixture be?**
A: Maximum 16 MB (enforced by parser). Typical Nmap scan is <1 MB, ZAP report is 0.5-5 MB.

---

**Last updated:** 2026-09-07
