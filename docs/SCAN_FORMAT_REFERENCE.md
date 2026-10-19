# VulnAssess Scan Format Reference Guide

Complete technical reference for Nmap, ZAP, and Nikto scan data formats compatible with vulnassess.

---

## Quick Comparison

| Aspect | Nmap XML | ZAP JSON | Nikto JSON |
|--------|----------|----------|-----------|
| **Command** | `nmap -sV -O -oX out.xml` | `zap-baseline.py -t URL -J out.json` | `nikto -h host -Format json -output out.json` |
| **Root Element** | `<nmaprun>` | `{"site": [...]}` | `{..., "vulnerabilities": [...]}` |
| **Primary Data** | Hosts + Services + CVEs from scripts | Web app alerts with instances | Web server findings |
| **Data Output** | Host objects + Findings | Findings only | Findings only |
| **Native Severity** | None (None) | Yes (0-3: Info/Low/Med/High) | None (None) |
| **Native Confidence** | None (None) | Yes (0-4) | None (None) |
| **CVE Format** | Extracted from script output | No (uses CWE only) | Extracted from msg/refs |
| **Evidence** | Verbatim script output line | Alert desc/instance uri | Message text |
| **Max File Size** | 16 MB | 16 MB | 16 MB |

---

## 1. NMAP XML - DETAILED SCHEMA

### 1.1 Minimal Valid Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
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
  <runstats>
    <finished time="1757116860" exit="success"/>
  </runstats>
</nmaprun>
```

### 1.2 Full Example with CVE Findings

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -O --script vulners -oX -" start="1757116800" version="7.94">
  <host starttime="1757116800" endtime="1757116860">
    <status state="up" reason="arp-response"/>
    <address addr="172.28.0.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="target.lab" type="PTR"/>
    </hostnames>
    <ports>
      <!-- Open port with service info -->
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.49" method="probed" conf="10">
          <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
        </service>
        <!-- CVE extracted from vulners script output -->
        <script id="vulners" output="&#10;  cpe:/a:apache:http_server:2.4.49: &#10;    CVE-1999-9001  9.8  https://vulners.com/cve/CVE-1999-9001&#10;"/>
      </port>
      
      <!-- Closed port - ignored by parser -->
      <port protocol="tcp" portid="3306">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.15 - Ubuntu 22.04" accuracy="96"/>
    </os>
  </host>
  
  <!-- Down hosts are skipped -->
  <host>
    <status state="down" reason="no-response"/>
    <address addr="172.28.0.99" addrtype="ipv4"/>
  </host>
  
  <runstats>
    <finished time="1757116860" exit="success" elapsed="80.00"/>
    <hosts up="1" down="1" total="2"/>
  </runstats>
</nmaprun>
```

### 1.3 Element Breakdown

#### Root: `<nmaprun>`
- **Required attributes:**
  - `scanner="nmap"`
  - `start` (epoch timestamp as string)
  - `version` (e.g., "7.94")

#### Host Element: `<host>`
- **Attributes:**
  - `starttime` (epoch, optional; converted to ISO-8601)
  - `endtime` (epoch, optional; converted to ISO-8601)

- **Child Elements:**
  - `<status state="up|down" reason="..."/>` - Parser only includes hosts with `state="up"`
  - `<address addr="IP" addrtype="ipv4"/>` - Parser extracts first IPv4 address
  - `<hostnames><hostname name="hostname.lab" type="PTR"/></hostnames>` - Optional
  - `<ports><port>...</port></ports>` - Port details
  - `<os><osmatch name="Linux..." accuracy="96"/></os>` - Optional; uses highest accuracy match

#### Port Element: `<port>`
- **Required attributes:**
  - `protocol` (tcp, udp, etc.)
  - `portid` (port number as string; converted to int)

- **Child elements:**
  - `<state state="open|closed|..."/>` - Parser only includes ports with `state="open"`
  - `<service>` - Service detection details
  - `<script>` - NSE script output (where CVEs come from)

#### Service Element: `<service>`
- **Attributes (all optional):**
  - `name` - Service name (e.g., "ssh", "http")
  - `product` - Product name (e.g., "OpenSSH", "Apache httpd")
  - `version` - Version string
  - `extrainfo` - Additional info (e.g., "Ubuntu")
  - `method` - Detection method (probed, table, etc.)
  - `conf` - Confidence level
  - `tunnel` - ssl/tls if present

- **Child elements:**
  - `<cpe>cpe:/a:vendor:product:version</cpe>` - Optional CPE string

#### Script Element: `<script>`
- **Attributes:**
  - `id` - Script ID (e.g., "vulners", "http-server-header")
  - `output` - Raw script output (contains CVEs)

**CVE Extraction:** Parser regex matches `CVE-\d{4}-\d{4,}` in script output

### 1.4 Parser Output

**From Nmap XML, parser generates:**

1. **Host Objects** (one per `<host state="up">`)
   ```python
   Host(
       ip="172.28.0.10",
       hostname="target.lab",  # Optional
       os_guess="Linux 5.15 - Ubuntu 22.04",  # Optional
       services=(
           Service(port=80, protocol="tcp", name="http", product="Apache httpd", 
                   version="2.4.49", cpe="cpe:/a:apache:http_server:2.4.49", 
                   banner="80/tcp http Apache httpd 2.4.49", tls=False),
           Service(port=443, protocol="tcp", ..., tls=True),
       )
   )
   ```

2. **Finding Objects** (one per CVE in script output)
   ```python
   Finding(
       id="<UUID5 from fingerprint>",
       host_ip="172.28.0.10",
       port=80,
       protocol="tcp",
       url=None,
       tool="nmap",
       tool_native_id="vulners:CVE-1999-9001",
       title="vulners reports CVE-1999-9001 on http",
       description="<full script output>",
       evidence="CVE-1999-9001  9.8  https://vulners.com/cve/CVE-1999-9001",  # Exact line
       cve_ids=("CVE-1999-9001",),
       cwe_ids=(),
       reference_urls=(),
       native_severity=None,
       native_confidence=None,
       first_seen="2026-01-06T00:00:00+00:00",  # ISO-8601 from epoch
       last_seen="2026-01-06T00:00:00+00:00",
       provenance=Provenance(tool="nmap", raw_path="...", record_index=0, run_id="..."),
   )
   ```

### 1.5 Capture Command

**Recommended (non-destructive, version-light):**
```bash
nmap -n -Pn -sT -sV --version-light -T2 --max-retries 1 --host-timeout 180s \
  -p 21,22,23,25,53,80,88,110,135,139,143,389,443,445,465,587,636,993,995,1433,2049,3000,3306,5432,6379,8080,8443,27017 \
  -oX tests/fixtures/nmap/<target>.xml <authorised-ip>
```

**With CVE script (requires NSE scripts installed):**
```bash
nmap -sV -O --script vulners -oX out.xml <target>
```

**Note:** `-n` (no DNS), `-Pn` (no ping), `-sT` (TCP connect) ensures no UDP/ICMP scanning.

---

## 2. ZAP JSON - DETAILED SCHEMA

### 2.1 Minimal Valid Example

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
      "alerts": []
    }
  ]
}
```

### 2.2 Full Example with Alerts

```json
{
  "_comment": "OWASP ZAP baseline report",
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
          "solution": "<p>Send a Content-Security-Policy frame-ancestors directive or X-Frame-Options.</p>",
          "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options</p>",
          "cweid": "1021",
          "wascid": "15",
          "instances": [
            {
              "uri": "http://172.28.0.11/",
              "method": "GET",
              "param": "x-frame-options",
              "evidence": ""
            },
            {
              "uri": "http://172.28.0.11/index.php",
              "method": "GET",
              "param": "x-frame-options",
              "evidence": ""
            }
          ]
        },
        {
          "pluginid": "10038",
          "alertRef": "10038-1",
          "alert": "Content Security Policy (CSP) Header Not Set",
          "name": "Content Security Policy (CSP) Header Not Set",
          "riskcode": "2",
          "confidence": "3",
          "riskdesc": "Medium (High)",
          "desc": "<p>Content Security Policy (CSP) is an added layer of security.</p>",
          "solution": "<p>Configure the web server to emit a Content-Security-Policy header.</p>",
          "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP</p>",
          "cweid": "693",
          "wascid": "15",
          "instances": [
            {
              "uri": "http://172.28.0.11/",
              "method": "GET",
              "param": "",
              "evidence": ""
            }
          ]
        },
        {
          "pluginid": "10096",
          "alertRef": "10096-1",
          "alert": "Timestamp Disclosure - Unix",
          "name": "Timestamp Disclosure - Unix",
          "riskcode": "0",
          "confidence": "1",
          "riskdesc": "Informational (Low)",
          "desc": "<p>A Unix timestamp was disclosed by the application.</p>",
          "solution": "<p>Verify the timestamp is not sensitive information.</p>",
          "reference": "<p>https://cwe.mitre.org/data/definitions/200.html</p>",
          "cweid": "200",
          "wascid": "13",
          "instances": [
            {
              "uri": "http://172.28.0.11/style.css",
              "method": "GET",
              "param": "",
              "evidence": "1610000000"
            }
          ]
        }
      ]
    }
  ]
}
```

### 2.3 Element Breakdown

#### Root Object
- **Required:**
  - `"site"` (array of site objects)

- **Optional (informational):**
  - `"@programName"` (usually "ZAP")
  - `"@version"` (ZAP version)
  - `"@generated"` (RFC date string; parsed to ISO-8601 UTC)

#### Site Object (in `site[]`)
- **Required attributes:**
  - `"@name"` or `"@host"` - URL or hostname (parser extracts host from URL if both present)
  - `"@port"` - Port number as string (default: 80)

- **Optional:**
  - `"@ssl"` - "true"/"false"
  - `"alerts"` - Array of alert objects (if missing, treated as empty)

#### Alert Object (in `site[].alerts[]`)
- **Required:**
  - `"pluginid"` - ZAP plugin ID (becomes tool_native_id)
  - `"name"` - Alert title
  - `"riskcode"` - "0" (Informational), "1" (Low), "2" (Medium), "3" (High)
  - `"confidence"` - "0" (False Positive), "1" (Low), "2" (Medium), "3" (High), "4" (User Confirmed)

- **Optional:**
  - `"desc"` - HTML description (converted to plain text)
  - `"solution"` - Remediation (optional)
  - `"reference"` - Reference URLs (as HTML; extracted as HTTP links)
  - `"cweid"` - CWE ID (string; "0", "-1", "" are skipped)
  - `"wascid"` - WASC ID
  - `"instances"` - Array of instances where issue found

#### Instance Object (in `alert.instances[]`)
- **Fields:**
  - `"uri"` - URL where issue was found
  - `"method"` - HTTP method (GET, POST, etc.)
  - `"param"` - Parameter name (empty if not applicable)
  - `"evidence"` - Raw evidence text

**Multiple instances:** Each instance generates a separate Finding
**No instances:** One Finding generated per alert

### 2.4 Risk/Confidence Mapping

```python
RISK = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}

CONFIDENCE = {"0": "False Positive", "1": "Low", "2": "Medium", "3": "High", "4": "User Confirmed"}
```

### 2.5 Parser Output

**One Finding per instance (or per alert if no instances):**

```python
Finding(
    id="<UUID5 from fingerprint>",
    host_ip="172.28.0.11",
    port=80,
    protocol="tcp",
    url="http://172.28.0.11/",
    tool="zap",
    tool_native_id="10020",
    title="Missing Anti-clickjacking Header",
    description="The response does not protect against ClickJacking attacks.",
    evidence="x-frame-options",  # From instance.evidence, param, or alert.name
    cve_ids=(),  # ZAP doesn't provide CVEs
    cwe_ids=("CWE-1021",),  # From cweid
    reference_urls=("https://developer.mozilla.org/...",),  # HTTP links from reference
    native_severity="Medium",  # From RISK map
    native_confidence="Medium",  # From CONFIDENCE map
    first_seen="2026-09-05T00:00:00+00:00",  # From @generated
    last_seen="2026-09-05T00:00:00+00:00",
    provenance=Provenance(tool="zap", raw_path="...", record_index=0, run_id="..."),
)
```

### 2.6 Capture Command

**Baseline scan (passive, no attack):**
```bash
zap-baseline.py -t http://<authorised-ip> -J tests/fixtures/zap/<target>.json
```

**With Docker (recommended):**
```bash
docker run --rm --network $NETWORK --mount type=bind,source=$OUTPUT,target=/zap/wrk \
  $ZAP_IMAGE_ID zap-baseline.py -t http://172.28.0.11/ -m 1 -T 3 -J output.json
```

**Options:**
- `-t` - Target URL
- `-m` - Time budget for spidering (minutes)
- `-T` - Time budget for scanning (minutes)
- `-J` - JSON output file

---

## 3. NIKTO JSON - DETAILED SCHEMA

### 3.1 Minimal Valid Example

```json
{
  "host": "172.28.0.11",
  "ip": "172.28.0.11",
  "port": "80",
  "banner": "Apache/2.4.49",
  "vulnerabilities": []
}
```

### 3.2 Full Example with Vulnerabilities

```json
{
  "_comment": "Nikto 2.5 JSON report (synthetic)",
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
    },
    {
      "id": "999103",
      "method": "GET",
      "url": "/icons/README",
      "msg": "Server leaks inodes via ETags, header found with file /icons/README, inode: 0x1234, tag: \"5a4d7-1d6\"",
      "references": "http://cwe.mitre.org/data/definitions/200.html"
    },
    {
      "id": "600523",
      "method": "GET",
      "url": "/",
      "msg": "Apache/2.4.49 appears vulnerable to CVE-1999-9001 (path traversal).",
      "references": "https://httpd.apache.org/security/vulnerabilities_24.html CVE-1999-9001"
    }
  ]
}
```

### 3.3 Format Flexibility

Parser can handle:
1. **Single report object** with `"vulnerabilities"` array
2. **Array of report objects**, each with `"vulnerabilities"` array
3. **Mixed structure** as long as at least one object has `"vulnerabilities"` array

```json
# Format 1: Single object
{
  "host": "...",
  "vulnerabilities": [...]
}

# Format 2: Array of objects
[
  {"host": "...", "vulnerabilities": [...]},
  {"host": "...", "vulnerabilities": [...]}
]
```

### 3.4 Report Object Fields

- **Required:**
  - `"vulnerabilities"` - Array of vulnerability items (must exist for parser to recognize as report)

- **Optional (for host IP extraction):**
  - `"ip"` - IP address (preferred)
  - `"host"` - Hostname or IP (fallback if "ip" missing)
  - `"port"` - Port number; defaults to 80 if missing
  - `"banner"` - Server banner info (informational only)

### 3.5 Vulnerability Item Fields

- **Required:**
  - `"msg"` - Vulnerability message (becomes title and description)

- **Optional:**
  - `"id"` - Vulnerability ID (OSVDB or other; becomes tool_native_id)
  - `"OSVDB"` - Alternative ID field (fallback for "id")
  - `"url"` - Relative URL where found
  - `"method"` - HTTP method (GET, POST, etc.)
  - `"references"` - Reference URLs and CVE citations

### 3.6 CVE Extraction

CVE IDs extracted from:
- `"msg"` field (using regex `CVE-\d{4}-\d{4,}`)
- `"references"` field (same regex)

Example: "...vulnerable to CVE-1999-9001 (path traversal)" → extracts CVE-1999-9001

### 3.7 Parser Output

**One Finding per vulnerability item:**

```python
Finding(
    id="<UUID5 from fingerprint>",
    host_ip="172.28.0.11",
    port=80,
    protocol="tcp",
    url="/",  # From vulnerability.url
    tool="nikto",
    tool_native_id="999957",
    title="The anti-clickjacking X-Frame-Options header is not present.",  # msg, capped to 120 chars
    description="The anti-clickjacking X-Frame-Options header is not present.",  # msg
    evidence="The anti-clickjacking X-Frame-Options header is not present.",  # msg or url
    cve_ids=(),  # Empty for this one; populated if CVE found in msg/references
    cwe_ids=(),  # Nikto doesn't provide CWE
    reference_urls=("https://developer.mozilla.org/...",),  # HTTP links from references
    native_severity=None,  # Nikto has no severity concept
    native_confidence=None,  # Nikto has no confidence concept
    first_seen="",  # Empty; no timestamp in Nikto JSON
    last_seen="",
    provenance=Provenance(tool="nikto", raw_path="...", record_index=0, run_id="..."),
)
```

### 3.8 Capture Command

**Basic scan:**
```bash
nikto -h <target> -Format json -output out.json
```

**With port and timeout:**
```bash
nikto -h 172.28.0.11 -port 80 -Format json -output tests/fixtures/nikto/<target>.json
```

---

## 4. FINDING SCHEMA (Output)

All parsers generate `Finding` objects conforming to this schema:

```python
@dataclass(frozen=True)
class Finding:
    id: str  # UUID5 derived from fingerprint
    host_ip: str  # Target IP address (required)
    tool: str  # "nmap", "zap", or "nikto"
    tool_native_id: str  # Scanner's native ID for the finding
    title: str  # Short title
    description: str  # Full description
    evidence: str  # Verbatim raw excerpt (max 2048 chars)
    provenance: Provenance
    
    # Optional fields:
    port: int | None = None
    protocol: str | None = None
    url: str | None = None
    cve_ids: tuple[str, ...] = ()  # ("CVE-YYYY-NNNN", ...)
    cwe_ids: tuple[str, ...] = ()  # ("CWE-NNN", ...)
    reference_urls: tuple[str, ...] = ()
    native_severity: str | None = None  # "Low", "Medium", "High" (ZAP only)
    native_confidence: str | None = None  # "Low", "Medium", "High" (ZAP only)
    first_seen: str = ""  # ISO-8601 UTC or empty
    last_seen: str = ""  # ISO-8601 UTC or empty
```

### Provenance Tracking

```python
@dataclass(frozen=True)
class Provenance:
    tool: str  # "nmap", "zap", "nikto"
    raw_path: str  # Absolute path to scan file
    record_index: int  # 0-based index within file
    run_id: str  # Provided by caller; identifies scan run
```

---

## 5. INPUT VALIDATION & CONSTRAINTS

All parsers enforce these limits:

### File Size
- **Maximum:** 16 MB (16,777,216 bytes)
- **Minimum:** 1 byte (empty files rejected)

### JSON Validation (ZAP, Nikto)
- Maximum 200,000 values
- Maximum nesting depth of 128
- Duplicate keys rejected
- Non-finite values (NaN, Infinity) rejected
- UTF-8 encoded (with optional BOM)

### XML Validation (Nmap)
- Maximum 200,000 elements
- Maximum nesting depth of 128
- DOCTYPE and ENTITY declarations forbidden (security)
- Must be valid UTF-8 XML

### Other Checks
- Network share paths forbidden (e.g., `\\server\share\`)
- Empty files rejected
- Missing files raise `ConfigError` (before reading)
- Malformed files raise `AdapterError`

---

## 6. TESTING WITH FIXTURES

### Fixture Directory Layout

```
tests/
  fixtures/
    nmap/
      README.md             # Provenance table (required if .xml files present)
      metasploitable2.xml   # Real captures (optional)
      dvwa.xml
      juice-shop.xml
    zap/
      README.md             # Provenance table (required if .json files present)
      metasploitable2.json  # Real captures (optional)
      dvwa.json
      juice-shop.json
    nikto/
      README.md             # (planned)
    intel/
      README.md             # Feed snapshots
  synthetic/
    synthetic_nmap_two_machines.xml
    synthetic_zap_dvwa.json
    synthetic_nikto_dvwa.json
    ...
  golden/
    nmap/
      metasploitable2.json  # Expected parser output
    zap/
      dvwa.json
```

### Fixture-Dependent Tests

```python
import pytest

# Define shorthand
needs_fixture = pytest.mark.needs_fixture


@needs_fixture(
    "tests/fixtures/nmap/metasploitable2.xml",
    "tests/fixtures/nmap/README.md",
)
def test_real_nmap_capture():
    path = Path("tests/fixtures/nmap/metasploitable2.xml")
    hosts, findings = parse_nmap_xml(path, "capture-test")
    assert hosts, "Documented lab capture must contain its target host"
    # Assert against golden snapshot...
```

**Marker behavior:**
- Missing files → test skipped with message: `fixture not provided: <path>`
- Malformed files → parser raises `AdapterError` (test fails normally)
- Existing valid files → test runs

### Synthetic vs. Real Data

| Type | Location | Use Case | Mutability |
|------|----------|----------|-----------|
| **Synthetic** | `tests/synthetic/` | Pure logic tests, CI/CD | Modifiable for testing |
| **Real fixtures** | `tests/fixtures/` | Integration tests, parser validation | Immutable; require README provenance |
| **Golden snapshots** | `tests/golden/` | Regression detection | Update only with intentional parser changes |

---

## 7. EXAMPLE: Creating Custom Test Data

### Minimal Nmap for Unit Testing

```xml
<?xml version="1.0" encoding="UTF-8"?>
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
```

### Minimal ZAP for Unit Testing

```json
{
  "@programName": "ZAP",
  "@version": "2.15.0",
  "@generated": "Fri, 5 Sep 2026 00:00:00",
  "site": [
    {
      "@name": "http://172.28.0.11",
      "@host": "172.28.0.11",
      "alerts": [
        {
          "pluginid": "10020",
          "name": "Missing X-Frame-Options",
          "riskcode": "2",
          "confidence": "2",
          "cweid": "1021",
          "instances": [
            {"uri": "http://172.28.0.11/", "param": "header"}
          ]
        }
      ]
    }
  ]
}
```

### Minimal Nikto for Unit Testing

```json
{
  "host": "172.28.0.11",
  "port": "80",
  "vulnerabilities": [
    {
      "id": "999957",
      "url": "/",
      "msg": "Missing X-Frame-Options header."
    }
  ]
}
```

---

## 8. PARSER LOCATION REFERENCE

| Tool | Parser File | Test File | Synthetic Examples |
|------|-------------|-----------|-------------------|
| Nmap | [vulnassess/readers/nmap_xml.py](vulnassess/readers/nmap_xml.py) | [legacy/tests/test_nmap_xml.py](legacy/tests/test_nmap_xml.py) | synthetic_nmap_two_machines.xml, synthetic_nmap_ssh_only.xml |
| ZAP | [vulnassess/readers/zap_json.py](vulnassess/readers/zap_json.py) | [legacy/tests/test_zap_json.py](legacy/tests/test_zap_json.py) | synthetic_zap_dvwa.json |
| Nikto | [vulnassess/readers/nikto_json.py](vulnassess/readers/nikto_json.py) | (TBD) | synthetic_nikto_dvwa.json |
| Input validation | [vulnassess/readers/_input.py](vulnassess/readers/_input.py) | [tests/test_reader_security.py](tests/test_reader_security.py) | synthetic_adapter_inputs.json |

---

## 9. KEY DESIGN DECISIONS

From [docs/decisions.md](docs/decisions.md#27-conflict--resolution--why---fixture-provenance):

- **ADR #27: Fixture Provenance** - Synthetic data never proves scanner compatibility. Real fixtures require captured evidence with date, command, target, and operator recorded in README.md.
- **I2 Security:** All scanner/feed input is untrusted; bounded JSON/XML parsing with size/depth limits prevents DoS.
- **Evidence Preservation:** Raw evidence excerpts (max 2048 chars) enable cross-checking without modifying scanner output.
- **No Severity Invention:** Nmap and Nikto have no native severity; never infer or fabricate severity values.

---

## 10. TROUBLESHOOTING

| Symptom | Cause | Fix |
|---------|-------|-----|
| `AdapterError: nmap: ... root element is <root>, expected <nmaprun>` | Wrong XML root | Use full Nmap XML output, not a transformed copy |
| `AdapterError: zap: ... has no top-level 'site' list` | Malformed ZAP JSON | Ensure `"site": [...]` array exists at root |
| `AdapterError: nikto: ... has no 'vulnerabilities' list` | Wrong JSON format | Must have `"vulnerabilities": [...]` array in at least one object |
| `ConfigError: ... MISSING scan file` | File not found | Check file path and permissions |
| `AdapterError: capture ... exceeds 16777216 bytes` | File too large | Compress or split the scan file |
| Test marked `fixture not provided: ...` | Missing .xml/.json file | Create fixture or update pytest marker |
| Parser hangs or crashes | Malicious/oversized file | Validate file size before running parser |

---

## 11. REFERENCE DOCUMENTS

- [docs/fixtures.md](docs/fixtures.md) - Full capture guide with PowerShell scripts
- [docs/contracts.md](docs/contracts.md) - Schema and adapter contracts
- [docs/schema.md](docs/schema.md) - Data model reference
- [docs/decisions.md](docs/decisions.md) - Architecture decisions (ADRs)
- [vulnassess/schema.py](vulnassess/schema.py) - Frozen dataclasses (actual types)
- [vulnassess/readers/_input.py](vulnassess/readers/_input.py) - Input validation code

---

**Last updated:** 2026-09-07  
**Status:** Current for vulnassess version 1.0 prototype
