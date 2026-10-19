# Fixture Integration Guide

**Date:** 2026-09-07  
**Status:** ✅ All fixture directories ready with examples and documentation

This guide walks through provisioning real scan data into the vulnassess project.

---

## 🎯 Overview

The project expects three types of scanner output:

| Scanner | Format | Status | Location | Notes |
|---------|--------|--------|----------|-------|
| **Nmap** | XML | 🟢 Ready (example included) | `tests/fixtures/nmap/` | Service discovery + CVEs |
| **ZAP** | JSON | 🟢 Ready (example included) | `tests/fixtures/zap/` | Web app security (passive) |
| **Nikto** | JSON | 🟢 Ready (example included) | `tests/fixtures/nikto/` | Web server checks |

All three have synthetic examples in place for testing. Real captures are optional but recommended.

---

## 📂 Current Fixture Structure

```
tests/fixtures/
├── nmap/
│   ├── README.md                                (UPDATED with guidance)
│   ├── .gitkeep
│   └── EXAMPLE-synthetic-lab-two-machines.xml  (Synthetic test data)
├── zap/
│   ├── README.md                                (UPDATED with guidance)
│   ├── .gitkeep
│   └── EXAMPLE-synthetic-dvwa.json              (Synthetic test data)
├── nikto/
│   ├── README.md                                (NEW - complete guide)
│   ├── .gitkeep
│   └── EXAMPLE-synthetic-dvwa.json              (Synthetic test data)
├── intel/
│   └── nvd/                                     (For NVD feeds)
└── golden/                                      (Expected parser output)
```

---

## 🚀 Quick Start: Test with Synthetic Examples

The project includes synthetic examples that demonstrate correct format. Run tests to validate:

```bash
cd c:\Users\aksha\Downloads\priv_DE\privwork

# Test Nmap parser
python -m pytest tests/test_all.py::TestRealFixtures::test_real_nmap_captures_parse -v

# Test ZAP parser
python -m pytest tests/test_all.py::TestRealFixtures::test_real_zap_reports_parse -v

# Run all fixture tests
python -m pytest tests/test_all.py::TestRealFixtures -v
```

**Current behavior:** Tests skip with `fixture not provided` because no real captures exist yet.
When you add real fixtures, tests will parse and validate them.

---

## 📊 Step-by-Step: Add Real Scan Data

### Step 1: Prepare Lab Environment

Before scanning, verify:

1. **Scope is defined** in `config/scope.yaml`
   ```yaml
   lab_targets:
     lab-web-01:
       networks: ["192.168.1.10/32"]
       role: "webserver"
   ```

2. **Canary is excluded**
   ```bash
   # Verify 172.28.0.250 is NOT in any network CIDR
   python -c "
   from vulnassess.settings import Config
   config = Config('config/scope.yaml')
   for name, target in config.lab_targets.items():
       for net in target.networks:
           if '172.28.0.250' in net:
               print(f'ERROR: Canary in {name}!')
   print('✓ Canary excluded')
   "
   ```

3. **Authorization obtained**
   - Written approval from InfoSec/management
   - Dated and signed (keep reference for provenance)

4. **Isolated network confirmed**
   - Lab network is separate from production
   - No access from/to production systems

### Step 2: Capture Real Scan Data

#### **Nmap**

```bash
# Standard service discovery
nmap -n -Pn -sT -sV --version-light -T2 \
  -p 21,22,23,25,53,80,88,110,135,139,143,389,443,445,465,587,636,993,995,1433,2049,3000,3306,5432,6379,8080,8443,27017 \
  -oX tests/fixtures/nmap/lab-web-01-2026-09-07.xml \
  192.168.1.10

# With Nikto's vulners NSE script (if installed)
nmap -n -Pn -sT -sV --script vulners \
  -oX tests/fixtures/nmap/lab-web-01-2026-09-07.xml \
  192.168.1.10
```

**Record:**
- Command used
- Nmap version: `nmap --version`
- Date/time started and ended
- Operator name
- Authorization reference

#### **ZAP (Passive Baseline)**

```bash
# Requires ZAP installed or Docker
zap-baseline.py \
  -t http://192.168.1.10 \
  -J tests/fixtures/zap/lab-web-01-2026-09-07.json
```

**Or via Docker:**

```bash
docker run -t --rm \
  -v $(pwd)/tests/fixtures/zap:/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://192.168.1.10 \
  -J /zap/wrk/lab-web-01-2026-09-07.json
```

**Record:**
- Command used
- ZAP version
- Date/time
- Operator name
- Authorization reference
- Container digest (if using Docker)

#### **Nikto**

```bash
# Native Perl (if installed)
nikto -h 192.168.1.10 \
  -Format json \
  -output tests/fixtures/nikto/lab-web-01-2026-09-07.json
```

**Or via Docker:**

```bash
docker run --rm \
  -v $(pwd)/tests/fixtures/nikto:/app/output \
  securecodebox/nikto:latest \
  -h 192.168.1.10 \
  -Format json \
  -output /app/output/lab-web-01-2026-09-07.json
```

**Record:**
- Command used
- Nikto version
- Date/time
- Operator name
- Authorization reference
- Container digest (if using Docker)

### Step 3: Validate & Document

1. **Verify files created:**
   ```bash
   ls -la tests/fixtures/nmap/*.xml
   ls -la tests/fixtures/zap/*.json
   ls -la tests/fixtures/nikto/*.json
   ```

2. **Calculate SHA-256 hashes:**
   ```python
   import hashlib
   
   for fname in ["lab-web-01-2026-09-07.xml", "lab-web-01-2026-09-07.json"]:
       with open(f"tests/fixtures/nmap/{fname}", "rb") as f:
           hash = hashlib.sha256(f.read()).hexdigest()
       print(f"{fname}: {hash}")
   ```

3. **Test parsing locally:**
   ```python
   from vulnassess.readers.nmap_xml import read_nmap_xml
   from vulnassess.settings import Config

   config = Config("config/scope.yaml")
   hosts, findings = read_nmap_xml("tests/fixtures/nmap/lab-web-01-2026-09-07.xml", config)
   print(f"✓ Hosts: {len(hosts)}, Findings: {len(findings)}")
   ```

4. **Add provenance rows** to README files:

   **`tests/fixtures/nmap/README.md`:**
   ```markdown
   | lab-web-01-2026-09-07.xml | 2026-09-07 | `nmap -n -Pn -sT -sV -p 22,80,443 -oX ...` | 192.168.1.10 | Nmap 7.94 | alice@company | Approved by InfoSec on 2026-09-07 | Lab DMZ | 172.28.0.250 not in scope |
   ```

   Same for ZAP and Nikto README.md files.

5. **Commit with message:**
   ```bash
   git add tests/fixtures/nmap/lab-web-01-2026-09-07.xml
   git add tests/fixtures/nmap/README.md
   git commit -m "Add real Nmap capture for lab-web-01 (2026-09-07, authorized)"
   ```

### Step 4: Run Full Test Suite

```bash
# Test individual parsers
pytest tests/test_all.py::TestRealFixtures -v

# Full validation
python scripts/check.py

# Run with coverage
pytest tests/ --cov=vulnassess --cov-report=html
```

---

## 🔒 Security Checklist (MUST COMPLETE)

**Before any scan:**
- [ ] Target explicitly in `config/scope.yaml`
- [ ] Canary `172.28.0.250` verified not in scope
- [ ] Isolated lab network exists and tested
- [ ] Written authorization obtained and dated
- [ ] Scan command, version, operator, time recorded

**Before commit:**
- [ ] No production data in fixtures
- [ ] No credentials, tokens, API keys in output
- [ ] All hostnames/IPs are lab-only
- [ ] Files are well-formed XML/JSON
- [ ] SHA-256 hashes calculated and recorded
- [ ] Provenance table updated in README
- [ ] Authorization reference is valid

---

## 📚 Reference Documents

| Document | Purpose |
|----------|---------|
| [SCAN_FORMAT_REFERENCE.md](SCAN_FORMAT_REFERENCE.md) | Complete technical specs (schemas, fields, validation) |
| [FIXTURE_CREATION_GUIDE.md](FIXTURE_CREATION_GUIDE.md) | Detailed step-by-step guide with examples |
| [tests/fixtures/nmap/README.md](tests/fixtures/nmap/README.md) | Nmap capture guidance |
| [tests/fixtures/zap/README.md](tests/fixtures/zap/README.md) | ZAP report guidance |
| [tests/fixtures/nikto/README.md](tests/fixtures/nikto/README.md) | Nikto report guidance |
| [docs/fixtures.md](docs/fixtures.md) | ADR #27 — fixture policy |
| [docs/decisions.md](docs/decisions.md) | Project decisions |
| [config/scope.yaml](config/scope.yaml) | Lab target definitions |

---

## ❓ Troubleshooting

### "fixture not provided" test skip

**Cause:** No real `.xml` or `.json` files in `tests/fixtures/nmap/`, `tests/fixtures/zap/`, or `tests/fixtures/nikto/` directories.

**Solution:** Add at least one real scan file with provenance documented in README.

### JSON parse errors

**Cause:** ZAP or Nikto output is malformed or contains non-UTF-8 characters.

**Solution:** Validate locally:
```python
import json

with open("tests/fixtures/zap/file.json") as f:
    data = json.load(f)
print(f"✓ Valid JSON with {len(data)} top-level keys")
```

### Scope validation failures

**Cause:** Scanner output contains IPs/hostnames not in `config/scope.yaml`.

**Solution:** Update `config/scope.yaml` with all lab targets and their networks, or filter scanner output.

### Canary in output

**Cause:** Accidentally scanned or included `172.28.0.250`.

**Solution:** Re-run scan with explicit target ranges excluding canary. Do not commit.

---

## 🎓 Learning Resources

- **Nmap:** https://nmap.org/documentation.html
- **ZAP:** https://www.zaproxy.org/getting-started/
- **Nikto:** https://github.com/sullo/nikto/wiki
- **CVE/CWE:** https://cve.mitre.org/, https://cwe.mitre.org/

---

**All fixture directories are now ready. Start with synthetic examples for testing, then add real captures when your lab is authorized and ready.**
