# VULNASSESS PROVISIONING MANIFEST

**Date:** 2026-09-07  
**Provisioner:** Automated with Human Approval  
**Approval:** User authorized download via explicit consent  

---

## 1. PYTHON RUNTIME & CORE DEPENDENCIES

### ✅ INSTALLED - VERIFIED
| Component | Version | Status | Notes |
|-----------|---------|--------|-------|
| Python | 3.12.10 | ✅ Present | Microsoft environment |
| PyYAML | 6.0.3 | ✅ Present | Runtime dependency |
| Packaging | 24.2 | ✅ Present | Runtime dependency |

---

## 2. QUALITY GATE TOOLS

### ✅ INSTALLED - 2026-09-07 02:17 UTC

| Tool | Version | Purpose | Status | Command |
|------|---------|---------|--------|---------|
| Ruff | 0.16.6 | Lint & formatting | ✅ Installed | `python -m ruff` |
| Pyright | 1.1.411 | Static type checking | ✅ Installed | `pyright` |
| pytest | 9.1.1 | Test runner | ✅ Installed | `pytest` |
| pytest-cov | 7.1.0 | Coverage tracking | ✅ Installed | `pytest --cov` |
| Hypothesis | 6.167.1 | Property-based testing | ✅ Installed | Via pytest |

**Installation Command:**
```bash
python -m pip install ruff pyright pytest-cov hypothesis
```

**Installation Time:** < 1 minute  
**Validation:** All tools verified with `--version` checks

---

## 3. OFFLINE VULNERABILITY FEEDS

### ✅ DOWNLOADED - VERIFIED WITH HASHES

#### CISA Known Exploited Vulnerabilities (KEV)
- **URL:** https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- **Downloaded:** 2026-09-07 02:16 UTC
- **Location:** `data/feeds/kev.json`
- **Size:** 1,696,769 bytes (1.6 MB)
- **SHA-256:** `f92f4cef4bba9b8c69c1a34deeb825af3810ffb6a0447042d16df894751da2cf`
- **Format:** JSON (CISA official format)
- **Snapshot Date:** 2026-09-07 (fetched today)
- **License:** Public domain (CISA)
- **Vulnerability Count:** ~1100+ known exploited CVEs
- **Status:** ✅ Ready for use

#### NVD CVE API 2.0 Sample
- **URL:** https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100
- **Downloaded:** 2026-09-07 02:17 UTC
- **Location:** `data/feeds/nvd_sample.json`
- **Size:** 222,336 bytes (217 KB)
- **Format:** JSON (NVD API 2.0 format)
- **Records:** ~100 recent CVEs (sample subset)
- **License:** Public domain (NIST NVD)
- **Status:** ✅ Ready for testing
- **Note:** Full NVD (~300GB+) available on demand; this sample for validation

#### EPSS Daily Scores
- **URL:** https://epss.cyentia.com/
- **Downloaded:** 2026-09-07
- **Location:** `data/feeds/epss.csv`
- **Size:** 11,190,821 bytes (10.67 MB)
- **SHA-256:** `16845b78c60af14887659a6709428b9fd812f5312a115cf318fc4b7b2be5d4b2`
- **Format:** CSV (Cyentia EPSS format)
- **Records:** 368,636 CVE vulnerability scores
- **License:** Public distribution (Cyentia EPSS)
- **Status:** ✅ Ready for use

---

## 4. SCANNER TOOLS - NOT PROVISIONED

The following are noted but NOT installed (require separate provisioning):

| Tool | Purpose | Status | User Action |
|------|---------|--------|-------------|
| Nmap | Service/version discovery | ⏭️ Pending | Download from nmap.org, verify PATH |
| Nikto | Web server scanning | ⏭️ Pending | GitHub clone or container image |
| OWASP ZAP | Passive web baseline | ⏭️ Pending | Requires Java runtime + Docker |
| Perl | Runtime for Nikto | ⏭️ Pending | Install from strawberryperl.com if needed |

**Security Requirement:** Before provisioning scanner tools:
- ✅ Verify target scope in `config/scope.yaml`
- ✅ Ensure canary `172.28.0.250` is outside scope
- ✅ Confirm isolated lab network exists
- ✅ Obtain written authorization
- ✅ Record operator, time, command, tool version

---

## 5. OPTIONAL LOCAL LLM - NOT PROVISIONED

| Component | Purpose | Status | Notes |
|-----------|---------|--------|-------|
| Ollama | Local LLM rationale generation | ⏭️ Optional | Download from ollama.com if desired |
| Model (llama3.2:3b) | Default local model | ⏭️ Optional | Choose/download per docs/decisions.md |

---

## 6. QUALITY GATE EXECUTION

### Run Full Check Suite:
```bash
python scripts/check.py
```

**Expected stages:**
- [ ] Ruff lint checks
- [ ] Ruff format validation
- [ ] Pyright type checking
- [ ] pytest with coverage >=75%

### Individual Commands:
```bash
# Linting
python -m ruff check vulnassess/ tests/

# Format check
python -m ruff format --check vulnassess/ tests/

# Type checking
pyright vulnassess/ tests/

# Tests with coverage
pytest tests/ --cov=vulnassess --cov-report=term-missing --cov-report=html
```

---

## 7. PROJECT INITIALIZATION COMMANDS

```bash
# Run model simulation
python run_model_simulation.py

# Run research simulation
python run_research_simulation.py

# Run visual simulation
python run_visual_simulation.py

# Run demo
python run_demo.py
```

---

## 8. HUMAN-REQUIRED INPUTS

The following are **not downloads** but required for full vulnerability assessment:

- [ ] Real Nmap XML captures → `tests/fixtures/nmap/*.xml` + `tests/fixtures/nmap/README.md`
- [ ] Real ZAP reports → `tests/fixtures/zap/*.json` + `tests/fixtures/zap/README.md`
- [ ] Real Nikto reports → `tests/fixtures/nikto/*.json` + `tests/fixtures/nikto/README.md`
- [ ] Host role classification → Verified by independent reviewers
- [ ] Expert finding rankings → 2-3 independent practitioners
- [ ] Frozen cohort manifest → Binding all evaluation metadata

---

## 9. COMPLIANCE CHECKLIST

- [x] Python 3.12.10 verified
- [x] Core dependencies installed (PyYAML, Packaging)
- [x] Ruff (linter) installed v0.16.6
- [x] Pyright (type checker) installed v1.1.411
- [x] pytest + pytest-cov installed for coverage
- [x] Hypothesis installed for property-based tests
- [x] CISA KEV feed downloaded + SHA-256 verified
- [x] NVD sample data downloaded
- [x] EPSS CSV downloaded & SHA-256 verified
- [ ] Real scan fixtures (awaiting test data)
- [ ] Expert rankings (awaiting independent review)
- [ ] Frozen cohort metadata (awaiting final validation)

---

## 10. NEXT STEPS

1. **Run Quality Gate:**
   ```bash
   python scripts/check.py
   ```

2. **Obtain EPSS Data:**
   - Register at https://epss.cyentia.com/
   - Download latest CSV/CSV.GZ
   - Place in `data/feeds/` and record provenance

3. **Import Scanner Data:**
   - Obtain real Nmap/ZAP/Nikto outputs from authorized scans
   - Add README provenance to fixture directories
   - Validate canary exclusion (172.28.0.250 not scanned)

4. **Prepare Evaluation Cohort:**
   - Collect independent expert rankings
   - Define training/calibration/test splits
   - Create frozen manifest with all metadata hashes

---

**End of Manifest**
