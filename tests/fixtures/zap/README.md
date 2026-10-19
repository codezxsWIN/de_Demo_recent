# Real ZAP Reports & Examples

This directory contains both **real OWASP ZAP JSON reports** (for validation) and **synthetic examples** (for testing).

## 📋 Real Reports Provenance

Add one row per file before committing. A report without a row is not usable as evidence.

| File | Report Date | Command | Target(s) | Tool Version | Captured By | Authorization | Lab Network | Canary Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `real-lab-172.28.0.12-juiceshop-zap.json` | 2026-09-19 | ZAP daemon API, spider, passive scan and `core.jsonreport` against `http://172.28.0.12:3000` | Juice Shop 20.2.0 on 172.28.0.12 | ZAP 2.16.1 | repository owner's agent, at the owner's explicit instruction | owner's own machine, loopback-only lab | loopback pseudo-interface (no network egress) | canary log supplied and empty (`data/lab/canary.log`) |

## 📚 Synthetic Examples (Testing Only)

These are **never produced by ZAP** and never evidence. Use only for unit/integration testing:

| File | Purpose | Alerts | Instances | CWE Count |
| --- | --- | --- | --- | --- |
| `EXAMPLE-synthetic-dvwa.json` | Demonstrate ZAP JSON structure with multiple alert severities | 3+ | Variable | Multiple (CWE-79, etc.) |

## ✅ How to Capture Real Reports

**Not run by the agent.** A human runs this against an address listed in `config/scope.yaml`, with
written authorisation. **The baseline scan is passive:** it does not attack the target.

### ZAP Baseline Command

```bash
zap-baseline.py -t http://<authorised-ip> \
  -J tests/fixtures/zap/<target-name>-<date>.json
```

### Alternative: Full ZAP Docker Container

```bash
docker run -t --pull=always \
  -v "$(pwd)/tests/fixtures/zap":/zap/wrk \
  --network isolated-lab-net \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://<authorised-ip> \
  -J /zap/wrk/<target-name>-<date>.json
```

**Note:** Use digest-pinned container image for reproducibility.

## 🔒 Safety Checklist (Before Any Scan)

- [ ] Target(s) explicitly listed in `config/scope.yaml`
- [ ] Canary `172.28.0.250` verified **NOT** in scope
- [ ] Isolated lab network confirmed
- [ ] Written authorization obtained and dated
- [ ] Passive scan (baseline) only; no active attacks
- [ ] Report command, version, operator, timestamp recorded
- [ ] Lab access log provided and verified empty of canary

## 📝 Validation Checklist (Before Commit)

- [ ] Provenance table row filled in above
- [ ] All URIs/targets in report are lab-only (no production data)
- [ ] No session tokens, API keys, or credentials in `instances[].uri`
- [ ] JSON is well-formed (validated locally with `json.load()`)
- [ ] SHA-256 hash calculated and noted
- [ ] File size reasonable (<16 MB)
- [ ] Authorization reference is valid and dated

## 🔍 Expected JSON Structure

Real ZAP reports follow this pattern:

```json
{
  "site": [
    {
      "[@name]": "http://<target>",
      "alerts": [
        {
          "pluginid": "1234",
          "alertRef": "50000",
          "alert": "Cross-Site Scripting (Reflected)",
          "name": "Cross-Site Scripting (Reflected)",
          "riskcode": "2",
          "confidence": "2",
          "riskdesc": "Medium",
          "confidencedesc": "High",
          "desc": "...",
          "instances": [
            {
              "uri": "http://<target>/path",
              "method": "GET",
              "param": "param_name",
              "attack": "...",
              "evidence": "..."
            }
          ],
          "count": "1",
          "solution": "..."
        }
      ]
    }
  ]
}
```

**Key Elements:**

- **`site.[@name]`** — Target URL (must be in lab network)
- **`alerts[]`** — Array of security findings
- **`pluginid`** — ZAP plugin identifier
- **`riskcode`** — 0-3 (Low to High) / `3` = High
- **`confidence`** — 0-2 (Low to High Confidence)
- **`instances[]`** — Specific affected URIs/parameters
- **CWE extraction** — Parsed from alert name/description

## 🧪 Local Testing

Before committing:

```python
from vulnassess.readers.zap_json import read_zap_json
from vulnassess.settings import Config

config = Config("config/scope.yaml")
findings = read_zap_json("tests/fixtures/zap/your-file.json", config)
print(f"✓ Parsed: {len(findings)} findings")
```

## 📖 References

- [SCAN_FORMAT_REFERENCE.md](../../docs/SCAN_FORMAT_REFERENCE.md) — Full technical specs
- [FIXTURE_CREATION_GUIDE.md](../../docs/FIXTURE_CREATION_GUIDE.md) — Step-by-step guide
- [docs/fixtures.md](../../docs/fixtures.md) — ADR #27 (fixture policy)
- [docs/decisions.md](../../docs/decisions.md) — Project decisions
- [config/scope.yaml](../../config/scope.yaml) — Approved scan targets
- [ZAP Documentation](https://www.zaproxy.org/) — Official ZAP docs
