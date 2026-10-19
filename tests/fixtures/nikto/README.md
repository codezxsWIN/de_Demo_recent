# Real Nikto Reports & Examples

This directory contains both **real Nikto JSON reports** (for validation) and **synthetic examples** (for testing).

## 📋 Real Reports Provenance

Add one row per file before committing. A report without a row is not usable as evidence.

| File | Report Date | Command | Target(s) | Tool Version | Captured By | Authorization | Lab Network | Canary Status |
|------|-------------|---------|-----------|--------------|-------------|----------------|-------------|----------------|
| _(none yet)_ | | | | | | | | |

## 📚 Synthetic Examples (Testing Only)

These are **never produced by Nikto** and never evidence. Use only for unit/integration testing:

| File | Purpose | Findings | CVE References |
|------|---------|----------|-----------------|
| `EXAMPLE-synthetic-dvwa.json` | Demonstrate Nikto JSON structure with web vulnerabilities | 3+ | Multiple (extracted from refs) |

## ✅ How to Capture Real Reports

**Not run by the agent.** A human runs this against an address listed in `config/scope.yaml`, with
written authorisation.

### Nikto Command (Native Perl)

Requires Perl runtime ([Strawberry Perl](https://strawberryperl.com/) on Windows):

```bash
nikto -h <authorised-ip> -Format json -output tests/fixtures/nikto/<target-name>-<date>.json
```

### Nikto via Docker Container (Recommended)

Isolated environment with no local Perl dependency:

```bash
docker run --rm -v "$(pwd)/tests/fixtures/nikto":/app/output \
  --network isolated-lab-net \
  securecodebox/nikto:latest \
  -h <authorised-ip> \
  -Format json \
  -output /app/output/<target-name>-<date>.json
```

**Note:** Use digest-pinned container image for reproducibility.

## 🔒 Safety Checklist (Before Any Scan)

- [ ] Target(s) explicitly listed in `config/scope.yaml`
- [ ] Canary `172.28.0.250` verified **NOT** in scope
- [ ] Isolated lab network confirmed
- [ ] Written authorization obtained and dated
- [ ] Scan command, version, operator, timestamp recorded
- [ ] Lab access log provided and verified empty of canary

## 📝 Validation Checklist (Before Commit)

- [ ] Provenance table row filled in above
- [ ] All targets/URIs in report are lab-only (no production data)
- [ ] No credentials, tokens, or sensitive data in output
- [ ] JSON is well-formed (validated locally with `json.load()`)
- [ ] SHA-256 hash calculated and noted
- [ ] File size reasonable (<16 MB)
- [ ] Authorization reference is valid and dated

## 🔍 Expected JSON Structure

Real Nikto reports follow this pattern:

```json
{
  "product": "Nikto",
  "version": "<nikto-version>",
  "scanTime": "...",
  "nScanners": "...",
  "host": "<target-url>",
  "port": 80,
  "banner": "...",
  "items": [
    {
      "id": "1234567",
      "osvdbId": "...",
      "method": "GET",
      "uri": "/path",
      "description": "...",
      "nameLink": "...",
      "iplink": "...",
      "refs": [
        { "ref": "CVE-XXXX-XXXXX", "key": "CVE" },
        { "ref": "CWE-XXXX", "key": "CWE" }
      ]
    }
  ]
}
```

**Key Elements:**
- **`host`** — Target URL (must be in lab network)
- **`port`** — HTTP/HTTPS port
- **`items[]`** — Array of detected vulnerabilities
- **`description`** — Nikto's finding description
- **`refs[]`** — CVE/CWE/other references
- **Flexible structure:** Nikto JSON can be either object or array

## 🧪 Local Testing

Before committing:

```python
from vulnassess.readers.nikto_json import read_nikto_json
from vulnassess.settings import Config

config = Config("config/scope.yaml")
findings = read_nikto_json("tests/fixtures/nikto/your-file.json", config)
print(f"✓ Parsed: {len(findings)} findings")
```

## 📖 References

- [SCAN_FORMAT_REFERENCE.md](../../docs/SCAN_FORMAT_REFERENCE.md) — Full technical specs
- [FIXTURE_CREATION_GUIDE.md](../../docs/FIXTURE_CREATION_GUIDE.md) — Step-by-step guide
- [docs/fixtures.md](../../docs/fixtures.md) — ADR #27 (fixture policy)
- [docs/decisions.md](../../docs/decisions.md) — Project decisions
- [config/scope.yaml](../../config/scope.yaml) — Approved scan targets
- [Nikto GitHub](https://github.com/sullo/nikto) — Official Nikto repository
- [Nikto Docker Image](https://hub.docker.com/r/securecodebox/nikto) — Container option
