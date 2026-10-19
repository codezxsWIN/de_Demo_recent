# Fixture provenance: tests/fixtures/intel/

Curated subset of REAL public feed records, fetched 2026-09-17 from the official publishers,
on the repository owner's explicit instruction. Hosts, findings and profiles in the tests that
use these fixtures remain synthetic.

| File | Source | Records | SHA-256 |
| --- | --- | --- | --- |
| `nvd/curated-real-subset.json` | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>` (3 requests) | CVE-2021-44228, CVE-2014-6271, CVE-2017-0143 (full API records incl. CPE configurations) | see below |
| `epss.csv` | slice of `https://epss.cyentia.com/epss_scores-current.csv.gz` (score_date 2026-09-17) | the same three CVEs | see below |
| `kev.json` | slice of `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (dateReleased 2026-09-16) | the same three CVEs | see below |

Slicing kept the official response shapes byte-for-byte for the kept records: the NVD document
is a valid single-page API 2.0 response; `epss.csv` keeps the `#model_version` comment, the
`cve,epss,percentile` header and the raw rows; `kev.json` keeps the catalog wrapper fields and
the raw vulnerability objects.

Facts visible in this real slice (worth reading twice): all three CVEs are CISA-KEV listed
(known exploited), Log4Shell and Shellshock sit at EPSS 0.99999, EternalBlue at 0.93307.

SHA-256:
- `nvd/curated-real-subset.json`: `1a5238afe4845a955465c58cb37e879ee655f7c9dc91c2afec3f8f617fbaef19`
- `epss.csv`: `aaa40a0dfb8aa0a52be6b8275f1333c7d656c1855736af993421f4fa03c442b9`
- `kev.json`: `595280a8913c1d583db168be412c103f2fa6885857c6bb5b89af42020c427b19`
