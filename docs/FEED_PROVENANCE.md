# Feed provenance

The offline snapshots under `data/feeds/` (gitignored — full feeds are never
committed) were fetched by the repository owner's agent on **2026-09-17**, on the
owner's explicit instruction, directly from the official publishers. The runtime
never refreshes them. Re-fetch any time with `python scripts/fetch_feeds.py`
(resumable; NVD is the long pole) and update this table.

| Feed | Official source | Fetched | Snapshot date | Rows | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 2026-09-17 | dateReleased 2026-09-16 | 1,713 | `72b4e3489021d2ad50c4f9b8ddddd1608a9e6b87dd7beedc126f6341ea98f105` |
| EPSS | `https://epss.cyentia.com/epss_scores-current.csv.gz` | 2026-09-17 | score_date 2026-09-17 | 375,610 | `388c2b40cf18d3bff78cf70598c8d5d77b630bb5346673b5df1ba07aeab99428` |
| NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0` (paged, `noRejected`, 2,000/page) | 2026-09-17 | 194 pages, `data/feeds/nvd/page-0000.json` … `page-0193.json` | 376,424 CVE records loaded (loader-reported; per-page digests combined by the loader into one feed hash, `d01e8f903a23b3ad…`) | fetch log: `data/feeds/nvd-fetch.log` |

Fetch method: `scripts/fetch_feeds.py` / `scripts/fetch_nvd.py` — urllib
with a descriptive User-Agent, one request per ~7 s (inside NVD's public no-key
quota of 5 per rolling 30 s), retries with backoff, resumable.

Curated committed subsets for reproducible integration tests live under
`tests/fixtures/intel/` with their own provenance headers; see
`tests/fixtures/intel/PROVENANCE.md`.

What this does and does not establish: the enrichment data is now **real**
(published by CISA, Cyentia/FIRST and NIST), so CVSS vectors, EPSS percentiles
and KEV flags in reports come from the real world. It does **not** constitute
scan evidence: no real scanner captures exist yet, and RQ1–RQ4 research outcomes
remain `NOT RUN` until independent captures, host-context truth and expert
rankings arrive (`DOWNLOADS_REQUIRED.txt` §6).

- 2026-09-21: fetched kev.json (1,716 rows, sha256 7b770a6f5eb1d47a...) and epss.csv.gz
  (377,238 rows, sha256 6e5d46d4fa7f7229...) via scripts/fetch_feeds.py --skip-nvd from
  CISA and FIRST/Cyentia. NVD: targeted mirror pages page-9100-*.json / page-9105-*.json
  from the official NVD API 2.0 using virtualMatchString for the CPEs observed in the
  real local scan (apache:tomcat 276, python:python 157, golang:go 180 full history;
  microsoft:windows last 360 days 1,926), while the full resumable mirror
  (scripts/fetch_nvd.py) continues in the background. Loaded: epss 377,238 / kev 1,716 /
  nvd 54,551 rows. Enrichment of run 'reallab': 14/14 findings matched, 1,231 enrichments.
