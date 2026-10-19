# Real feed snapshots

This directory now holds a curated slice of REAL feed records, fetched on 2026-09-17 by the
agent at the repository owner's explicit instruction; provenance and hashes are in
[PROVENANCE.md](PROVENANCE.md). The subset is committed so CI can prove the loader, matcher and
scoring path accept the official formats without downloading the full feeds. Full snapshots live
under gitignored `data/feeds/`; fetch them with `python data/feeds/fetch_feeds.py`.

`vulnassess intel load --from-dir <dir>` exits `5` and names every missing path while any of the
three is absent. Nothing in the runtime downloads a feed.

## Expected layout

```text
tests/fixtures/intel/
  nvd/*.json      one or more NVD API 2.0 responses: {"vulnerabilities": [{"cve": {...}}, ...]}
  epss.csv[.gz]   the EPSS daily file: #model_version:...,score_date:YYYY-MM-DD
                  then the header cve,epss,percentile
  kev.json        the CISA KEV catalog: {"dateReleased": ..., "vulnerabilities": [...]}
```

## How to obtain

**Not run by the agent.** A human downloads these from the official sources and records what they
fetched. The loader stores the SHA-256 and the snapshot date of every file and prints both in the
report, so a result can always be tied to the exact data that produced it.

| Feed | Source |
| --- | --- |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` |
| EPSS | `epss.cyentia.com` daily `epss_scores-YYYY-MM-DD.csv.gz` |
| KEV | the CISA Known Exploited Vulnerabilities catalog JSON |

## Provenance

| File | Fetch date | Source URL | SHA-256 | Fetched by |
| --- | --- | --- | --- | --- |
| _(none yet)_ | | | | |

## What must not be committed here

A full feed dump. Commit only the trimmed subset needed by a test, keep the provenance row, and
pin the snapshot date in any assessment report generated from it.
