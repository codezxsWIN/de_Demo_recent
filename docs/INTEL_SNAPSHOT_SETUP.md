# Four-source intelligence snapshots

The full public datasets are **not committed** to this repository, as required by `DOWNLOADS_REQUIRED.txt` and `docs/FEED_PROVENANCE.md`. Instead, `scripts/sync_intel_snapshot.py` downloads and validates the four datasets locally.

## Windows setup

```powershell
git pull origin main
python scripts/sync_intel_snapshot.py
```

On success, files are saved to the ignored `intel_snapshots/` folder:

- `cisa_kev_catalog.json` (CISA KEV)
- `nvd_CVE-2022-0543.json` (NVD single CVE)
- `epss_scores-2026-10-22.csv` (dated EPSS snapshot)
- `cwec_v4.20.xml` (MITRE CWE)

An internet connection is required. If a source URL is inaccessible or a validation fails, the script stops and displays an error. These downloads are **not** automatically loaded into VulnAssess; the existing application expects its runtime feeds under `data/feeds/`, and the existing NVD importer may expect paged NVD records.

For the existing three-feed loader, prefer the repo's established workflow:

```powershell
python scripts/fetch_feeds.py --skip-nvd
python -m vulnassess intel load --from-dir data/feeds
```

The first command refreshes KEV and EPSS; skip-nvd deliberately does not mirror NVD. Use `python scripts/fetch_feeds.py` for the full resumable NVD download. See `docs/FEED_PROVENANCE.md` for source provenance and reproducibility requirements.
