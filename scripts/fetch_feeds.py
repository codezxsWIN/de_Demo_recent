"""Fetch the three public feed snapshots into this directory (gitignored).

    python scripts/fetch_feeds.py [--skip-nvd]

Pulls only from the official publishers: CISA (KEV), FIRST/Cyentia (EPSS) and
NIST (NVD API 2.0). The NVD mirror is the long pole (~200 pages, rate-limited
to stay inside the public no-key quota); it is resumable, so re-running this
script continues where it stopped. After fetching, load with:

    vulnassess intel load --from-dir data/feeds

Record the results in docs/FEED_PROVENANCE.md.
"""

import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

FEEDS = Path(__file__).resolve().parents[1] / "data" / "feeds"
UA = "vulnassess-feed-provisioning/1.0 (github.com/codezxsWIN/privwork)"

SOURCES = {
    "kev.json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss.csv.gz": "https://epss.cyentia.com/epss_scores-current.csv.gz",
}


def fetch(url: str, out: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(request, timeout=600) as response:
        raw = response.read()
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_bytes(raw)
    tmp.replace(out)
    print(f"{out.name:14} {len(raw):>12,} bytes  sha256 {sha256(raw).hexdigest()}")


def main() -> int:
    fetched: list[str] = []
    for name, url in SOURCES.items():
        fetch(url, FEEDS / name)
        fetched.append(name)
    if "--skip-nvd" not in sys.argv:
        print("mirroring NVD (rate-limited; resumable)...", flush=True)
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent / "fetch_nvd.py")], check=False
        )
        if result.returncode != 0:
            return result.returncode
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with (FEEDS / "PROVENANCE.md").open("a", encoding="utf-8") as log:
        log.write(f"\n- {stamp}: fetched {', '.join(fetched)} (+ NVD pages present)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
