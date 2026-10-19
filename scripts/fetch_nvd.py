"""Rate-limited, resumable NVD API 2.0 mirror for local offline use.

Polite to the public API: one request per ~7 seconds (limit is 5 per rolling 30s
without a key), retries with backoff, skips pages already on disk. Run with:

    python scripts/fetch_nvd.py
"""

import json
import sys
import time
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "feeds" / "nvd"
PAGE = 2000
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "vulnassess-feed-provisioning/1.0 (github.com/codezxsWIN/privwork)"


def fetch(url: str, tries: int = 6) -> bytes:
    delay = 7.0
    for attempt in range(1, tries + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(request, timeout=300) as response:
                return response.read()
        except Exception as error:  # noqa: BLE001 - log and retry any transport error
            if attempt == tries:
                raise
            print(f"  retry {attempt} after error: {error}", flush=True)
            time.sleep(delay * attempt)
    raise RuntimeError("unreachable")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    probe = json.loads(fetch(f"{BASE}?resultsPerPage=1&startIndex=0"))
    total = int(probe["totalResults"])
    pages = (total + PAGE - 1) // PAGE
    print(f"total CVEs: {total} -> {pages} pages of {PAGE}", flush=True)

    for index in range(pages):
        start = index * PAGE
        path = OUT / f"page-{index:04d}.json"
        if path.is_file() and path.stat().st_size > 1000:
            continue
        url = f"{BASE}?resultsPerPage={PAGE}&startIndex={start}&noRejected"
        raw = fetch(url)
        payload = json.loads(raw)
        got = len(payload.get("vulnerabilities", []))
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(raw)
        tmp.replace(path)
        print(f"[{index + 1}/{pages}] startIndex={start} rows={got} bytes={len(raw)}", flush=True)
        time.sleep(7.0)
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
