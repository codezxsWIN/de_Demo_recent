"""Reproduce the team's NVD/CVSS and EPSS/KEV lookups using existing adapters.

Archive parsed publisher JSON, source URLs, dates and hashes. Never create scan
findings, archive HTTP headers or import credentials from submitted documents.
"""

import argparse
import json
import sys
import tempfile
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnassess import intel_online  # noqa: E402
from vulnassess.store import Store  # noqa: E402

REFERENCE_CASES = Path(__file__).resolve().parents[1] / "examples/intelligence-reference-cases.json"


def verify(cves, output_root, *, cache_path=None, fetch=intel_online.fetch_json):
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="intelligence-", dir=output_root))
    manifest = {
        "purpose": "intelligence lookup only; no target scan or vulnerability detection",
        "status": "incomplete",
        "started_at": datetime.now(UTC).isoformat(),
        "sources": [],
    }

    def archive(url, limit):
        payload = fetch(url, limit)
        raw = json.dumps(payload, ensure_ascii=True, sort_keys=True, allow_nan=False).encode()
        name = f"source-{len(manifest['sources']) + 1}.json"
        (directory / name).write_bytes(raw)
        manifest["sources"].append(
            {
                "url": url,
                "file": name,
                "sha256": sha256(raw).hexdigest(),
                "fetched_at": datetime.now(UTC).isoformat(),
                "representation": "parsed response serialized as canonical JSON",
            }
        )
        return payload

    try:
        with Store(Path(cache_path) if cache_path else directory / "intel-cache.db") as store:
            counts = intel_online.sync_cves(cves, store, fetch_json=archive, force_refresh=True)
            rows = []
            for cve_id in sorted({item.strip().upper() for item in cves}):
                cve = store.cve(cve_id) or {}
                epss = store.epss(cve_id)
                kev = store.kev(cve_id)
                rows.append(
                    {
                        "cve": cve_id,
                        "nvd_found": bool(cve),
                        "cvss31_base": cve.get("cvss31_base"),
                        "cvss31_vector": cve.get("cvss31_vector"),
                        "epss": epss,
                        "kev_listed": kev is not None,
                        "kev_date_added": (kev or {}).get("dateAdded"),
                        "cve_applies_to_scanned_host": "not evaluated",
                    }
                )
            result = {
                "results": rows,
                "counts": counts,
                "feeds": store.feeds_meta(),
                "source_manifest": "manifest.json",
                "scanner_launched": False,
                "reference_cases": json.loads(REFERENCE_CASES.read_text(encoding="utf-8")),
            }
            # Keep date-specific submitted EPSS values as references, never replace
            # the live probability or silently mark historical values as fresh.
            (directory / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        manifest["status"] = "verified"
        manifest["results_sha256"] = sha256((directory / "results.json").read_bytes()).hexdigest()
    finally:
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return directory, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cves", nargs="*")
    parser.add_argument("--output", type=Path, default=Path("data/intelligence-verification"))
    parser.add_argument(
        "--update-cache",
        action="store_true",
        help="Refresh the operational isolated data/intel-cache.db after validating all sources",
    )
    args = parser.parse_args()
    references = json.loads(REFERENCE_CASES.read_text(encoding="utf-8"))
    cves = args.cves or [item["cve"] for item in references["submissions"]]
    directory, result = verify(
        cves, args.output, cache_path=Path("data/intel-cache.db") if args.update_cache else None
    )
    print(
        json.dumps(
            {
                "evidence_directory": str(directory),
                "results": result["results"],
                "scanner_launched": False,
                "operational_cache_updated": args.update_cache,
            }
        )
    )


if __name__ == "__main__":
    main()
