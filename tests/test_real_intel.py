"""Integration over a curated slice of REAL public feed snapshots.

The fixtures under tests/fixtures/intel/ are genuine records from the CISA KEV
catalog, the EPSS daily CSV and the NVD API 2.0 (provenance in
tests/fixtures/intel/PROVENANCE.md). They prove the loader, matcher and scoring
path accept the official formats — they are still not scan evidence: the hosts
and findings here are synthetic.
"""

import unittest
from pathlib import Path

from vulnassess import intel, scoring
from vulnassess.schema import Finding, Provenance, Service
from vulnassess.settings import Settings
from vulnassess.store import Store

ROOT = Path(__file__).resolve().parents[1]
REAL_FEEDS = ROOT / "tests" / "fixtures" / "intel"
SETTINGS = Settings(ROOT / "config")
WEIGHTS = SETTINGS.weights
BASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

CVE_2021_44228 = "CVE-2021-44228"  # Log4Shell: KEV, EPSS percentile 1.0, CVSS 10.0


def make_finding(cve_id: str, host_ip: str = "172.28.0.12") -> Finding:
    return Finding.make(
        host_ip=host_ip,
        port=8080,
        protocol="tcp",
        url=None,
        tool="nmap",
        tool_native_id=f"vulners:{cve_id}",
        title=f"vulners reports {cve_id} on http",
        description="synthetic host, real CVE evidence",
        evidence=f"{cve_id} reported by scanner",
        cve_ids=[cve_id],
        first_seen="2026-09-17T00:00:00+00:00",
        last_seen="2026-09-17T00:00:00+00:00",
        provenance=Provenance("nmap", "tests/synthetic/x.xml", 1, "unit"),
    )


def make_service(port: int = 8080, cpe: str | None = None) -> Service:
    return Service(
        port=port,
        protocol="tcp",
        name="http",
        product="log4j" if cpe else None,
        version="2.14.1" if cpe else None,
        cpe=cpe,
        banner="HTTP/1.1 200",
        tls=False,
    )


class TestRealIntel(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name) / "data" / "vulnassess.db")
        self.addCleanup(self.store.close)
        self.counts = intel.load_feeds(REAL_FEEDS, self.store)
        self.feed_dates = {
            feed: (info.get("file_date") or "") for feed, info in self.store.feeds_meta().items()
        }

    def test_real_feed_loader_accepts_official_formats(self) -> None:
        self.assertEqual(self.counts, {"nvd": 3, "epss": 3, "kev": 3})
        meta = self.store.feeds_meta()
        self.assertEqual(meta["kev"]["file_date"], "2026-09-16")
        self.assertEqual(meta["epss"]["file_date"], "2026-09-17")
        for feed, info in meta.items():
            self.assertEqual(info["rows"], 3, feed)
            self.assertRegex(info["sha256"], r"^[0-9a-f]{64}$", feed)

    def test_real_kev_and_epss_reach_the_threat_factor(self) -> None:
        finding = make_finding(CVE_2021_44228)
        services = (make_service(),)
        enrichments = intel.match_finding(finding, services, self.store, self.feed_dates)
        self.assertEqual(len(enrichments), 1)
        enrichment = enrichments[0]
        self.assertEqual(enrichment.match_method, "explicit")
        self.assertTrue(enrichment.kev)
        self.assertAlmostEqual(enrichment.epss, 0.99999)
        self.assertEqual(enrichment.epss_percentile, 1.0)
        self.assertEqual(enrichment.cvss31_base, 10.0)

        breakdown = scoring.score(
            finding,
            enrichment,
            scoring_context_profile_internet_facing(),
            services,
            WEIGHTS,
        )
        self.assertEqual(breakdown.band, "Critical")
        self.assertGreaterEqual(breakdown.risk, 90.0)

    def test_real_cpe_range_match_against_nvd_configurations(self) -> None:
        # No explicit scanner claim: the match must come from the CPE version range
        # over the real NVD configuration data for apache:log4j.
        finding = make_finding("log4j RCE", host_ip="172.28.0.11")
        stripped = finding.to_json()
        stripped["id"] = "f-log4j"
        stripped["cve_ids"] = []
        finding = Finding(**{**stripped, "provenance": Provenance(**stripped["provenance"])})
        service = make_service(cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        enrichments = intel.match_finding(finding, (service,), self.store, self.feed_dates)
        methods = {item.cve_id: item.match_method for item in enrichments}
        self.assertIn(CVE_2021_44228, methods, methods)
        self.assertEqual(methods[CVE_2021_44228], "cpe_range")
        match = next(item for item in enrichments if item.cve_id == CVE_2021_44228)
        self.assertTrue(match.kev)

    def test_cve_absent_from_snapshot_is_unscored_not_defaulted(self) -> None:
        finding = make_finding("CVE-2099-0001")
        enrichments = intel.match_finding(finding, (make_service(),), self.store, self.feed_dates)
        self.assertEqual(len(enrichments), 1)
        enrichment = enrichments[0]
        self.assertIsNone(enrichment.epss)
        self.assertIsNone(enrichment.epss_percentile)
        self.assertFalse(enrichment.kev)
        breakdown = scoring.score(
            finding,
            enrichment,
            scoring_context_profile_internet_facing(),
            (make_service(),),
            WEIGHTS,
        )
        self.assertIsNone(breakdown.threat_multiplier)


def scoring_context_profile_internet_facing():
    from vulnassess.schema import ContextProfile, Feature

    return ContextProfile(
        host_ip="172.28.0.12",
        role=Feature("web_frontend", 0.9, "rule", "808/tcp http"),
        exposure=Feature("internet_facing", 0.9, "rule", "ip is internet_facing"),
        segment="172.28.0.12/32",
    )


if __name__ == "__main__":
    unittest.main()
