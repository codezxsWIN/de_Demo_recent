"""Auditable CVE matching decision-trace tests."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess import intel, pipeline
from vulnassess.schema import Finding, Provenance, Service
from vulnassess.settings import Settings
from vulnassess.store import Store

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC = ROOT / "tests" / "synthetic"
SETTINGS = Settings(ROOT / "config")


def finding(*, cves=(), port: int | None = 80) -> Finding:
    return Finding.make(
        host_ip="172.28.0.10",
        port=port,
        protocol="tcp" if port else None,
        url=None,
        tool="nmap",
        tool_native_id=f"synthetic-{cves}-{port}",
        title="SYNTHETIC matching input",
        description="SYNTHETIC",
        evidence="SYNTHETIC matching evidence",
        cve_ids=cves,
        first_seen="2026-09-07T00:00:00Z",
        last_seen="2026-09-07T00:00:00Z",
        provenance=Provenance("nmap", "tests/synthetic/synthetic_intel_trace.xml", 1, "synthetic"),
    )


def apache(version: str, cpe: str | None = "cpe:/a:apache:http_server:2.4.49") -> Service:
    return Service(
        port=80,
        protocol="tcp",
        name="http",
        product="Apache httpd",
        version=version,
        cpe=cpe,
        banner=f"80/tcp http Apache httpd {version}",
    )


class TestIntelTrace(unittest.TestCase):
    def store(self, directory: str) -> Store:
        store = Store(Path(directory) / "intel.db")
        intel.load_feeds(SYNTHETIC / "feeds", store)
        return store

    def test_explicit_match_records_presence_or_absence_of_nvd_row(self):
        with TemporaryDirectory() as directory, self.store(directory) as store:
            known, known_trace = intel.match_finding_with_trace(
                finding(cves=("CVE-1999-9001",)),
                (apache("2.4.49"),),
                store,
                {"nvd": "2026-09-05"},
            )
            unknown, unknown_trace = intel.match_finding_with_trace(
                finding(cves=("CVE-1999-9999",)),
                (apache("2.4.49"),),
                store,
                {"nvd": "2026-09-05"},
            )

        self.assertEqual(known[0].cve_id, "CVE-1999-9001")
        self.assertEqual(known_trace[0].decision, "accepted")
        self.assertNotIn("no row", known_trace[0].reason)
        self.assertEqual(unknown[0].cve_id, "CVE-1999-9999")
        self.assertIsNone(unknown[0].cvss31_vector)
        self.assertIn("no row", unknown_trace[0].reason)

    def test_cpe_range_acceptance_and_rejection_are_explained(self):
        no_cve = finding()
        with TemporaryDirectory() as directory, self.store(directory) as store:
            accepted, accepted_trace = intel.match_finding_with_trace(
                no_cve,
                (apache("2.4.50"),),
                store,
                {"nvd": "2026-09-05"},
            )
            rejected, rejected_trace = intel.match_finding_with_trace(
                no_cve,
                (apache("2.4.51"),),
                store,
                {"nvd": "2026-09-05"},
            )

        self.assertEqual([item.cve_id for item in accepted], ["CVE-1999-9001"])
        self.assertTrue(
            any(
                item.decision == "accepted" and item.method == "cpe_range"
                for item in accepted_trace
            )
        )
        self.assertEqual(rejected, [])
        self.assertTrue(any(item.decision == "rejected" for item in rejected_trace))
        self.assertEqual(rejected_trace[-1].decision, "fallback")

    def test_missing_service_and_cpe_are_not_silent(self):
        no_cve = finding()
        with TemporaryDirectory() as directory, self.store(directory) as store:
            _, no_service = intel.match_finding_with_trace(no_cve, (), store, {"nvd": "2026-09-05"})
            _, no_cpe = intel.match_finding_with_trace(
                no_cve,
                (apache("2.4.49", cpe=None),),
                store,
                {"nvd": "2026-09-05"},
            )

        self.assertIn("no observed service", no_service[0].reason)
        self.assertIn("no CPE", no_cpe[0].reason)
        self.assertEqual(no_service[-1].method, "native_severity")
        self.assertEqual(no_cpe[-1].method, "native_severity")

    def test_enrich_run_reports_unmatched_finding_reasons(self):
        with TemporaryDirectory() as directory, self.store(directory) as store:
            pipeline.do_import(
                SETTINGS,
                store,
                "trace",
                "172.28.0.11",
                SYNTHETIC / "synthetic_nmap_two_machines.xml",
                SYNTHETIC / "synthetic_zap_dvwa.json",
            )
            result = intel.enrich_run("trace", store)

        self.assertEqual(result["findings"], 4)
        self.assertEqual(result["matched"], 0)
        self.assertEqual(len(result["unmatched"]), 4)
        self.assertGreaterEqual(result["trace_counts"]["fallback:native_severity"], 4)
        self.assertTrue(all(item["reasons"] for item in result["unmatched"]))

    def test_trace_run_reports_decisions_without_writing_enrichments(self):
        with TemporaryDirectory() as directory, self.store(directory) as store:
            pipeline.do_import(
                SETTINGS,
                store,
                "trace-read-only",
                "172.28.0.11",
                SYNTHETIC / "synthetic_nmap_two_machines.xml",
                SYNTHETIC / "synthetic_zap_dvwa.json",
            )
            finding_ids = [item.id for item in store.findings("trace-read-only")]
            before = {finding_id: store.enrichments(finding_id) for finding_id in finding_ids}
            result = intel.trace_run("trace-read-only", store)
            after = {finding_id: store.enrichments(finding_id) for finding_id in finding_ids}

        self.assertEqual(before, after)
        self.assertEqual(result["findings"], 4)
        self.assertEqual(set(result["traces"]), set(finding_ids))
        self.assertEqual(result["unmatched_count"], len(result["unmatched"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
