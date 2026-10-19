"""Evidence-preserving correlation tests for the unified-result engine."""

import unittest

from vulnassess.errors import ConfigError
from vulnassess.schema import Finding, Provenance
from vulnassess.unify import unify_findings


def finding(
    native_id: str,
    *,
    tool: str = "nmap",
    host: str = "192.0.2.10",
    port: int = 80,
    url: str | None = None,
    title: str = "Synthetic finding",
    cves: tuple[str, ...] = (),
    cwes: tuple[str, ...] = (),
) -> Finding:
    return Finding.make(
        host_ip=host,
        port=port,
        protocol="tcp",
        url=url,
        tool=tool,
        tool_native_id=native_id,
        title=title,
        description="SYNTHETIC correlation input",
        evidence=f"SYNTHETIC evidence {native_id}",
        cve_ids=cves,
        cwe_ids=cwes,
        first_seen="2026-09-07T00:00:00Z",
        last_seen="2026-09-07T00:00:00Z",
        provenance=Provenance(tool, "tests/synthetic/synthetic_unify.json", 1, "synthetic"),
    )


class TestUnification(unittest.TestCase):
    def test_shared_cve_same_instance_merges_and_preserves_sources(self):
        # A positive duplicate case must establish the same affected instance;
        # two missing URLs are now covered separately as unresolved evidence.
        url = "http://192.0.2.10/synthetic-instance"
        left = finding("nmap-a", cves=("CVE-1999-9001",), url=url)
        right = finding("zap-a", tool="zap", cves=("CVE-1999-9001",), url=url)

        result = unify_findings([left, right])

        self.assertEqual(result.raw_count, 2)
        self.assertEqual(result.unified_count, 1)
        group = result.groups[0]
        self.assertEqual(group.method, "shared_cve_same_instance")
        self.assertEqual(group.confidence, 0.95)
        self.assertEqual(set(group.source_finding_ids), {left.id, right.id})
        self.assertEqual(group.tools, ("nmap", "zap"))
        self.assertEqual(group.cve_ids, ("CVE-1999-9001",))
        self.assertEqual(len(group.evidence), 2)

    def test_shared_cve_on_different_urls_is_a_candidate_not_a_merge(self):
        left = finding(
            "zap-root",
            tool="zap",
            url="http://192.0.2.10/",
            cves=("CVE-1999-9001",),
        )
        right = finding(
            "zap-login",
            tool="zap",
            url="http://192.0.2.10/login",
            cves=("CVE-1999-9001",),
        )

        result = unify_findings([left, right])

        self.assertEqual(result.unified_count, 2)
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.candidates[0].method, "shared_cve_different_instance")
        self.assertIn("URLs differ", result.candidates[0].justification)

    def test_shared_generic_cwe_is_never_an_automatic_merge(self):
        left = finding("zap-csp", tool="zap", cwes=("CWE-693",))
        right = finding("nikto-csp", tool="nikto", cwes=("CWE-693",))

        result = unify_findings([left, right])

        self.assertEqual(result.unified_count, 2)
        self.assertEqual(result.candidates[0].method, "shared_cwe_candidate")
        self.assertIn("insufficient", result.candidates[0].justification)

    def test_title_similarity_is_review_only(self):
        left = finding("zap-title", tool="zap", title="Missing CSP response header")
        right = finding("nikto-title", tool="nikto", title="Missing CSP header")

        result = unify_findings([left, right])

        self.assertEqual(result.unified_count, 2)
        self.assertEqual(result.candidates[0].method, "similar_title_candidate")
        self.assertGreaterEqual(result.candidates[0].confidence, 0.6)

    def test_different_host_or_port_never_correlates(self):
        base = finding("base", cves=("CVE-1999-9001",))
        other_host = finding("host", host="192.0.2.11", cves=("CVE-1999-9001",))
        other_port = finding("port", port=443, cves=("CVE-1999-9001",))

        result = unify_findings([base, other_host, other_port])

        self.assertEqual(result.unified_count, 3)
        self.assertEqual(result.candidates, ())

    def test_output_is_order_independent_and_covers_every_source_once(self):
        records = [
            finding("nmap-a", cves=("CVE-1999-9001",)),
            finding("zap-a", tool="zap", cves=("CVE-1999-9001",)),
            finding(
                "zap-url",
                tool="zap",
                url="http://192.0.2.10/login",
                cves=("CVE-1999-9001",),
            ),
        ]

        forward = unify_findings(records).to_json()
        reversed_result = unify_findings(list(reversed(records))).to_json()

        self.assertEqual(forward, reversed_result)
        source_ids = [
            source for group in forward["groups"] for source in group["source_finding_ids"]
        ]
        self.assertEqual(sorted(source_ids), sorted(record.id for record in records))
        self.assertEqual(len(source_ids), len(set(source_ids)))

    def test_duplicate_source_ids_fail_instead_of_disappearing(self):
        record = finding("duplicate")

        with self.assertRaises(ConfigError):
            unify_findings([record, record])


if __name__ == "__main__":
    unittest.main(verbosity=2)
