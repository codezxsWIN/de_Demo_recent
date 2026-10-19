"""Parsing tests over committed REAL Nmap captures (see tests/fixtures/nmap/README.md).

These two captures were produced by real Nmap 7.80 executions on 2026-09-17 via
`vulnassess scan --execute` against the owner's own loopback-bound lab hosts. They
prove the reader accepts genuine scanner output — including the bare
`<!DOCTYPE nmaprun>` header real Nmap always writes. They carry no explicit CVE
evidence: vulners ran keyless and the lab hosts expose no vulnerable versions,
and the pipeline must treat that honestly rather than invent findings.
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnassess import analyst, audit, intel, pipeline
from vulnassess.readers import parse_nmap_xml, parse_zap_json
from vulnassess.role_model import load_model
from vulnassess.settings import Settings
from vulnassess.store import Store
from vulnassess.ui.server import UiApplication

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "nmap"


class TestRealZapCapture(unittest.TestCase):
    def test_real_zap_report_parses_with_native_severities(self) -> None:
        findings = parse_zap_json(
            FIXTURES.parent / "zap" / "real-lab-172.28.0.12-juiceshop-zap.json",
            "real",
            host_ip="172.28.0.12",
        )
        self.assertGreater(len(findings), 200)
        self.assertTrue(all(finding.tool == "zap" for finding in findings))
        self.assertTrue(all(finding.native_severity for finding in findings))
        self.assertTrue(all(not finding.cve_ids for finding in findings))


class TestRealCaptures(unittest.TestCase):
    def test_recorded_evidence_replays_to_ranked_report_without_network(self) -> None:
        settings = Settings(ROOT / "config")
        model_path = ROOT / "models" / "synthetic-role-model.json"
        model = load_model(model_path)
        with TemporaryDirectory() as directory:
            database = Path(directory) / "recorded_replay.db"
            report_path = Path(directory) / "recorded_report.html"
            run_id = "recorded-replay"
            with Store(database) as store:
                for address, name in (
                    ("172.28.0.10", "real-lab-172.28.0.10-windows.xml"),
                    ("172.28.0.11", "real-lab-172.28.0.11-nginx.xml"),
                    ("172.28.0.12", "real-lab-172.28.0.12-juiceshop.xml"),
                ):
                    pipeline.do_import(settings, store, run_id, address, FIXTURES / name)
                before_services = store.hosts(run_id)
                pipeline.do_import(
                    settings,
                    store,
                    run_id,
                    "172.28.0.12",
                    None,
                    FIXTURES.parent / "zap" / "real-lab-172.28.0.12-juiceshop-zap.json",
                )
                self.assertEqual(store.hosts(run_id), before_services)
                intel.load_feeds(FIXTURES.parent / "intel", store)
                matching = intel.enrich_run(run_id, store)
                pipeline.do_context(settings, store, run_id)
                pipeline.do_rank(settings, store, run_id)
                first = json.dumps(
                    [item.to_json() for item in store.scores(run_id)], sort_keys=True
                )
                pipeline.do_rank(settings, store, run_id)
                repeated = json.dumps(
                    [item.to_json() for item in store.scores(run_id)], sort_keys=True
                )
                self.assertEqual(first, repeated)
                findings = store.findings(run_id)
                self.assertEqual(len(findings), 225)
                self.assertEqual(len(store.scores(run_id)), len(findings))
                for finding in findings:
                    self.assertTrue(Path(finding.provenance.raw_path).is_file())
                    self.assertEqual(finding.provenance.tool, finding.tool)
                cached = sum(
                    store.cve(item.cve_id) is not None
                    for finding in findings
                    for item in store.enrichments(finding.id)
                )
                self.assertEqual(cached, 0)
                self.assertTrue(all(item.base_score is None for item in store.scores(run_id)))
                for order in pipeline.baseline_orders(store, run_id).values():
                    self.assertEqual(set(order), {finding.id for finding in findings})
                report_audit = audit.collect_report_audit(
                    settings, store, run_id, model_path=model_path
                )
                pipeline.do_report(settings, store, run_id, report_path, audit_data=report_audit)
                html = report_path.read_text(encoding="utf-8")
                for expected in ("Provenance", "Research and audit evidence", model.model_hash):
                    self.assertIn(expected, html)

            response = UiApplication(database, ROOT / "config", run_id).get(f"/api/run/{run_id}")
            self.assertEqual(response.status, 200)
            payload = json.loads(response.body)
            case, evidence, aliases = analyst.build_case(payload, "172.28.0.12")
            self.assertEqual(case["coverage"]["findings_total"], 222)
            self.assertGreater(case["coverage"]["findings_omitted"], 0)
            self.assertLessEqual(
                len(analyst.build_prompt(case, evidence, len(aliases))), analyst.MAX_PROMPT_CHARS
            )
            print(
                "RECORDED_REPLAY "
                + json.dumps(
                    {
                        "findings": len(findings),
                        "matched_identifiers": matching["matched"],
                        "cached_nvd_records": cached,
                        "identical_rerank": first == repeated,
                        "run_endpoint": response.status,
                        "coverage": case["coverage"],
                    },
                    sort_keys=True,
                )
            )

    def test_real_juice_shop_capture_parses_with_services(self) -> None:
        hosts, findings = parse_nmap_xml(FIXTURES / "real-lab-172.28.0.12-juiceshop.xml", "real")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip, "172.28.0.12")
        ports = {service.port for service in hosts[0].services}
        self.assertIn(3000, ports)
        self.assertIn(445, ports)
        self.assertEqual(findings, [])

    def test_real_windows_capture_parses_with_named_product(self) -> None:
        hosts, findings = parse_nmap_xml(FIXTURES / "real-lab-172.28.0.10-windows.xml", "real")
        self.assertEqual(len(hosts), 1)
        banners = " ".join(
            (service.banner or "") + (service.product or "") for service in hosts[0].services
        )
        self.assertIn("Python", banners)
        self.assertEqual(findings, [])

    def test_real_captures_carry_the_bare_nmap_doctype(self) -> None:
        for name in (
            "real-lab-172.28.0.12-juiceshop.xml",
            "real-lab-172.28.0.10-windows.xml",
        ):
            with self.subTest(name=name):
                head = (FIXTURES / name).read_bytes()[:200]
                self.assertIn(b"<!DOCTYPE nmaprun>", head)


if __name__ == "__main__":
    unittest.main()
