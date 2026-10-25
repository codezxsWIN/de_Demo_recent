"""Synthetic pure-logic grounding regressions; no scanner, model or network evidence."""

import copy
import json
from typing import Any

from vulnassess import helpy


def synthetic_record(count: int = 1) -> dict[str, Any]:
    return {
        "capture_id": "SYNTHETIC-helpy-grounding",
        "result": {"scan_status": "complete", "ai_status": "not_attempted"},
        "payload": {
            "findings": [
                {
                    "id": f"SYNTHETIC-finding-{number}",
                    "title": f"SYNTHETIC scanner lead {number}",
                    "tool": "nikto",
                    "port": 8787,
                    "protocol": "tcp",
                    "cve_ids": [],
                }
                for number in range(count)
            ],
            "scores": [],
            "hosts": [],
            "scanner_coverage": {"nmap": "SYNTHETIC bounded observation"},
        },
    }


def test_summary_counts_the_whole_capture_not_only_the_first_twelve_findings() -> None:
    record = synthetic_record(19)
    items = helpy.sources(record)
    assert "This capture records 19" in items["R:exploitability"]["text"]
    assert sum(ref.startswith("R:finding:") for ref in items) == 19
    bounded = helpy._bounded_sources(items, "Explain the last scanner lead")
    assert "R:selection" in bounded
    assert "omitted excerpts were not reviewed" in bounded["R:selection"]["text"]


def test_cve_after_the_excerpt_limit_is_not_reported_as_zero_cves() -> None:
    record = synthetic_record(13)
    record["payload"]["findings"][-1]["cve_ids"] = ["CVE-1999-9001"]
    items = helpy.sources(record)
    assert "R:exploitability" not in items
    assert "zero scanner-named CVEs" not in str(items)


def test_native_lab_observations_are_not_misrepresented_as_missing_application_checks() -> None:
    record = synthetic_record()
    record["payload"]["findings"][0].update(
        tool="harbordesk",
        tool_native_id="HD-24",
        title="SYNTHETIC intentional management control",
        port=8791,
    )
    record["payload"]["scanner_coverage"]["harbordesk-check"] = (
        "SYNTHETIC complete bounded verifier receipt"
    )
    items = helpy.sources(record)
    assert "HarborDesk" in items["R:web-coverage"]["text"]
    assert "specific" in items["R:web-coverage"]["text"]
    assert "not confirmed exploitable vulnerabilities" not in items["R:exploitability"]["text"]
    assert "fictional" in items["R:exploitability"]["text"]
    assert "No exploit recipe" not in items["R:verify:0"]["text"]
    assert "fictional" in items["R:verify:0"]["text"]


def test_no_nikto_collection_is_claimed_when_only_nmap_is_recorded() -> None:
    items = helpy.sources(synthetic_record())
    assert (
        "has Nmap port/service coverage and bounded Nikto checks"
        not in (items["R:web-coverage"]["text"])
    )


def test_canonical_tool_and_native_severity_remain_in_the_source_excerpt() -> None:
    record = synthetic_record()
    record["payload"]["findings"][0].update(
        tool="harbordesk", tool_native_id="HD-23", native_severity="High"
    )
    original = copy.deepcopy(record)
    items = helpy.sources(record)
    text = items["R:finding:0"]["text"]
    assert text.startswith("Retained HarborDesk verifier finding: ")
    assert '"native_severity": "High"' in text and '"tool_native_id": "HD-23"' in text
    assert record == original
    assert "vendor CVEs" in items["R:exploitability"]["text"]
    assert all(len(item["text"]) <= 2500 for item in items.values())
    assert json.dumps(record) == json.dumps(original)
