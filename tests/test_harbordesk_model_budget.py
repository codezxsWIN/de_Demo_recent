"""Mixed-service labs must fit bounded requests without losing original evidence."""

import copy

from tests.test_analyst import demo_payload
from vulnassess import analyst


def test_model_focuses_affected_endpoints_but_full_frame_keeps_inventory():
    payload = demo_payload()
    ip = "172.28.0.12"
    host = next(item for item in payload["hosts"] if item["ip"] == ip)
    ports = {item["port"] for item in payload["findings"] if item["host_ip"] == ip}
    for port in range(24000, 24012):
        host["services"].append({"port": port, "protocol": "tcp", "name": "unknown", "tls": False})
    original = copy.deepcopy(payload)
    case, _, _ = analyst.build_case(payload, ip)
    _, evidence, aliases = analyst.build_case(payload, ip)
    assert (
        len(analyst.build_prompt(case, evidence, len(aliases)))
        <= analyst.MAX_PROMPT_CHARS - analyst.CORRECTION_RESERVE
    )
    assert all(service["port"] in ports for service in case["services"])
    assert case["coverage"]["services_omitted"] >= 12
    full, _, _ = analyst._assemble_case(payload, ip, for_model=False)
    assert len(full["services"]) == len(host["services"])
    assert payload == original


def test_mixed_service_batches_cover_every_finding_without_repeating_all_endpoints(monkeypatch):
    host = "127.0.0.1"
    findings = [
        {
            "id": f"fixture-{index}",
            "host_ip": host,
            "port": 8787 if index < 3 else 8791,
            "protocol": "tcp",
        }
        for index in range(8)
    ]
    payload = {
        "hosts": [{"ip": host, "services": [{"port": port} for port in range(10)]}],
        "findings": findings,
        "scores": [{"finding_id": item["id"], "risk": 60} for item in findings],
        "enrichments": [],
    }
    original = copy.deepcopy(payload)
    observed = []

    def analyze(focused, target, **kwargs):
        observed.append({item["port"] for item in focused["findings"]})
        return {"finding_coverage": {"included_ids": [item["id"] for item in focused["findings"]]}}

    monkeypatch.setattr(analyst, "analyze_target", analyze)
    result = analyst.analyze_findings(payload, host)
    assert observed == [{8787}, {8791}]
    assert result["batch_coverage"]["findings_included"] == 8
    assert result["batch_coverage"]["findings_omitted"] == 0
    assert payload == original
