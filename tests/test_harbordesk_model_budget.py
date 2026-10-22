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
    assert all(service["port"] in ports for service in case["services"])
    assert case["coverage"]["services_omitted"] >= 12
    full, _, _ = analyst._assemble_case(payload, ip, for_model=False)
    assert len(full["services"]) == len(host["services"])
    assert payload == original
