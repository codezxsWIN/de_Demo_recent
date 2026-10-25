"""Identity-gated protocol lab adapter; real transcripts, no CVE inference."""

import json

from vulnassess.errors import ScopeError
from vulnassess.schema import Finding, Provenance, Service

BASE = "http://127.0.0.1:8800/"
METADATA = {
    "mail": (
        8825,
        "smtp",
        "SMTP permits fictional account enumeration",
        "CWE-203",
        "Low",
        "A bounded VRFY command disclosed the designated fictional mailbox.",
        "Disable mailbox enumeration and return uniform responses to untrusted clients.",
    ),
    "cache": (
        11211,
        "memcached",
        "Cache returns private fixture data without authentication",
        "CWE-306",
        "Medium",
        "A Memcached text GET returned the private training key without credentials.",
        "Restrict cache listeners to approved application clients; use an authenticated transport or trusted local socket where supported.",
    ),
    "industrial": (
        1502,
        "modbus",
        "Modbus permits reading designated private fixture registers",
        "CWE-306",
        "Medium",
        "A Modbus function-three request read designated private training registers without an access check. This does not establish exposure of a real controller.",
        "Restrict controller communications to approved monitoring clients using segmentation, allowlists and a controlled gateway.",
    ),
}


def eligible(target_ip, endpoint):
    return bool(
        target_ip == "127.0.0.1"
        and endpoint
        and endpoint.get("host") == "127.0.0.1"
        and endpoint.get("scheme") == "http"
        and endpoint.get("path") == "/"
        and type(endpoint.get("port")) is int
        and endpoint["port"] == 8800
    )


def run(scope, target_ip, endpoint, directory):
    if (
        not eligible(target_ip, endpoint)
        or not scope.contains(target_ip)
        or scope.is_canary(target_ip)
    ):
        raise ScopeError("Network protocol verification requires authorized http://127.0.0.1:8800/")
    from labs.network_environments.servers import LAB_ID
    from labs.network_environments.verify import observed, verify

    path = directory / "network-environment-checks.json"
    with path.open("x", encoding="utf-8") as stream:
        receipt = verify()
        json.dump(receipt, stream, indent=2)
    rows = receipt.get("checks")
    if (
        receipt.get("lab_id") != LAB_ID
        or receipt.get("target") != BASE
        or not isinstance(rows, list)
        or len(rows) != len(METADATA)
        or {row.get("id") for row in rows} != set(METADATA)
    ):
        raise ValueError("Network environment receipt identity or check coverage is invalid")
    findings, services = [], []
    for index, row in enumerate(rows):
        port, protocol, title, cwe, severity, meaning, fix = METADATA[row["id"]]
        if row.get("port") != port or row.get("protocol") != protocol:
            raise ValueError("Network environment proof differs from trusted metadata")
        if row.get("port_evidence"):
            services.append(
                Service(
                    port=port,
                    protocol="tcp",
                    name=protocol,
                    banner="Custom fictional network-protocol training service",
                )
            )
        if row.get("observed") is not True:
            continue
        if not observed(protocol, row["port_evidence"]):
            raise ValueError("Network environment finding has no matching protocol proof")
        findings.append(
            Finding.make(
                host_ip=target_ip,
                port=port,
                protocol="tcp",
                tool="network-lab",
                tool_native_id=row["id"],
                title=title,
                description=meaning
                + " "
                + fix
                + " Custom lab condition; no vendor/CVE/exploit claim.",
                evidence=json.dumps(row, ensure_ascii=True),
                native_severity=severity,
                native_confidence="high",
                cwe_ids=[cwe],
                provenance=Provenance(
                    tool="network-lab",
                    raw_path=str(path.resolve()),
                    record_index=index,
                    run_id="live",
                ),
            )
        )
    errors = [
        row["id"]
        for row in receipt["checks"]
        if any(key.endswith("_error") for key in row) or not row["control_passed"]
    ]
    prefix = "partial" if errors else "complete"
    coverage = (
        f"{prefix}: {len(receipt['checks'])}/3 fixed protocol checks; "
        f"{len(findings)} observed fixture conditions; "
        f"{sum(row['control_passed'] for row in receipt['checks'])}/3 access-denied comparisons; "
        "no mail delivery, writes, exploitation or OS checks"
    )
    return findings, services, coverage


def guidance(finding):
    if finding.get("tool") != "network-lab" or finding.get("tool_native_id") not in METADATA:
        return None
    _, protocol, title, _, _, meaning, fix = METADATA[finding["tool_native_id"]]
    return {
        "category": title,
        "meaning": meaning,
        "scenario": "A client able to connect to the fixture endpoint can request its designated fictional data. Real-world exposure and impact require separate verification.",
        "prerequisites": [
            "Reachability to the affected endpoint; equivalent access policy and data on a real deployment."
        ],
        "impact": "Fictional data was disclosed in this controlled lab. No production data or compromise was established.",
        "patch": [fix],
        "mitigations": ["Keep this training service loopback-only. Do not publish or tunnel it."],
        "verify": [
            f"Repeat the same bounded {protocol} read; confirm the protected comparison refuses disclosure and approved legitimate clients still work."
        ],
        "example": None,
        "source": "Reviewed protocol-specific lab guidance; not an AI-generated exploitation claim.",
    }
